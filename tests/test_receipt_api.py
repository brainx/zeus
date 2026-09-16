from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus import message_store
from zeus.message_store import MessageStore, MessageStoreError
from zeus.receipt_api import is_receipt_path, receipt_response
from zeus.state import StateStore

PUBLIC_FIELDS = {
    "message_id",
    "bot_id",
    "dispatch_state",
    "run_id",
    "run_status",
    "created_at",
    "updated_at",
    "retry_before",
    "last_checked_at",
    "cancel_requested_at",
    "released_at",
    "archived_at",
    "error_code",
}
CAPACITY_FIELDS = {
    "limit",
    "used",
    "remaining",
    "total",
    "archived",
    "blocking",
    "status",
    "database_bytes",
    "wal_bytes",
    "filesystem_free_bytes",
}


class ReceiptApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "state" / "zeus.db"
        StateStore(self.path).init()
        self.store = MessageStore(self.path)
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def seed(self, letter: str, *, bot_id: str = "coder", seconds: int = 0, prepared=False):
        stamp = self.now + timedelta(seconds=seconds)
        with patch(
            "zeus.message_store.uuid.uuid4",
            side_effect=[uuid.UUID(hex=letter * 32), uuid.UUID(hex="0" + letter * 31)],
        ):
            receipt, _ = self.store.prepare(
                bot_id=bot_id,
                incarnation=self.now - timedelta(days=1),
                target_fingerprint="1" * 64,
                endpoint="http://127.0.0.1:8765/health",
                credential_fingerprint="2" * 64,
                input_fingerprint="3" * 64,
                request_key_fingerprint="4" * 64 if prepared else None,
                now=stamp,
                retry_before=stamp + timedelta(minutes=10),
            )
        if not prepared:
            receipt = self.store.finish_attempt(
                receipt.message_id, expected_version=1, dispatch_state="rejected", now=stamp
            )
        return receipt

    def request(self, target: str):
        path = target.split("?", 1)[0]
        return receipt_response(path, target, self.path)

    def test_routes_only_claim_message_namespace(self) -> None:
        for path in ("/messages", "/messages/capacity", "/messages/abc", "/messages/"):
            self.assertTrue(is_receipt_path(path))
        for path in ("/message", "/messages-other", "/bots/coder/status", "/v1/messages"):
            self.assertFalse(is_receipt_path(path))

    def test_receipt_allowlist_is_exact_and_prepared_observation_is_unknown(self) -> None:
        receipt = self.seed("a", prepared=True)
        status, detail = self.request("/messages/" + receipt.message_id)
        self.assertEqual(200, status)
        self.assertEqual(PUBLIC_FIELDS, set(detail))
        self.assertEqual("unknown", detail["dispatch_state"])
        self.assertIsNone(detail["last_checked_at"])
        self.assertIsNone(detail["run_status"])
        status, page = self.request("/messages")
        self.assertEqual(200, status)
        self.assertEqual([detail], page["items"])
        self.assertIsNone(page["next_before"])
        serialized = json.dumps(page)
        for secret in (
            receipt.endpoint,
            receipt.target_fingerprint,
            receipt.credential_fingerprint,
            receipt.request_hash,
            receipt.request_key_hash,
            receipt.upstream_key,
        ):
            self.assertNotIn(secret, serialized)
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(
                "prepared",
                conn.execute("SELECT dispatch_state FROM message_receipts").fetchone()[0],
            )

    def test_pages_are_stable_across_insertions_ties_archival_and_bot_filters(self) -> None:
        for letter, bot, seconds in (
            ("f", "coder", 0),
            ("e", "other", 20),
            ("d", "coder", 10),
            ("c", "coder", 20),
            ("b", "other", 30),
        ):
            self.seed(letter, bot_id=bot, seconds=seconds)
        self.store.archive(
            before=self.now + timedelta(days=1), now=self.now + timedelta(days=2), apply=True
        )
        status, first = self.request("/messages?limit=2")
        self.assertEqual(200, status)
        self.seed("a", bot_id="other", seconds=40)
        _, second = self.request("/messages?limit=2&before=" + first["next_before"])
        _, third = self.request("/messages?limit=2&before=" + second["next_before"])
        items = first["items"] + second["items"] + third["items"]
        self.assertEqual(
            [letter * 32 for letter in "becdf"], [item["message_id"] for item in items]
        )
        self.assertTrue(all(item["archived_at"] is not None for item in items))
        self.assertIsNone(third["next_before"])
        _, filtered = self.request("/messages?bot_id=coder&limit=1")
        _, remaining = self.request("/messages?bot_id=coder&before=" + filtered["next_before"])
        self.assertEqual(
            [letter * 32 for letter in "cdf"],
            [item["message_id"] for item in filtered["items"] + remaining["items"]],
        )
        self.assertEqual(400, self.request("/messages?bot_id=coder&before=" + "e" * 32)[0])

    def test_strict_queries_identifiers_and_cursors(self) -> None:
        self.seed("a")
        for target in (
            "/messages?limit=0",
            "/messages?limit=101",
            "/messages?limit=bad",
            "/messages?limit=",
            "/messages?limit=1&limit=2",
            "/messages?before=bad",
            "/messages?bot_id=!!",
            "/messages?unknown=private-value",
            "/messages/",
            "/messages/a/extra",
            "/messages/%FF",
            "/messages/%2F",
            "/messages/capacity/",
            "/messages/capacity?limit=1",
            "/messages/" + "a" * 32 + "?refresh=true",
        ):
            with self.subTest(target=target):
                status, body = self.request(target)
                self.assertEqual(400, status)
                self.assertEqual("invalid_request", body["error"]["code"])
                self.assertNotIn("private-value", json.dumps(body))
        status, body = self.request("/messages?before=" + "0" * 32)
        self.assertEqual(400, status)
        self.assertEqual("invalid_cursor", body["error"]["code"])
        status, body = self.request("/messages/" + "0" * 32)
        self.assertEqual(404, status)
        self.assertEqual("unknown_message", body["error"]["code"])

    def test_default_and_maximum_page_sizes(self) -> None:
        # Small MAX_MESSAGE_RECEIPTS overrides would change admissions, not the
        # public pagination bound; seed actual durable receipts here.
        for index in range(101):
            stamp = self.now + timedelta(seconds=index)
            receipt, _ = self.store.prepare(
                bot_id="coder",
                incarnation=self.now - timedelta(days=1),
                target_fingerprint="1" * 64,
                endpoint="http://127.0.0.1:8765/health",
                credential_fingerprint="2" * 64,
                input_fingerprint="3" * 64,
                request_key_fingerprint=None,
                now=stamp,
                retry_before=stamp + timedelta(minutes=10),
            )
            self.store.finish_attempt(
                receipt.message_id, expected_version=1, dispatch_state="rejected", now=stamp
            )
        _, default = self.request("/messages")
        _, maximum = self.request("/messages?limit=100")
        self.assertEqual(50, len(default["items"]))
        self.assertEqual(100, len(maximum["items"]))
        self.assertIsNotNone(maximum["next_before"])

    def test_capacity_reports_exact_archived_and_blocking_counts(self) -> None:
        self.seed("a")
        self.store.archive(
            before=self.now + timedelta(days=1), now=self.now + timedelta(days=2), apply=True
        )
        self.seed("b", prepared=True)
        status, capacity = self.request("/messages/capacity")
        self.assertEqual(200, status)
        self.assertEqual(CAPACITY_FIELDS, set(capacity))
        self.assertEqual(
            (2, 1, 1, 1, 9999, "ok"),
            tuple(
                capacity[name]
                for name in ("total", "used", "archived", "blocking", "remaining", "status")
            ),
        )

    def test_reads_do_not_create_migrate_recover_execute_or_refresh(self) -> None:
        receipt = self.seed("a", prepared=True)
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
        before = self.path.read_bytes()
        forbidden = AssertionError("receipt observation crossed its read-only boundary")
        with (
            patch("zeus.bot_messaging.BotMessaging", side_effect=forbidden),
            patch("zeus.supervisor.Supervisor", side_effect=forbidden),
            patch("zeus.state.StateStore.init", side_effect=forbidden),
            patch("zeus.hermes_runs_client.request_json", side_effect=forbidden),
            patch("zeus.gateway_http.request_json", side_effect=forbidden),
            patch("subprocess.Popen", side_effect=forbidden),
            patch("subprocess.run", side_effect=forbidden),
            patch("os.kill", side_effect=forbidden),
            patch("os.killpg", side_effect=forbidden),
        ):
            for target in ("/messages", "/messages/" + receipt.message_id, "/messages/capacity"):
                self.assertEqual(200, self.request(target)[0])
        self.assertEqual(before, self.path.read_bytes())
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual("delete", conn.execute("PRAGMA journal_mode").fetchone()[0])

    def test_missing_storage_is_not_created(self) -> None:
        missing = self.root / "missing" / "zeus.db"
        for target in ("/messages", "/messages/" + "a" * 32, "/messages/capacity"):
            status, body = receipt_response(target, target, missing)
            self.assertEqual(503, status)
            self.assertEqual("message_store_unavailable", body["error"]["code"])
        self.assertFalse(missing.parent.exists())

    def test_incompatible_and_malformed_storage_is_not_modified(self) -> None:
        for version in (9, 11):
            with closing(sqlite3.connect(self.path)) as conn:
                conn.execute("UPDATE schema_version SET version = ?", (version,))
                conn.commit()
            before = self.path.read_bytes()
            for target in ("/messages", "/messages/" + "a" * 32, "/messages/capacity"):
                self.assertEqual(503, self.request(target)[0])
            self.assertEqual(before, self.path.read_bytes())
        self.path.write_bytes(b"not a database")
        before = self.path.read_bytes()
        for target in ("/messages", "/messages/" + "a" * 32, "/messages/capacity"):
            self.assertEqual(503, self.request(target)[0])
        self.assertEqual(before, self.path.read_bytes())

    def test_invalid_receipts_fail_closed_without_echoing_stored_text(self) -> None:
        receipt = self.seed("a")
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("UPDATE message_receipts SET target_bot_id = 'private invalid text'")
            conn.commit()
        for target in ("/messages", "/messages/" + receipt.message_id, "/messages/capacity"):
            status, body = self.request(target)
            self.assertEqual(503, status)
            self.assertNotIn("private", json.dumps(body))

    def test_capacity_budget_exhaustion_never_returns_partial_counts(self) -> None:
        self.seed("a")
        original = message_store._receipt
        clock = [0.0]

        def slow_receipt(*args, **kwargs):
            clock[0] = 3.0
            return original(*args, **kwargs)

        before = self.path.read_bytes()
        with (
            patch("zeus.message_store.time.monotonic", side_effect=lambda: clock[0]),
            patch("zeus.message_store._receipt", side_effect=slow_receipt),
        ):
            status, body = self.request("/messages/capacity")
        self.assertEqual(503, status)
        self.assertEqual({"error"}, set(body))
        self.assertEqual("message_read_budget_exceeded", body["error"]["code"])
        self.assertEqual(before, self.path.read_bytes())

    def test_sqlite_progress_handler_interrupts_expensive_work(self) -> None:
        self.seed("a")
        clock = [0.0]
        with (
            patch("zeus.message_store.time.monotonic", side_effect=lambda: clock[0]),
            self.assertRaisesRegex(MessageStoreError, "read_budget_exceeded"),
            self.store._read(deadline=2.0) as conn,
        ):
            clock[0] = 3.0
            with self.assertRaisesRegex(sqlite3.OperationalError, "interrupted"):
                conn.execute(
                    "WITH RECURSIVE counter(n) AS (VALUES(1) UNION ALL "
                    "SELECT n + 1 FROM counter WHERE n < 1000000) SELECT sum(n) FROM counter"
                ).fetchone()

    def test_capacity_lock_wait_is_limited_to_remaining_budget(self) -> None:
        self.seed("a")
        connect = sqlite3.connect
        clock = iter((0.0, 0.5, 0.5))
        with (
            patch("zeus.message_store.time.monotonic", side_effect=lambda: next(clock, 0.5)),
            patch("zeus.message_store.sqlite3.connect", wraps=connect) as observed,
        ):
            self.assertEqual(1, self.store.capacity(read_timeout_seconds=2.0)["total"])
        self.assertEqual(1.5, observed.call_args.kwargs["timeout"])

    def test_capacity_optional_budget_preserves_unlimited_cli_default(self) -> None:
        self.seed("a")
        with patch("zeus.message_store.time.monotonic", side_effect=AssertionError("no deadline")):
            self.assertEqual(1, self.store.capacity()["total"])
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.capacity(read_timeout_seconds=value)


if __name__ == "__main__":
    unittest.main()
