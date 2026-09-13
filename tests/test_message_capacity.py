from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.cli import main
from zeus.message_store import MessageStore, MessageStoreError
from zeus.state import StateStore


class MessageCapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state_dir = self.root / "state"
        self.path = self.state_dir / "zeus.db"
        StateStore(self.path).init()
        self.store = MessageStore(self.path)
        now = datetime(2026, 1, 1, tzinfo=UTC)
        receipt, _ = self.store.prepare(
            bot_id="coder",
            incarnation=now - timedelta(days=1),
            target_fingerprint="a" * 64,
            endpoint="http://127.0.0.1:8765/health",
            credential_fingerprint="b" * 64,
            input_fingerprint="c" * 64,
            request_key_fingerprint=None,
            now=now,
            retry_before=now + timedelta(minutes=10),
        )
        self.store.finish_attempt(
            receipt.message_id, expected_version=1, dispatch_state="rejected", now=now
        )
        self.receipt_id = receipt.message_id

    def _resize(self, total: int) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("DELETE FROM message_receipts WHERE message_id != ?", (self.receipt_id,))
            conn.executemany(
                "INSERT INTO message_receipts SELECT ?, NULL, target_bot_id, target_created_at, "
                "target_fingerprint, endpoint, credential_fingerprint, request_hash, ?, "
                "dispatch_state, run_id, run_status, created_at, updated_at, retry_before, "
                "last_checked_at, cancel_requested_at, lease_until, error_code, version, "
                "released_at "
                "FROM message_receipts WHERE message_id = ?",
                (
                    (f"{index:032x}", f"{index + 20000:032x}", self.receipt_id)
                    for index in range(1, total)
                ),
            )
            conn.commit()

    def _cli(self, *args: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(self.state_dir)}, clear=True),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(["message", "capacity", *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exact_capacity_thresholds(self) -> None:
        for total, expected in (
            (7999, "ok"),
            (8000, "warning"),
            (8001, "warning"),
            (9499, "warning"),
            (9500, "critical"),
            (9501, "critical"),
            (9999, "critical"),
            (10000, "full"),
            (10001, "full"),
        ):
            with self.subTest(total=total):
                self._resize(total)
                result = self.store.capacity()
                self.assertEqual(expected, result["status"])
                self.assertEqual(total, result["used"])
                self.assertEqual(total, result["total"])
                self.assertEqual(max(0, 10000 - total), result["remaining"])
                self.assertEqual(0, result["archived"])

    def test_blockers_are_distinct_from_retained_receipts(self) -> None:
        now = datetime(2026, 1, 2, tzinfo=UTC)
        active, _ = self.store.prepare(
            bot_id="active",
            incarnation=now - timedelta(days=1),
            target_fingerprint="d" * 64,
            endpoint="http://127.0.0.1:8766/health",
            credential_fingerprint="e" * 64,
            input_fingerprint="f" * 64,
            request_key_fingerprint=None,
            now=now,
            retry_before=now + timedelta(minutes=10),
        )
        result = self.store.capacity()
        self.assertEqual(2, result["used"])
        self.assertEqual(1, result["blocking"])
        self.store.finish_attempt(
            active.message_id,
            expected_version=1,
            dispatch_state="accepted",
            run_id="run-1",
            run_status="running",
            now=now,
        )
        self.assertEqual(1, self.store.capacity()["blocking"])
        self.store.release(active.message_id, expected_version=2, now=now)
        self.assertEqual(0, self.store.capacity()["blocking"])

    def test_invalid_receipt_fails_closed(self) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute(
                "UPDATE message_receipts SET target_bot_id = '!!' WHERE message_id = ?",
                (self.receipt_id,),
            )
            conn.commit()
        with self.assertRaisesRegex(MessageStoreError, "invalid_receipt"):
            self.store.capacity()

    def test_cli_is_read_only_one_document_and_full_exits_zero(self) -> None:
        self._resize(10000)
        forbidden = AssertionError("capacity command crossed its read-only boundary")
        with (
            patch("zeus.messaging_cli.BotMessaging", side_effect=forbidden),
            patch("zeus.messaging_cli.Supervisor", side_effect=forbidden),
            patch("zeus.messaging_cli.StateStore", side_effect=forbidden),
            patch("subprocess.Popen", side_effect=forbidden),
            patch("subprocess.run", side_effect=forbidden),
            patch("os.kill", side_effect=forbidden),
            patch("os.killpg", side_effect=forbidden),
            patch("zeus.hermes_runs_client.request_json", side_effect=forbidden),
            patch("zeus.gateway_http.request_json", side_effect=forbidden),
            patch("zeus.gateway_http.socket.socket", side_effect=forbidden),
        ):
            code, output, error = self._cli("--json")
        self.assertEqual(0, code)
        self.assertEqual("", error)
        payload = json.loads(output)
        self.assertEqual("full", payload["status"])
        self.assertEqual(10000, payload["limit"])
        self.assertIsInstance(payload["database_bytes"], int)
        self.assertIsInstance(payload["filesystem_free_bytes"], int)

    def test_missing_state_and_unavailable_observations_are_safe(self) -> None:
        self.path.unlink()
        code, output, _error = self._cli("--json")
        self.assertEqual(1, code)
        self.assertIn(json.loads(output)["error"]["code"], {"state_unavailable", "not_ready"})
        self.assertFalse(self.path.exists())

        StateStore(self.path).init()
        with (
            patch("zeus.message_store._file_size", return_value=None),
            patch("zeus.message_store._wal_size", return_value=None),
            patch("zeus.message_store._filesystem_free", return_value=None),
        ):
            result = MessageStore(self.path).capacity()
        self.assertIsNone(result["database_bytes"])
        self.assertIsNone(result["wal_bytes"])
        self.assertIsNone(result["filesystem_free_bytes"])

    def test_incompatible_and_malformed_databases_are_not_modified(self) -> None:
        for content in (b"not sqlite", b""):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                before = self.path.read_bytes()
                code, output, _error = self._cli("--json")
                self.assertEqual(1, code)
                self.assertEqual("state_unavailable", json.loads(output)["error"]["code"])
                self.assertEqual(before, self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
