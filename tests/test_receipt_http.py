from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import ExitStack, closing, contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from tests.test_api import (
    request_json,
    request_json_with_headers,
    stop_api_fixture,
    wait_for_access_rows,
)
from tests.test_receipt_api import CAPACITY_FIELDS, PUBLIC_FIELDS
from zeus.api import make_handler
from zeus.api_server import ThreadingHTTPServer
from zeus.config import Settings
from zeus.integration_auth import IntegrationCredential
from zeus.message_store import MessageReceipt, MessageStore

ADMIN_KEY = "receipt-admin-example-key-" + "a" * 32
OBSERVER_KEY = "receipt-observer-example-key-" + "b" * 32
DIAGNOSTICS_KEY = "receipt-diagnostics-example-key-" + "c" * 32
OPERATOR_KEY = "receipt-operator-example-key-" + "d" * 32


@contextmanager
def receipt_server(*, allow_unauthenticated: bool = False) -> Iterator[tuple[int, Path]]:
    with tempfile.TemporaryDirectory() as tmp:
        settings = replace(
            Settings.from_env(
                {"ZEUS_STATE_DIR": str(Path(tmp) / "state"), "ZEUS_API_KEY": ADMIN_KEY},
                include_dotenv=False,
            ),
            allow_unauth_reads=allow_unauthenticated,
            api_integrations=(
                IntegrationCredential("dashboard", OBSERVER_KEY, frozenset({"observer"})),
                IntegrationCredential("diagnoser", DIAGNOSTICS_KEY, frozenset({"diagnostics"})),
                IntegrationCredential("controller", OPERATOR_KEY, frozenset({"operator"})),
            ),
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(settings))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, settings.state_dir
        finally:
            stop_api_fixture(server, thread)


def seed_receipt(
    path: Path, *, seconds: int = 0, prepared: bool = False, bot_id: str = "coder"
) -> MessageReceipt:
    now = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    store = MessageStore(path)
    receipt, _ = store.prepare(
        bot_id=bot_id,
        incarnation=now - timedelta(days=1),
        target_fingerprint="1" * 64,
        endpoint="http://127.0.0.1:8765/health",
        credential_fingerprint="2" * 64,
        input_fingerprint="3" * 64,
        request_key_fingerprint=None,
        now=now,
        retry_before=now + timedelta(minutes=10),
    )
    if not prepared:
        receipt = store.finish_attempt(
            receipt.message_id, expected_version=1, dispatch_state="rejected", now=now
        )
    return receipt


class ReceiptHttpTests(unittest.TestCase):
    def test_admin_and_observer_can_read_both_aliases_but_other_scopes_cannot(self) -> None:
        with receipt_server(allow_unauthenticated=True) as (port, state_dir):
            receipt = seed_receipt(state_dir / "zeus.db")
            for prefix in ("", "/v1"):
                for path in ("/messages", "/messages/capacity", "/messages/" + receipt.message_id):
                    for key, expected in (
                        (ADMIN_KEY, 200),
                        (OBSERVER_KEY, 200),
                        (DIAGNOSTICS_KEY, 403),
                        (OPERATOR_KEY, 403),
                        (None, 401),
                    ):
                        with self.subTest(prefix=prefix, path=path, expected=expected):
                            headers = {"x-zeus-api-key": key} if key else {}
                            status, body = request_json(port, "GET", prefix + path, headers=headers)
                            self.assertEqual(expected, status)
                            if expected == 403:
                                self.assertEqual("permission_denied", body["error"]["code"])

    def test_authorization_precedes_receipt_query_validation(self) -> None:
        with receipt_server(allow_unauthenticated=True) as (port, _):
            for prefix in ("", "/v1"):
                for path in ("/messages", "/messages/capacity", "/messages/" + "a" * 32):
                    target = prefix + path + "?unexpected=private-query-value"
                    self.assertEqual(401, request_json(port, "GET", target)[0])
                    self.assertEqual(
                        403,
                        request_json(
                            port, "GET", target, headers={"x-zeus-api-key": DIAGNOSTICS_KEY}
                        )[0],
                    )
                    status, body = request_json(
                        port, "GET", target, headers={"x-zeus-api-key": OBSERVER_KEY}
                    )
                    self.assertEqual(400, status)
                    self.assertNotIn("private-query-value", json.dumps(body))

    def test_read_responses_preserve_storage_and_do_not_touch_execution_paths(self) -> None:
        with receipt_server() as (port, state_dir):
            path = state_dir / "zeus.db"
            receipt = seed_receipt(path, prepared=True)
            with closing(sqlite3.connect(path)) as conn:
                conn.execute("PRAGMA journal_mode=DELETE")
                before_dump = list(conn.iterdump())
            before_bytes = path.read_bytes()
            forbidden = AssertionError("HTTP receipt read crossed its observation boundary")
            with ExitStack() as guards:
                for target in (
                    "zeus.bot_messaging.BotMessaging.__init__",
                    "zeus.bot_messaging.BotMessaging.send",
                    "zeus.bot_messaging.BotMessaging.retry",
                    "zeus.bot_messaging.BotMessaging.status",
                    "zeus.bot_messaging.BotMessaging.cancel",
                    "zeus.supervisor.Supervisor.status",
                    "zeus.supervisor.Supervisor.reconcile",
                    "zeus.supervisor.Supervisor.reconcile_summary",
                    "zeus.state.StateStore.init",
                    "zeus.hermes_runs_client.capabilities",
                    "zeus.hermes_runs_client.submit",
                    "zeus.hermes_runs_client.status",
                    "zeus.hermes_runs_client.stop",
                    "zeus.gateway_http.request_json",
                ):
                    guards.enter_context(patch(target, side_effect=forbidden))
                for prefix in ("", "/v1"):
                    for route, fields in (
                        ("/messages", {"items", "next_before"}),
                        ("/messages/" + receipt.message_id, PUBLIC_FIELDS),
                        ("/messages/capacity", CAPACITY_FIELDS),
                    ):
                        status, headers, payload = request_json_with_headers(
                            port,
                            "GET",
                            prefix + route,
                            headers={
                                "x-zeus-api-key": OBSERVER_KEY,
                                "x-zeus-integration-id": "admin",
                            },
                        )
                        self.assertEqual(200, status)
                        self.assertEqual(fields, set(payload))
                        self.assertEqual("no-store", headers["cache-control"])
                        self.assertRegex(headers["x-request-id"], r"^[0-9a-f]{32}$")
                        serialized = json.dumps(payload)
                        for value in (
                            OBSERVER_KEY,
                            receipt.endpoint,
                            receipt.upstream_key,
                            receipt.target_fingerprint,
                            receipt.credential_fingerprint,
                            receipt.request_hash,
                            str(state_dir),
                        ):
                            self.assertNotIn(value, serialized)
            self.assertEqual(before_bytes, path.read_bytes())
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(before_dump, list(conn.iterdump()))
                self.assertEqual("delete", conn.execute("PRAGMA journal_mode").fetchone()[0])
                self.assertEqual(
                    "prepared",
                    conn.execute("SELECT dispatch_state FROM message_receipts").fetchone()[0],
                )
            rows = wait_for_access_rows(state_dir, 6)
            self.assertEqual({"dashboard"}, {row["integration_id"] for row in rows})
            self.assertEqual(
                {"/messages", "/messages/{message_id}", "/messages/capacity"},
                {row["route"] for row in rows},
            )
            logs = json.dumps(rows)
            for value in (
                receipt.message_id,
                receipt.endpoint,
                receipt.upstream_key,
                receipt.request_hash,
                OBSERVER_KEY,
                ADMIN_KEY,
                str(state_dir),
            ):
                self.assertNotIn(value, logs)

    def test_http_pagination_detail_and_errors(self) -> None:
        headers = {"x-zeus-api-key": OBSERVER_KEY}
        with receipt_server() as (port, state_dir):
            path = state_dir / "zeus.db"
            older = seed_receipt(path)
            newer = seed_receipt(path, seconds=1)
            unrelated = seed_receipt(path, seconds=2, bot_id="other")
            status, first = request_json(
                port, "GET", "/v1/messages?bot_id=coder&limit=1", headers=headers
            )
            self.assertEqual(200, status)
            self.assertEqual([newer.message_id], [item["message_id"] for item in first["items"]])
            _, second = request_json(
                port,
                "GET",
                "/messages?bot_id=coder&before=" + first["next_before"],
                headers=headers,
            )
            self.assertEqual([older.message_id], [item["message_id"] for item in second["items"]])
            self.assertIsNone(second["next_before"])
            _, detail = request_json(port, "GET", "/messages/" + older.message_id, headers=headers)
            self.assertEqual(second["items"][0], detail)
            for prefix in ("", "/v1"):
                for target, expected, code in (
                    ("/messages?limit=101", 400, "invalid_request"),
                    ("/messages?limit=1&limit=2", 400, "invalid_request"),
                    ("/messages?before=" + "0" * 32, 400, "invalid_cursor"),
                    (
                        "/messages?bot_id=coder&before=" + unrelated.message_id,
                        400,
                        "invalid_cursor",
                    ),
                    ("/messages/capacity?refresh=true", 400, "invalid_request"),
                    ("/messages/" + "0" * 32, 404, "unknown_message"),
                ):
                    with self.subTest(target=prefix + target):
                        status, body = request_json(port, "GET", prefix + target, headers=headers)
                        self.assertEqual(expected, status)
                        self.assertEqual(code, body["error"]["code"])

    def test_missing_state_stays_missing_after_authenticated_http_reads(self) -> None:
        with receipt_server() as (port, state_dir):
            path = state_dir / "zeus.db"
            path.unlink()
            for prefix in ("", "/v1"):
                for target in ("/messages", "/messages/capacity", "/messages/" + "a" * 32):
                    status, body = request_json(
                        port, "GET", prefix + target, headers={"x-zeus-api-key": OBSERVER_KEY}
                    )
                    self.assertEqual(503, status)
                    self.assertEqual("message_store_unavailable", body["error"]["code"])
                    self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
