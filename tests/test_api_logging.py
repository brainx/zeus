from __future__ import annotations

import http.client
import io
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import call, patch

from zeus.api import make_handler
from zeus.api_logging import ApiLogWriter
from zeus.config import Settings
from zeus.request_context import (
    IDEMPOTENCY_OUTCOMES,
    RequestContext,
    new_request_id,
    route_template,
)


def raw_http_request(port: int, request: bytes) -> tuple[int, dict[str, str], dict[str, Any]]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk

    raw_headers, separator, raw_body = response.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError(f"raw HTTP response did not include headers: {response!r}")
    header_lines = raw_headers.decode("iso-8859-1").split("\r\n")
    status = int(header_lines[0].split(maxsplit=2)[1])
    headers = {
        name.strip().lower(): value.strip()
        for line in header_lines[1:]
        for name, value in [line.split(":", maxsplit=1)]
    }
    body = json.loads(raw_body.decode("utf-8"))
    return status, headers, body


class ApiLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _wait_for_log_rows(
        self, path: Path, *, count: int, timeout_seconds: float = 2
    ) -> list[dict[str, object]]:
        deadline = time.monotonic() + timeout_seconds
        rows: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            if path.exists():
                rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                if len(rows) >= count:
                    break
            threading.Event().wait(0.01)
        return rows

    def test_request_ids_are_lowercase_uuid_hex(self) -> None:
        request_id = new_request_id()
        self.assertRegex(request_id, r"^[0-9a-f]{32}$")

    def test_request_context_finishes_with_safe_outcome_defaults(self) -> None:
        fields = RequestContext(request_id="a" * 32, started_at=time.monotonic()).finish(200, None)

        self.assertEqual("not_checked", fields["auth_outcome"])
        self.assertEqual("not_applicable", fields["idempotency_outcome"])

    def test_idempotency_outcomes_are_a_closed_secret_free_vocabulary(self) -> None:
        self.assertEqual(
            {
                "not_applicable",
                "claimed",
                "replayed",
                "conflict",
                "in_progress",
                "indeterminate",
                "unavailable",
            },
            IDEMPOTENCY_OUTCOMES,
        )
        writer = ApiLogWriter(self.root / "outcomes.jsonl", enabled=True)
        for outcome in sorted(IDEMPOTENCY_OUTCOMES):
            writer.access({"idempotency_outcome": outcome})
        rows = [
            json.loads(line)
            for line in (self.root / "outcomes.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(sorted(IDEMPOTENCY_OUTCOMES), [row["idempotency_outcome"] for row in rows])

    def test_route_templates_hide_bot_ids_and_normalize_v1(self) -> None:
        self.assertEqual("/bots/{bot_id}/start", route_template("/v1/bots/secret-bot/start"))
        self.assertEqual("/bots/{bot_id}/history", route_template("/v1/bots/secret-bot/history"))
        self.assertIsNone(route_template("/not-a-route"))

    def test_api_log_writer_writes_parseable_redacted_lines(self) -> None:
        writer = ApiLogWriter(self.root / "api.jsonl", enabled=True)
        writer.access(
            {
                "request_id": "a" * 32,
                "method": "GET",
                "route": "/health",
                "status": 200,
                "error_code": "request_failed",
                "bot_id": "private-bot-id",
            }
        )
        writer.error("a" * 32, RuntimeError("TOKEN=plain-secret"))

        rows = [
            json.loads(line)
            for line in (self.root / "api.jsonl").read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(["api.access", "api.error"], [row["event"] for row in rows])
        self.assertEqual([1, 1], [row["schema_version"] for row in rows])
        self.assertEqual(["info", "error"], [row["level"] for row in rows])
        serialized = json.dumps(rows)
        self.assertNotIn("plain-secret", serialized)
        self.assertNotIn("private-bot-id", serialized)
        self.assertEqual("request_failed", rows[0]["error_code"])
        self.assertEqual("RuntimeError", rows[1]["error_type"])
        self.assertEqual("Unexpected API error", rows[1]["message"])

    def test_api_logging_rejects_secret_bearing_request_ids(self) -> None:
        access_path = self.root / "access.jsonl"
        error_path = self.root / "error.jsonl"
        secret_request_id = "TOKEN=request-secret?bot_id=private-bot&client=10.0.0.1:1234"

        ApiLogWriter(access_path, enabled=True).access(
            {"request_id": secret_request_id, "status": 200}
        )
        ApiLogWriter(error_path, enabled=True).error(secret_request_id, RuntimeError("safe"))

        self.assertFalse(access_path.exists())
        self.assertFalse(error_path.exists())

    def test_api_access_rejects_nested_values_under_allowed_fields(self) -> None:
        path = self.root / "api.jsonl"
        writer = ApiLogWriter(path, enabled=True)

        for forbidden_key in ("body", "authorization", "query", "bot_id", "client_ip"):
            writer.access(
                {
                    "status": 500,
                    "error_code": {forbidden_key: "must-not-be-written"},
                }
            )

        self.assertFalse(path.exists())

    def test_api_access_rejects_invalid_and_nonfinite_schema_values(self) -> None:
        path = self.root / "api.jsonl"
        writer = ApiLogWriter(path, enabled=True)

        invalid_fields = (
            {"request_id": 123},
            {"request_id": None},
            {"request_id": "A" * 32},
            {"request_id": "a" * 31},
            {"request_id": "g" * 32},
            {"method": object()},
            {"route": ["/health"]},
            {"status": True},
            {"status": "200"},
            {"error_code": {"body": "must-not-be-written"}},
            {"duration_ms": True},
            {"duration_ms": float("inf")},
            {"duration_ms": float("-inf")},
            {"duration_ms": float("nan")},
            {"auth_outcome": "TOKEN=private"},
            {"auth_outcome": "unknown"},
            {"idempotency_outcome": "key=private"},
            {"idempotency_outcome": "unknown"},
        )
        for fields in invalid_fields:
            writer.access(fields)

        self.assertFalse(path.exists())

    def test_api_access_rejects_unsafe_context_labels(self) -> None:
        path = self.root / "api.jsonl"
        writer = ApiLogWriter(path, enabled=True)

        invalid_fields = (
            {"method": "get"},
            {"method": "GET client=10.0.0.1"},
            {"method": "POST body=private"},
            {"route": "/bots/private-bot/status"},
            {"route": "/health?api_key=private"},
            {"route": "/v1/health"},
            {"error_code": "TOKEN=private"},
            {"error_code": "body=private"},
            {"error_code": "1_invalid"},
            {"error_code": "UPPERCASE"},
        )
        for fields in invalid_fields:
            writer.access(fields)

        self.assertFalse(path.exists())

    def test_api_access_accepts_normalized_context_labels(self) -> None:
        path = self.root / "api.jsonl"

        ApiLogWriter(path, enabled=True).access(
            {
                "request_id": "a" * 32,
                "method": "POST",
                "route": "/bots/{bot_id}/restart",
                "status": 409,
                "error_code": "restart_conflict_2",
                "duration_ms": 1.25,
                "auth_outcome": "authenticated",
                "idempotency_outcome": "not_applicable",
            }
        )

        row = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("POST", row["method"])
        self.assertEqual("/bots/{bot_id}/restart", row["route"])
        self.assertEqual("restart_conflict_2", row["error_code"])
        self.assertEqual("authenticated", row["auth_outcome"])
        self.assertEqual("not_applicable", row["idempotency_outcome"])

    def test_api_log_failure_is_fail_open(self) -> None:
        bad_path = self.root / "directory"
        bad_path.mkdir()

        ApiLogWriter(bad_path, enabled=True).access({"status": 200})

        disabled_path = self.root / "disabled.jsonl"
        ApiLogWriter(disabled_path, enabled=False).access({"status": 200})
        self.assertFalse(disabled_path.exists())

    def test_api_access_payload_building_is_fail_open(self) -> None:
        class BrokenString:
            def __str__(self) -> str:
                raise RuntimeError("string conversion failed")

        path = self.root / "api.jsonl"
        ApiLogWriter(path, enabled=True).access({"status": BrokenString()})

        self.assertFalse(path.exists())

    def test_api_error_payload_building_is_fail_open(self) -> None:
        class BrokenException(Exception):
            def __str__(self) -> str:
                raise RuntimeError("exception conversion failed")

        path = self.root / "api.jsonl"
        ApiLogWriter(path, enabled=True).error("a" * 32, BrokenException())

        row = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("Exception", row["error_type"])
        self.assertEqual("Unexpected API error", row["message"])

    def test_api_log_writer_creates_private_directory_and_file(self) -> None:
        path = self.root / "logs" / "api.jsonl"

        ApiLogWriter(path, enabled=True).access({"status": 200})

        self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_api_log_writer_tightens_existing_directory_and_file_modes(self) -> None:
        directory = self.root / "logs"
        directory.mkdir(mode=0o755)
        path = directory / "api.jsonl"
        path.write_text("", encoding="utf-8")
        directory.chmod(0o755)
        path.chmod(0o644)

        ApiLogWriter(path, enabled=True).access({"status": 200})

        self.assertEqual(0o700, stat.S_IMODE(directory.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(200, json.loads(path.read_text(encoding="utf-8"))["status"])

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW unavailable")
    def test_api_log_writer_does_not_follow_symlinked_log_directory(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o755)
        outside.chmod(0o755)
        outside_mode = stat.S_IMODE(outside.stat().st_mode)
        logs = self.root / "state" / "logs"
        logs.parent.mkdir()
        logs.symlink_to(outside, target_is_directory=True)

        ApiLogWriter(logs / "api.jsonl", enabled=True).access({"status": 200})

        self.assertFalse((outside / "api.jsonl").exists())
        self.assertEqual(outside_mode, stat.S_IMODE(outside.stat().st_mode))

    def test_api_log_writer_closes_descriptor_when_fchmod_fails(self) -> None:
        path = self.root / "api.jsonl"

        with (
            patch("zeus.api_logging.os.fchmod", side_effect=OSError("denied")),
            patch("zeus.api_logging.os.close", wraps=os.close) as close,
        ):
            ApiLogWriter(path, enabled=True).access({"status": 200})

        close.assert_called_once()
        self.assertFalse(path.exists())

    def test_api_log_writer_closes_both_descriptors_when_file_fchmod_fails(self) -> None:
        path = self.root / "api.jsonl"

        with (
            patch("zeus.api_logging.os.fchmod", side_effect=[None, OSError("denied")]),
            patch("zeus.api_logging.os.close", wraps=os.close) as close,
        ):
            ApiLogWriter(path, enabled=True).access({"status": 200})

        self.assertEqual(2, close.call_count)
        self.assertEqual("", path.read_text(encoding="utf-8"))

    def test_api_log_writer_attempts_directory_close_when_file_close_fails(self) -> None:
        path = self.root / "api.jsonl"

        with (
            patch("zeus.api_logging.os.open", side_effect=[101, 202]),
            patch("zeus.api_logging.os.fchmod", side_effect=[None, OSError("denied")]),
            patch(
                "zeus.api_logging.os.close",
                side_effect=[OSError("file close failed"), None],
            ) as close,
        ):
            ApiLogWriter(path, enabled=True).access({"status": 200})

        self.assertEqual([call(202), call(101)], close.call_args_list)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW unavailable")
    def test_api_log_writer_does_not_follow_symlinks(self) -> None:
        target = self.root / "target.jsonl"
        target.write_text("original\n", encoding="utf-8")
        path = self.root / "api.jsonl"
        path.symlink_to(target)

        ApiLogWriter(path, enabled=True).access({"status": 200})

        self.assertEqual("original\n", target.read_text(encoding="utf-8"))

    def test_api_error_omits_exception_messages_and_tracebacks(self) -> None:
        path = self.root / "api.jsonl"
        sensitive_message = (
            "bot_id=private-bot client=10.0.0.1:4321 ?api_key=plain-secret TOKEN=token-secret"
        )
        ApiLogWriter(path, enabled=True).error("a" * 32, RuntimeError(sensitive_message))

        row = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("RuntimeError", row["error_type"])
        self.assertEqual("Unexpected API error", row["message"])
        serialized = json.dumps(row)
        for sensitive_value in (
            "private-bot",
            "10.0.0.1",
            "4321",
            "api_key",
            "plain-secret",
            "token-secret",
        ):
            self.assertNotIn(sensitive_value, serialized)
        self.assertNotIn("traceback", row)

    def test_api_error_uses_generic_type_for_custom_exception_classes(self) -> None:
        path = self.root / "api.jsonl"
        hostile_class_name = "TOKEN=class-secret?bot_id=private-bot&client=10.0.0.1"
        exception_type = type(hostile_class_name, (RuntimeError,), {})

        ApiLogWriter(path, enabled=True).error("a" * 32, exception_type("TOKEN=message-secret"))

        row = json.loads(path.read_text(encoding="utf-8"))
        serialized = json.dumps(row)
        self.assertEqual("Exception", row["error_type"])
        self.assertEqual("Unexpected API error", row["message"])
        for sensitive_value in (
            "class-secret",
            "private-bot",
            "10.0.0.1",
            "message-secret",
        ):
            self.assertNotIn(sensitive_value, serialized)

    def test_api_error_accepts_generated_request_ids(self) -> None:
        path = self.root / "api.jsonl"
        request_id = new_request_id()

        ApiLogWriter(path, enabled=True).error(request_id, RuntimeError("safe"))

        row = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(request_id, row["request_id"])
        self.assertEqual("RuntimeError", row["error_type"])

    def test_api_log_writer_serializes_concurrent_events_as_complete_lines(self) -> None:
        path = self.root / "api.jsonl"
        writer = ApiLogWriter(path, enabled=True)

        with ThreadPoolExecutor(max_workers=16) as executor:
            list(executor.map(lambda index: writer.access({"status": index}), range(100)))

        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(100, len(rows))
        self.assertEqual(set(range(100)), {row["status"] for row in rows})
        self.assertTrue(all(row["event"] == "api.access" for row in rows))

    def test_api_logging_defaults_enabled_and_can_be_disabled(self) -> None:
        self.assertTrue(Settings.from_env({}).api_log_enabled)
        self.assertFalse(Settings.from_env({"ZEUS_API_LOG_ENABLED": "0"}).api_log_enabled)

    def test_each_terminal_response_writes_exactly_one_access_row(self) -> None:
        state_dir = self.root / "state"
        handler = make_handler(
            Settings.from_env(
                {
                    "ZEUS_API_KEY": "secret",
                    "ZEUS_STATE_DIR": str(state_dir),
                }
            )
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        requests = (
            ("GET", "/health", 200),
            ("GET", "/health?unknown=1", 400),
            ("GET", "/v1/health", 200),
            ("PUT", "/bots", 405),
        )
        try:
            for method, path, expected_status in requests:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    conn.request(method, path)
                    response = conn.getresponse()
                    response.read()
                finally:
                    conn.close()
                self.assertEqual(expected_status, response.status)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        rows = self._wait_for_log_rows(state_dir / "logs" / "api.jsonl", count=4)
        access_rows = [row for row in rows if row["event"] == "api.access"]
        self.assertEqual(4, len(rows))
        self.assertEqual(4, len(access_rows))
        self.assertCountEqual(
            [
                ("GET", "/health", 200),
                ("GET", "/health", 400),
                ("GET", "/health", 200),
                ("UNSUPPORTED", "/bots", 405),
            ],
            [(row["method"], row["route"], row["status"]) for row in access_rows],
        )
        self.assertEqual(
            ["not_required", "not_required", "not_required", "not_required"],
            [row["auth_outcome"] for row in access_rows],
        )
        for row in access_rows:
            self.assertEqual(
                {
                    "schema_version",
                    "ts",
                    "level",
                    "event",
                    "request_id",
                    "method",
                    "route",
                    "status",
                    "error_code",
                    "duration_ms",
                    "auth_outcome",
                    "idempotency_outcome",
                },
                set(row),
            )
            self.assertEqual(1, row["schema_version"])
            self.assertEqual("info", row["level"])
            self.assertEqual("not_applicable", row["idempotency_outcome"])

    def test_all_unsupported_methods_are_correlated_and_safely_logged(self) -> None:
        state_dir = self.root / "state-unsupported"
        handler = make_handler(
            Settings.from_env(
                {
                    "ZEUS_API_KEY": "secret",
                    "ZEUS_STATE_DIR": str(state_dir),
                }
            )
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = "/bots/private-bot/status?api_key=target-secret"
        responses: list[tuple[int, dict[str, str], dict[str, Any]]] = []
        try:
            for method in ("HEAD", "TRACE", "CONNECT", "ZEUS-EXT"):
                responses.append(
                    raw_http_request(
                        server.server_port,
                        (
                            f"{method} {target} HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\nConnection: close\r\n\r\n"
                        ).encode("ascii"),
                    )
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        for status, headers, body in responses:
            self.assertEqual(405, status)
            self.assertEqual("application/json", headers.get("content-type"))
            self.assertRegex(headers.get("x-request-id", ""), r"^[0-9a-f]{32}$")
            self.assertEqual("GET, POST", headers.get("allow"))
            self.assertEqual("method_not_allowed", body["error"]["code"])
            self.assertEqual(405, body["error"]["status"])

        rows = self._wait_for_log_rows(state_dir / "logs" / "api.jsonl", count=4)
        self.assertEqual(4, len(rows))
        self.assertEqual(["UNSUPPORTED"] * 4, [row["method"] for row in rows])
        self.assertEqual([405] * 4, [row["status"] for row in rows])
        self.assertEqual(["method_not_allowed"] * 4, [row["error_code"] for row in rows])
        self.assertEqual(
            ["/bots/{bot_id}/status"] * 4,
            [row["route"] for row in rows],
        )
        serialized = json.dumps({"responses": responses, "rows": rows})
        self.assertNotIn("private-bot", serialized)
        self.assertNotIn("target-secret", serialized)

    def test_access_rows_record_deterministic_authentication_outcomes(self) -> None:
        cases = (
            ({"ZEUS_API_KEY": "secret"}, {}, 401, "missing"),
            (
                {"ZEUS_API_KEY": "secret"},
                {"x-zeus-api-key": "wrong"},
                401,
                "rejected",
            ),
            (
                {"ZEUS_API_KEY": "secret"},
                {"x-zeus-api-key": "secret"},
                200,
                "authenticated",
            ),
            (
                {"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"},
                {},
                200,
                "allowed_unauthenticated",
            ),
            ({"ZEUS_API_KEY": ""}, {}, 503, "unconfigured"),
        )

        for index, (settings_env, headers, expected_status, expected_outcome) in enumerate(cases):
            with self.subTest(expected_outcome=expected_outcome):
                state_dir = self.root / f"state-{index}"
                handler = make_handler(
                    Settings.from_env({"ZEUS_STATE_DIR": str(state_dir), **settings_env})
                )
                server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                    try:
                        conn.request("GET", "/bots", headers=headers)
                        response = conn.getresponse()
                        response.read()
                    finally:
                        conn.close()
                    self.assertEqual(expected_status, response.status)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=1)

                rows = self._wait_for_log_rows(state_dir / "logs" / "api.jsonl", count=1)
                self.assertEqual(1, len(rows))
                self.assertEqual(expected_outcome, rows[0]["auth_outcome"])
                self.assertEqual("not_applicable", rows[0]["idempotency_outcome"])

    def test_malformed_absolute_target_gets_correlated_redacted_400(self) -> None:
        state_dir = self.root / "state"
        raw_target = "http://[TOKEN=target-secret/health"
        handler = make_handler(
            Settings.from_env(
                {
                    "ZEUS_API_KEY": "secret",
                    "ZEUS_STATE_DIR": str(state_dir),
                }
            )
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            thread.start()
            try:
                status, headers, body = raw_http_request(
                    server.server_port,
                    (
                        f"GET {raw_target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                    ).encode("ascii"),
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=1)

        self.assertEqual(400, status)
        self.assertRegex(headers.get("x-request-id", ""), r"^[0-9a-f]{32}$")
        self.assertEqual("invalid_request", body["error"]["code"])
        rows = self._wait_for_log_rows(state_dir / "logs" / "api.jsonl", count=1)
        self.assertEqual(1, len(rows))
        self.assertEqual("api.access", rows[0]["event"])
        self.assertEqual(400, rows[0]["status"])
        self.assertIsNone(rows[0]["route"])
        serialized = json.dumps({"body": body, "rows": rows, "stderr": stderr.getvalue()})
        self.assertNotIn(raw_target, serialized)
        self.assertNotIn("target-secret", serialized)

    def test_response_write_failure_logs_at_most_one_error_and_one_access(self) -> None:
        state_dir = self.root / "state"
        secret = "TOKEN=response-write-secret"
        handler = make_handler(
            Settings.from_env(
                {
                    "ZEUS_API_KEY": "secret",
                    "ZEUS_STATE_DIR": str(state_dir),
                }
            )
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        stderr = io.StringIO()
        with (
            patch.object(handler, "_json", side_effect=RuntimeError(secret)),
            redirect_stderr(stderr),
        ):
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    conn.request("GET", "/health")
                    with self.assertRaises(http.client.RemoteDisconnected):
                        conn.getresponse()
                finally:
                    conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=1)

        rows = self._wait_for_log_rows(state_dir / "logs" / "api.jsonl", count=2)
        error_rows = [row for row in rows if row["event"] == "api.error"]
        access_rows = [row for row in rows if row["event"] == "api.access"]
        self.assertEqual(1, len(error_rows))
        self.assertEqual(1, len(access_rows))
        self.assertEqual(500, access_rows[0]["status"])
        self.assertEqual("/health", access_rows[0]["route"])
        self.assertNotIn(secret, json.dumps(rows))
        self.assertNotIn(secret, stderr.getvalue())

    def test_unexpected_error_logs_correlated_generic_500(self) -> None:
        state_dir = self.root / "state"
        secret = "TOKEN=plain-secret"

        with patch("zeus.api.run_doctor", side_effect=RuntimeError(secret)):
            handler = make_handler(
                Settings.from_env(
                    {
                        "ZEUS_API_KEY": "secret",
                        "ZEUS_STATE_DIR": str(state_dir),
                    }
                )
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    conn.request("GET", "/doctor", headers={"x-zeus-api-key": "secret"})
                    response = conn.getresponse()
                    body = json.loads(response.read().decode("utf-8"))
                finally:
                    conn.close()
                request_id = response.getheader("x-request-id") or ""
                self.assertEqual(500, response.status)
                self.assertRegex(request_id, r"^[0-9a-f]{32}$")
                self.assertEqual(
                    {
                        "error": {
                            "code": "internal_error",
                            "message": "internal server error",
                            "status": 500,
                        }
                    },
                    body,
                )

                log_path = state_dir / "logs" / "api.jsonl"
                deadline = time.monotonic() + 2
                rows: list[dict[str, object]] = []
                while time.monotonic() < deadline:
                    if log_path.exists():
                        rows = [
                            json.loads(line)
                            for line in log_path.read_text(encoding="utf-8").splitlines()
                        ]
                        if len(rows) == 2:
                            break
                    threading.Event().wait(0.01)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=1)

        self.assertEqual(["api.error", "api.access"], [row["event"] for row in rows])
        self.assertEqual([request_id, request_id], [row["request_id"] for row in rows])
        self.assertEqual(500, rows[1]["status"])
        self.assertEqual("internal_error", rows[1]["error_code"])
        self.assertEqual("/doctor", rows[1]["route"])
        self.assertEqual("GET", rows[1]["method"])
        serialized = json.dumps(rows)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("plain-secret", serialized)
