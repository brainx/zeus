from __future__ import annotations

import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeus import api as api_module
from zeus.api import make_handler, serve
from zeus.config import Settings
from zeus.errors import ZeusConflictError
from zeus.models import BotRecord, BotStatus, BotStatusResponse, TemplateError
from zeus.process_lock import LockTimeoutError
from zeus.rate_limit import TokenBucket
from zeus.reconciliation import (
    BotReconcileResult,
    ReconcileLockTimeoutError,
    ReconcileOutcome,
    ReconcileRunSummary,
)
from zeus.state import StateStore

JsonPayload = dict[str, Any] | list[Any]


@contextmanager
def api_server_with_state(env: dict[str, str] | None = None) -> Iterator[tuple[int, Path]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        settings_env = {
            "ZEUS_STATE_DIR": str(root / ".zeus"),
            "ZEUS_HOST": "127.0.0.1",
            "ZEUS_PORT": "0",
            "ZEUS_API_KEY": "",
            "ZEUS_ALLOW_UNAUTH_READS": "",
        }
        if env:
            settings_env.update(env)
        settings = Settings.from_env(settings_env)
        handler = make_handler(settings)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, settings.state_dir
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)


@contextmanager
def api_server(env: dict[str, str] | None = None) -> Iterator[int]:
    with api_server_with_state(env) as (port, _state_dir):
        yield port


def request_json(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        response_body = response.read()
        return response.status, json.loads(response_body.decode("utf-8"))
    finally:
        conn.close()


def request_json_with_headers(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], JsonPayload]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        response_body = response.read()
        return (
            response.status,
            {name.lower(): value for name, value in response.getheaders()},
            json.loads(response_body.decode("utf-8")),
        )
    finally:
        conn.close()


def wait_for_access_rows(state_dir: Path, count: int) -> list[dict[str, Any]]:
    path = state_dir / "logs" / "api.jsonl"
    deadline = time.monotonic() + 2
    while True:
        try:
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        except FileNotFoundError:
            rows = []
        if len(rows) >= count:
            return rows
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected at least {count} API access rows, found {len(rows)}")
        time.sleep(0.01)


class ApiFakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def raw_http_response(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        response.read()
        return response
    finally:
        conn.close()


def json_request_body(payload: JsonPayload) -> bytes:
    return json.dumps(payload).encode("utf-8")


def auth_json_headers(key: str = "secret") -> dict[str, str]:
    return {"content-type": "application/json", "x-zeus-api-key": key}


def adversarial_reconcile_summary() -> ReconcileRunSummary:
    started_at = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)
    escaped_message = "\x1f" * 682 + "xx"
    if len(json.dumps(escaped_message).encode("utf-8")) != 4_096:
        raise AssertionError("adversarial message must exactly reach the keyed message cap")
    result = BotReconcileResult(
        bot_id="coder",
        outcome=ReconcileOutcome.error,
        desired_state="running",
        observed_status="failed",
        pid=2**63 - 1,
        action="\U0010ffff" * api_module.MAX_RECONCILE_TEXT_LENGTH,
        message=escaped_message,
        error_code="\U0010ffff" * api_module.MAX_RECONCILE_TEXT_LENGTH,
        event_id=2**63 - 1,
        started_at=started_at,
        finished_at=started_at,
    )
    counts = {outcome.value: 0 for outcome in ReconcileOutcome}
    counts[ReconcileOutcome.error.value] = 1
    return ReconcileRunSummary(
        run_id="f" * 32,
        scope="fleet",
        started_at=started_at,
        finished_at=started_at,
        outcome="completed_with_errors",
        total=1,
        counts=counts,
        results=(result,),
    )


def raw_request_json(port: int, request: bytes) -> tuple[int, dict[str, Any]]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
    header, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError(f"raw HTTP response did not include headers: {response!r}")
    status = int(header.split(maxsplit=2)[1])
    return status, json.loads(body.decode("utf-8"))


def raw_post_with_content_length(port: int, content_length: str) -> tuple[int, dict[str, Any]]:
    request = (
        "POST /bots HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "Content-Type: application/json\r\n"
        "X-Zeus-Api-Key: secret\r\n"
        f"Content-Length: {content_length}\r\n"
        "\r\n"
    ).encode("ascii")
    return raw_request_json(port, request)


def raw_post_without_content_length(port: int, body: bytes) -> tuple[int, dict[str, Any]]:
    request = (
        b"POST /bots HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Connection: close\r\n"
        b"Content-Type: application/json\r\n"
        b"X-Zeus-Api-Key: secret\r\n"
        b"\r\n" + body
    )
    return raw_request_json(port, request)


class ApiBehaviorTests(unittest.TestCase):
    def test_exception_status_payload_and_header_contracts(self) -> None:
        cases = (
            (
                "unknown_bot",
                lambda: KeyError("unknown bot: coder"),
                404,
                "unknown_bot",
                "unknown bot: coder",
            ),
            (
                "unknown_template",
                lambda: KeyError("unknown template: missing"),
                400,
                "unknown_template",
                "unknown template: missing",
            ),
            (
                "missing_field",
                lambda: KeyError("bot_id"),
                400,
                "invalid_request",
                "missing required field: bot_id",
            ),
            (
                "invalid_bot_id",
                lambda: TemplateError("bot_id must match ^[a-z][a-z0-9-]{1,62}$"),
                400,
                "invalid_bot_id",
                "bot_id must match ^[a-z][a-z0-9-]{1,62}$",
            ),
            (
                "template_error",
                lambda: TemplateError("template contract failed"),
                400,
                "invalid_request",
                "template contract failed",
            ),
            (
                "reconcile_lock",
                lambda: ReconcileLockTimeoutError(Path("/tmp/reconcile.lock"), 0.1),
                409,
                "reconcile_locked",
                "reconciliation is already in progress",
            ),
            (
                "bot_lock",
                lambda: LockTimeoutError(Path("/tmp/coder.lock"), 0.1),
                409,
                "bot_locked",
                "bot lifecycle operation is already in progress",
            ),
            (
                "conflict",
                lambda: ZeusConflictError("conflicting lifecycle state"),
                409,
                "conflict",
                "conflicting lifecycle state",
            ),
            (
                "value_error",
                lambda: ValueError("invalid lifecycle request"),
                400,
                "invalid_request",
                "invalid lifecycle request",
            ),
            (
                "internal_error",
                lambda: RuntimeError("private failure detail"),
                500,
                "internal_error",
                "internal server error",
            ),
        )

        class RaisingSupervisor:
            failure: Exception

            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def status(self, *args: object, **kwargs: object) -> BotStatusResponse:
                raise self.failure

            def start(self, *args: object, **kwargs: object) -> BotStatusResponse:
                raise self.failure

        with (
            patch("zeus.api.Supervisor", RaisingSupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            for name, make_error, expected_status, code, message in cases:
                expected = {
                    "error": {
                        "code": code,
                        "message": message,
                        "status": expected_status,
                    }
                }
                expected_body = json.dumps(expected, sort_keys=True).encode("utf-8")
                requests = (
                    ("GET", "/bots/coder/status", {}),
                    (
                        "POST",
                        "/bots/coder/start",
                        {"idempotency-key": f"characterization-{name}"},
                    ),
                )
                for method, path, extra_headers in requests:
                    with self.subTest(name=name, method=method):
                        RaisingSupervisor.failure = make_error()
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            conn.request(
                                method,
                                path,
                                headers={
                                    "x-zeus-api-key": "secret",
                                    **extra_headers,
                                },
                            )
                            response = conn.getresponse()
                            body = response.read()
                            headers = {key.lower(): value for key, value in response.getheaders()}
                        finally:
                            conn.close()

                        self.assertEqual(expected_status, response.status)
                        self.assertEqual(expected_body, body)
                        self.assertEqual(
                            {
                                "cache-control": "no-store",
                                "content-length": str(len(expected_body)),
                                "content-type": "application/json",
                                "cross-origin-resource-policy": "same-origin",
                                "referrer-policy": "no-referrer",
                                "x-content-type-options": "nosniff",
                            },
                            {
                                key: headers[key]
                                for key in (
                                    "cache-control",
                                    "content-length",
                                    "content-type",
                                    "cross-origin-resource-policy",
                                    "referrer-policy",
                                    "x-content-type-options",
                                )
                            },
                        )
                        self.assertRegex(headers["x-request-id"], r"^[0-9a-f]{32}$")

    def test_all_json_responses_include_generated_request_id(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            for method, path in (("GET", "/health"), ("GET", "/bots"), ("PUT", "/bots")):
                with self.subTest(method=method, path=path):
                    response = raw_http_response(port, method, path)
                    self.assertRegex(
                        response.getheader("x-request-id") or "",
                        r"^[0-9a-f]{32}$",
                    )

    def test_api_resource_limits_are_configurable_and_bounded(self) -> None:
        defaults = Settings.from_env({})
        configured = Settings.from_env(
            {
                "ZEUS_API_MAX_CONCURRENT_REQUESTS": "2",
                "ZEUS_API_REQUEST_TIMEOUT_SECONDS": "0.25",
                "ZEUS_API_SHUTDOWN_DRAIN_SECONDS": "0.25",
            }
        )

        self.assertEqual(32, getattr(defaults, "api_max_concurrent_requests", None))
        self.assertEqual(10.0, getattr(defaults, "api_request_timeout_seconds", None))
        self.assertEqual(20.0, getattr(defaults, "api_shutdown_drain_seconds", None))
        self.assertEqual(2, getattr(configured, "api_max_concurrent_requests", None))
        self.assertEqual(0.25, getattr(configured, "api_request_timeout_seconds", None))
        self.assertEqual(0.25, getattr(configured, "api_shutdown_drain_seconds", None))

        with tempfile.TemporaryDirectory() as tmp:
            wired_settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / "state"),
                    "ZEUS_API_MAX_CONCURRENT_REQUESTS": "2",
                    "ZEUS_API_REQUEST_TIMEOUT_SECONDS": "0.25",
                }
            )
            handler = make_handler(wired_settings)

        self.assertEqual(2, handler.api_max_concurrent_requests)
        self.assertEqual(0.25, handler.api_request_timeout_seconds)

        invalid_values = (
            ({"ZEUS_API_MAX_CONCURRENT_REQUESTS": "0"}, "between 1 and 256"),
            ({"ZEUS_API_MAX_CONCURRENT_REQUESTS": "257"}, "between 1 and 256"),
            ({"ZEUS_API_REQUEST_TIMEOUT_SECONDS": "0"}, "between 0.1 and 300"),
            ({"ZEUS_API_SHUTDOWN_DRAIN_SECONDS": "-0.1"}, "between 0 and 300"),
            ({"ZEUS_API_SHUTDOWN_DRAIN_SECONDS": "301"}, "between 0 and 300"),
            ({"ZEUS_API_SHUTDOWN_DRAIN_SECONDS": "nan"}, "between 0 and 300"),
        )
        for env, message in invalid_values:
            with self.subTest(env=env), self.assertRaisesRegex(ValueError, message):
                Settings.from_env(env)

    def test_http_server_rejects_requests_above_concurrency_limit(self) -> None:
        first_entered = threading.Event()
        release_first = threading.Event()
        call_lock = threading.Lock()
        call_count = 0

        class LimitedHandler(BaseHTTPRequestHandler):
            api_max_concurrent_requests = 1
            api_request_timeout_seconds = 2.0

            def do_GET(self) -> None:
                nonlocal call_count
                with call_lock:
                    call_count += 1
                    current_call = call_count
                if current_call == 1:
                    first_entered.set()
                    release_first.wait(timeout=3)
                data = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = api_module.ThreadingHTTPServer(("127.0.0.1", 0), LimitedHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        first_result: list[tuple[int, dict[str, Any]]] = []
        first_thread = threading.Thread(
            target=lambda: first_result.append(request_json(server.server_port, "GET", "/health"))
        )
        server_thread.start()
        first_thread.start()
        try:
            self.assertTrue(first_entered.wait(timeout=2))
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                conn.request("GET", "/health")
                response = conn.getresponse()
                raw_body = response.read()
            finally:
                conn.close()

            self.assertEqual(503, response.status)
            self.assertEqual("1", response.getheader("retry-after"))
            self.assertRegex(
                response.getheader("x-request-id") or "",
                r"^[0-9a-f]{32}$",
            )
            body = json.loads(raw_body.decode("utf-8"))
            self.assertEqual("server_busy", body["error"]["code"])
        finally:
            release_first.set()
            first_thread.join(timeout=3)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

        self.assertFalse(first_thread.is_alive())
        self.assertEqual(200, first_result[0][0])

    def test_http_server_drains_active_requests_and_rejects_new_work(self) -> None:
        first_entered = threading.Event()
        release_first = threading.Event()

        class DrainHandler(BaseHTTPRequestHandler):
            api_max_concurrent_requests = 2
            api_request_timeout_seconds = 2.0

            def do_GET(self) -> None:
                first_entered.set()
                release_first.wait(timeout=3)
                data = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = api_module.ThreadingHTTPServer(("127.0.0.1", 0), DrainHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        first_result: list[tuple[int, dict[str, Any]]] = []
        first_thread = threading.Thread(
            target=lambda: first_result.append(request_json(server.server_port, "GET", "/health"))
        )
        server_thread.start()
        first_thread.start()
        try:
            self.assertTrue(first_entered.wait(timeout=2))
            request_graceful_shutdown = getattr(server, "request_graceful_shutdown", None)
            wait_until_draining = getattr(server, "wait_until_draining", None)
            wait_for_drain = getattr(server, "wait_for_drain", None)
            self.assertTrue(callable(request_graceful_shutdown))
            self.assertTrue(callable(wait_until_draining))
            self.assertTrue(callable(wait_for_drain))
            request_graceful_shutdown(1.0)
            self.assertTrue(wait_until_draining(1.0))

            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                conn.request("GET", "/health")
                response = conn.getresponse()
                raw_body = response.read()
            finally:
                conn.close()

            self.assertEqual(503, response.status)
            self.assertEqual("1", response.getheader("retry-after"))
            self.assertRegex(
                response.getheader("x-request-id") or "",
                r"^[0-9a-f]{32}$",
            )
            body = json.loads(raw_body.decode("utf-8"))
            self.assertEqual("server_draining", body["error"]["code"])
            self.assertFalse(wait_for_drain(0.05))

            release_first.set()
            first_thread.join(timeout=3)
            self.assertTrue(wait_for_drain(1.0))
            server_thread.join(timeout=3)
        finally:
            release_first.set()
            first_thread.join(timeout=3)
            if server_thread.is_alive():
                server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

        self.assertFalse(first_thread.is_alive())
        self.assertFalse(server_thread.is_alive())
        self.assertEqual(200, first_result[0][0])

    def test_http_server_times_out_incomplete_requests_and_releases_capacity(self) -> None:
        accepted = threading.Event()

        class TimeoutHandler(BaseHTTPRequestHandler):
            api_max_concurrent_requests = 1
            api_request_timeout_seconds = 0.1

            def do_GET(self) -> None:
                data = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        class TrackingServer(api_module.ThreadingHTTPServer):
            def process_request(self, request: Any, client_address: Any) -> None:
                accepted.set()
                super().process_request(request, client_address)

        server = TrackingServer(("127.0.0.1", 0), TimeoutHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        slow_client = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
        try:
            slow_client.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            self.assertTrue(accepted.wait(timeout=2))
            slow_client.settimeout(1)
            try:
                closed_data = slow_client.recv(1)
            except TimeoutError:
                self.fail("incomplete API request was not closed after the configured timeout")
            self.assertEqual(b"", closed_data)

            status, body = request_json(server.server_port, "GET", "/health")
            self.assertEqual(200, status)
            self.assertEqual({"status": "ok"}, body)
        finally:
            slow_client.close()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

    def test_health_is_public_but_missing_api_key_rejects_bots_list(self) -> None:
        with api_server() as port:
            status, body = request_json(port, "GET", "/health")
            self.assertEqual(200, status)
            self.assertEqual({"status": "ok"}, body)

            status, body = request_json(port, "GET", "/bots")
            self.assertEqual(503, status)
            self.assertEqual("missing_api_key", body["error"]["code"])

    def test_start_wait_query_parameter_is_forwarded(self) -> None:
        calls: list[tuple[str, bool, float | None]] = []

        class QuerySupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def start(
                self,
                bot_id: str,
                *,
                wait: bool = False,
                timeout_seconds: float | None = None,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                self.assert_api_context(source, request_id)
                calls.append((bot_id, wait, timeout_seconds))
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.starting,
                    pid=1234,
                    profile_path="/tmp/profile",
                    message="started; readiness probe pending",
                )

            @staticmethod
            def assert_api_context(source: str, request_id: str | None) -> None:
                if source != "api" or request_id is None or len(request_id) != 32:
                    raise AssertionError("missing generated API lifecycle context")

        with (
            patch("zeus.api.Supervisor", QuerySupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            status, body = request_json(
                port,
                "POST",
                "/bots/coder/start?wait=1&timeout=2.5",
                headers={"x-zeus-api-key": "secret"},
            )

        self.assertEqual(200, status)
        self.assertEqual("starting", body["status"])
        self.assertEqual([("coder", True, 2.5)], calls)

    def test_stop_kill_after_timeout_query_parameter_is_forwarded(self) -> None:
        calls: list[tuple[str, bool | None]] = []

        class QuerySupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def stop(
                self,
                bot_id: str,
                *,
                kill_after_timeout: bool | None = None,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                if source != "api" or request_id is None or len(request_id) != 32:
                    raise AssertionError("missing generated API lifecycle context")
                calls.append((bot_id, kill_after_timeout))
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.stopped,
                    pid=None,
                    profile_path="/tmp/profile",
                )

        with (
            patch("zeus.api.Supervisor", QuerySupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            status, body = request_json(
                port,
                "POST",
                "/bots/coder/stop?kill_after_timeout=1",
                headers={"x-zeus-api-key": "secret"},
            )

        self.assertEqual(200, status)
        self.assertEqual("stopped", body["status"])
        self.assertEqual([("coder", True)], calls)

    def test_lock_timeout_returns_409(self) -> None:
        class LockedSupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def status(
                self,
                bot_id: str,
                *,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                raise LockTimeoutError(Path("/tmp/coder.lock"), 0.1)

        with (
            patch("zeus.api.Supervisor", LockedSupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            status, body = request_json(
                port,
                "GET",
                "/bots/coder/status",
                headers={"x-zeus-api-key": "secret"},
            )

        self.assertEqual(409, status)
        self.assertEqual("bot_locked", body["error"]["code"])

    def test_v1_prefix_routes_health_and_bots(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(port, "GET", "/v1/health")
            self.assertEqual(200, status)
            self.assertEqual({"status": "ok"}, body)

            status, body = request_json(
                port,
                "POST",
                "/v1/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)
            self.assertEqual("coder", body["bot_id"])

            status, body = request_json(port, "GET", "/v1/bots")
            self.assertEqual(200, status)
            self.assertEqual("coder", body[0]["bot_id"])

    def test_v1_alias_normalizes_roots_and_forwards_lifecycle_queries(self) -> None:
        calls: list[tuple[object, ...]] = []

        class CapturingSupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def start(
                self,
                bot_id: str,
                *,
                wait: bool = False,
                timeout_seconds: float | None = None,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                calls.append(("start", bot_id, wait, timeout_seconds, source, request_id))
                return BotStatusResponse(bot_id, BotStatus.starting, 123, "/profiles/coder")

            def stop(
                self,
                bot_id: str,
                *,
                kill_after_timeout: bool | None = None,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                calls.append(("stop", bot_id, kill_after_timeout, source, request_id))
                return BotStatusResponse(bot_id, BotStatus.stopped, None, "/profiles/coder")

            def restart(
                self,
                bot_id: str,
                *,
                wait: bool = False,
                timeout_seconds: float | None = None,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                calls.append(("restart", bot_id, wait, timeout_seconds, source, request_id))
                return BotStatusResponse(bot_id, BotStatus.running, 456, "/profiles/coder")

            def reconcile_summary(
                self,
                bot_id: str | None = None,
                *,
                source: str = "cli",
                request_id: str | None = None,
                **kwargs: object,
            ) -> object:
                calls.append(("reconcile_summary", bot_id, source, request_id))

                class Summary:
                    def to_dict(self) -> dict[str, object]:
                        return {"ok": True, "scope": "bot"}

                return Summary()

        headers = {"x-zeus-api-key": "secret"}
        with (
            patch("zeus.api.Supervisor", CapturingSupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            for root in ("/v1", "/v1/"):
                with self.subTest(root=root):
                    status, body = request_json(port, "GET", root, headers=headers)
                    self.assertEqual(404, status)
                    self.assertEqual(
                        {
                            "error": {
                                "code": "invalid_request",
                                "message": "not found",
                                "status": 404,
                            }
                        },
                        body,
                    )

            requests = (
                (
                    "/v1/bots/coder/start?wait=1&timeout=2.5",
                    {
                        "bot_id": "coder",
                        "message": "",
                        "pid": 123,
                        "profile_path": "/profiles/coder",
                        "status": "starting",
                    },
                    ("start", "coder", True, 2.5, "api"),
                ),
                (
                    "/v1/bots/coder/stop?kill_after_timeout=1",
                    {
                        "bot_id": "coder",
                        "message": "",
                        "pid": None,
                        "profile_path": "/profiles/coder",
                        "status": "stopped",
                    },
                    ("stop", "coder", True, "api"),
                ),
                (
                    "/v1/bots/coder/restart?wait=0&timeout=3.5",
                    {
                        "bot_id": "coder",
                        "message": "",
                        "pid": 456,
                        "profile_path": "/profiles/coder",
                        "status": "running",
                    },
                    ("restart", "coder", False, 3.5, "api"),
                ),
                (
                    "/v1/bots/coder/reconcile?summary=1",
                    {"ok": True, "scope": "bot"},
                    ("reconcile_summary", "coder", "api"),
                ),
            )
            for path, expected_body, expected_call in requests:
                with self.subTest(path=path):
                    status, body = request_json(port, "POST", path, headers=headers)
                    self.assertEqual(200, status)
                    self.assertEqual(expected_body, body)
                    call = calls.pop(0)
                    self.assertEqual(expected_call, call[:-1])
                    self.assertRegex(str(call[-1]), r"^[0-9a-f]{32}$")

        self.assertEqual([], calls)

    def test_bot_create_and_list_expose_desired_state_and_convergence(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, created = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)
            self.assertEqual("stopped", created["desired_state"])
            self.assertIs(True, created["converged"])

            status, bots = request_json(
                port,
                "GET",
                "/bots",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(200, status)
            self.assertEqual("stopped", bots[0]["desired_state"])
            self.assertIs(True, bots[0]["converged"])

    def test_create_existing_bot_requires_replace_query(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            body = json_request_body({"bot_id": "coder", "template_id": "coding-bot"})
            status, created = request_json(
                port,
                "POST",
                "/bots",
                body=body,
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)
            self.assertEqual("coder", created["bot_id"])

            status, conflict = request_json(
                port,
                "POST",
                "/bots",
                body=body,
                headers=auth_json_headers(),
            )
            self.assertEqual(409, status)
            self.assertEqual("bot_exists", conflict["error"]["code"])

            status, replaced = request_json(
                port,
                "POST",
                "/bots?replace=1",
                body=body,
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)
            self.assertEqual("coder", replaced["bot_id"])

    def test_v1_sensitive_diagnostics_still_require_key(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)

            status, body = request_json(port, "GET", "/v1/bots/coder/logs")
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

            status, body = request_json(
                port,
                "GET",
                "/v1/bots/coder/logs",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(200, status)
            self.assertEqual("coder", body["bot_id"])

    def test_v1_missing_explicit_reconcile_still_returns_unknown_bot(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/v1/bots/missing/reconcile",
                headers={"x-zeus-api-key": "secret"},
            )

            self.assertEqual(404, status)
            self.assertEqual("unknown_bot", body["error"]["code"])

    def test_reconcile_summary_returns_canonical_fleet_and_bot_run_payloads(self) -> None:
        with api_server_with_state({"ZEUS_API_KEY": "secret"}) as (port, state_dir):
            create_status, _created = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, create_status)

            fleet_status, fleet = request_json(
                port,
                "POST",
                "/bots/reconcile?summary=1",
                headers={"x-zeus-api-key": "secret"},
            )
            bot_status, bot = request_json(
                port,
                "POST",
                "/bots/coder/reconcile?summary=1",
                headers={"x-zeus-api-key": "secret"},
            )

            self.assertEqual(200, fleet_status)
            self.assertEqual(200, bot_status)
            self.assertEqual("fleet", fleet["scope"])
            self.assertEqual("bot", bot["scope"])
            for payload in (fleet, bot):
                self.assertEqual(
                    {
                        "run_id",
                        "scope",
                        "started_at",
                        "finished_at",
                        "outcome",
                        "ok",
                        "counts",
                        "total",
                        "results",
                    },
                    set(payload),
                )
                self.assertEqual("succeeded", payload["outcome"])
                self.assertTrue(payload["ok"])
                self.assertEqual(1, payload["total"])
                self.assertEqual("coder", payload["results"][0]["bot_id"])
                self.assertEqual(1, sum(payload["counts"].values()))
                self.assertEqual(
                    {
                        "bot_id",
                        "outcome",
                        "desired_state",
                        "observed_status",
                        "pid",
                        "action",
                        "message",
                        "error_code",
                        "event_id",
                        "started_at",
                        "finished_at",
                    },
                    set(payload["results"][0]),
                )
            with sqlite3.connect(state_dir / "zeus.db") as conn:
                self.assertEqual(
                    2,
                    conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                )

            legacy_status, legacy = request_json(
                port,
                "POST",
                "/bots/reconcile",
                headers={"x-zeus-api-key": "secret"},
            )

            self.assertEqual(200, legacy_status)
            self.assertIsInstance(legacy, list)
            self.assertEqual("coder", legacy[0]["bot_id"])
            v1_status, v1_summary = request_json(
                port,
                "POST",
                "/v1/bots/reconcile?summary=1",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(200, v1_status)
            self.assertEqual("fleet", v1_summary["scope"])

    def test_reconcile_summary_query_is_strict_and_missing_bot_remains_404(self) -> None:
        with api_server_with_state({"ZEUS_API_KEY": "secret"}) as (port, state_dir):
            headers = {"x-zeus-api-key": "secret"}
            for path in (
                "/bots/reconcile?summary=",
                "/bots/reconcile?summary=0",
                "/bots/reconcile?summary=true",
                "/bots/reconcile?summary=2",
                "/bots/coder/reconcile?summary=false",
                "/v1/bots/reconcile?summary=true",
            ):
                with self.subTest(path=path):
                    status, body = request_json(port, "POST", path, headers=headers)
                    self.assertEqual(400, status)
                    self.assertEqual("invalid_request", body["error"]["code"])
                    self.assertEqual("summary must be 1", body["error"]["message"])

            status, body = request_json(
                port,
                "POST",
                "/bots/reconcile?summary=1&summary=1",
                headers=headers,
            )
            self.assertEqual(400, status)
            self.assertEqual(
                "query parameter summary must be specified once",
                body["error"]["message"],
            )

            status, body = request_json(
                port,
                "POST",
                "/bots/missing/reconcile?summary=1",
                headers=headers,
            )
            self.assertEqual(404, status)
            self.assertEqual("unknown_bot", body["error"]["code"])
            with sqlite3.connect(state_dir / "zeus.db") as conn:
                self.assertEqual(
                    0,
                    conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                )

    def test_summary_lock_conflict_has_specific_code_and_legacy_code_is_unchanged(
        self,
    ) -> None:
        summary_calls = 0

        class LockedReconcileSupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def reconcile_summary(self, *args: object, **kwargs: object) -> ReconcileRunSummary:
                nonlocal summary_calls
                summary_calls += 1
                raise ReconcileLockTimeoutError(Path("/tmp/reconcile.lock"), 0.1)

            def reconcile(self, *args: object, **kwargs: object) -> list[BotStatusResponse]:
                raise LockTimeoutError(Path("/tmp/reconcile.lock"), 0.1)

        with (
            patch("zeus.api.Supervisor", LockedReconcileSupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            summary_status, summary_body = request_json(
                port,
                "POST",
                "/bots/reconcile?summary=1",
                headers={"x-zeus-api-key": "secret"},
            )
            legacy_status, legacy_body = request_json(
                port,
                "POST",
                "/bots/reconcile",
                headers={"x-zeus-api-key": "secret"},
            )
            keyed_headers = {
                "x-zeus-api-key": "secret",
                "idempotency-key": "locked-summary",
            }
            keyed_status, _keyed_headers, keyed_body = request_json_with_headers(
                port,
                "POST",
                "/bots/reconcile?summary=1",
                headers=keyed_headers,
            )
            replay_status, replay_headers, replay_body = request_json_with_headers(
                port,
                "POST",
                "/bots/reconcile?summary=1",
                headers=keyed_headers,
            )

        self.assertEqual(409, summary_status)
        self.assertEqual("reconcile_locked", summary_body["error"]["code"])
        self.assertEqual(409, legacy_status)
        self.assertEqual("bot_locked", legacy_body["error"]["code"])
        self.assertEqual(409, keyed_status)
        self.assertEqual(409, replay_status)
        self.assertEqual(keyed_body, replay_body)
        self.assertEqual("reconcile_locked", keyed_body["error"]["code"])
        self.assertEqual("true", replay_headers["idempotency-replayed"])
        self.assertEqual(2, summary_calls)

    def test_completed_with_errors_summary_is_http_200(self) -> None:
        started_at = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)
        counts = {outcome.value: 0 for outcome in ReconcileOutcome}
        counts[ReconcileOutcome.error.value] = 1
        result = BotReconcileResult(
            bot_id="coder",
            outcome=ReconcileOutcome.error,
            desired_state="running",
            observed_status="failed",
            pid=None,
            action="reconcile",
            message="bot reconciliation failed",
            error_code="reconcile_error",
            event_id=None,
            started_at=started_at,
            finished_at=started_at,
        )
        summary = ReconcileRunSummary(
            run_id="run-error",
            scope="bot",
            started_at=started_at,
            finished_at=started_at,
            outcome="completed_with_errors",
            total=1,
            counts=counts,
            results=(result,),
        )

        class ErrorSummarySupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def reconcile_summary(self, *args: object, **kwargs: object) -> ReconcileRunSummary:
                return summary

        with (
            patch("zeus.api.Supervisor", ErrorSummarySupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            status, body = request_json(
                port,
                "POST",
                "/bots/coder/reconcile?summary=1",
                headers={"x-zeus-api-key": "secret"},
            )

        self.assertEqual(200, status)
        self.assertEqual("completed_with_errors", body["outcome"])
        self.assertFalse(body["ok"])
        self.assertEqual(1, body["counts"]["error"])

    def test_reconcile_summary_idempotency_replays_one_persisted_run(self) -> None:
        with api_server_with_state({"ZEUS_API_KEY": "secret"}) as (port, state_dir):
            create_status, _created = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, create_status)
            headers = {
                "x-zeus-api-key": "secret",
                "idempotency-key": "summary-coder",
            }
            original_claim = StateStore.claim_idempotency
            registry_grew = False

            def claim_after_registry_growth(
                current_store: StateStore,
                **kwargs: object,
            ):
                nonlocal registry_grew
                if not registry_grew:
                    registry_grew = True
                    current_store.upsert_bot(
                        BotRecord(
                            bot_id="new-bot",
                            template_id="coding-bot",
                            display_name="New Bot",
                            profile_path=str(state_dir / "profiles" / "new-bot"),
                        )
                    )
                return original_claim(current_store, **kwargs)  # type: ignore[arg-type]

            with patch.object(StateStore, "claim_idempotency", claim_after_registry_growth):
                first_status, first_headers, first = request_json_with_headers(
                    port,
                    "POST",
                    "/bots/reconcile?summary=1",
                    headers=headers,
                )
            with patch.object(
                api_module,
                "_fleet_reconcile_response_ceiling",
                side_effect=AssertionError("replay must not rerun preclaim"),
            ):
                replay_status, replay_headers, replay = request_json_with_headers(
                    port,
                    "POST",
                    "/bots/reconcile?summary=1",
                    headers=headers,
                )

            self.assertEqual(200, first_status)
            self.assertEqual(200, replay_status)
            self.assertEqual(first, replay)
            self.assertEqual(["coder"], [item["bot_id"] for item in first["results"]])
            self.assertNotIn("idempotency-replayed", first_headers)
            self.assertEqual("true", replay_headers["idempotency-replayed"])
            with sqlite3.connect(state_dir / "zeus.db") as conn:
                self.assertEqual(
                    1,
                    conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                )

    def test_summary_response_ceiling_is_bounded_and_stops_after_cap(self) -> None:
        consumed = 0

        def snapshot():
            nonlocal consumed
            for index in range(10_000):
                consumed += 1
                yield f"bot-{index}", f"/profiles/bot-{index}"

        with patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", 128):
            ceiling = api_module._fleet_reconcile_response_ceiling(
                snapshot(),
                summary=True,
            )

        self.assertGreater(ceiling, 128)
        self.assertLess(consumed, 10_000)

    def test_summary_ceiling_bounds_adversarial_escaped_unicode_and_controls(self) -> None:
        summary = adversarial_reconcile_summary()
        payload = summary.to_dict()
        bounded, oversized = api_module._bound_idempotent_messages(payload)
        actual_size = len(json.dumps(bounded, sort_keys=True, allow_nan=False).encode("utf-8"))

        ceiling = api_module._fleet_reconcile_response_ceiling(
            (("coder", "/profiles/coder"),),
            summary=True,
        )

        self.assertFalse(oversized)
        self.assertGreaterEqual(ceiling, actual_size)

        bot_count = 12
        multi_payload = dict(payload)
        multi_payload["total"] = bot_count
        multi_payload["counts"] = {
            **payload["counts"],
            ReconcileOutcome.error.value: bot_count,
        }
        multi_payload["results"] = [
            {**payload["results"][0], "bot_id": f"bot-{index}"} for index in range(bot_count)
        ]
        bounded_multi, oversized_multi = api_module._bound_idempotent_messages(multi_payload)
        actual_multi_size = len(
            json.dumps(bounded_multi, sort_keys=True, allow_nan=False).encode("utf-8")
        )
        multi_ceiling = api_module._fleet_reconcile_response_ceiling(
            tuple((f"bot-{index}", f"/profiles/bot-{index}") for index in range(bot_count)),
            summary=True,
        )

        self.assertFalse(oversized_multi)
        self.assertGreaterEqual(multi_ceiling, actual_multi_size)

    def test_adversarial_summary_preclaim_rejects_before_claim_run_or_effect(self) -> None:
        summary = adversarial_reconcile_summary()
        effects = 0

        class AdversarialSummarySupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def reconcile_summary(self, *args: object, **kwargs: object) -> ReconcileRunSummary:
                nonlocal effects
                effects += 1
                return summary

        snapshot = (("coder", "/profiles/coder"),)
        ceiling = api_module._fleet_reconcile_response_ceiling(snapshot, summary=True)
        with (
            patch("zeus.api.Supervisor", AdversarialSummarySupervisor),
            api_server_with_state({"ZEUS_API_KEY": "secret"}) as (port, state_dir),
        ):
            StateStore(state_dir / "zeus.db").upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path="/profiles/coder",
                )
            )
            with patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", ceiling):
                accepted_status, accepted = request_json(
                    port,
                    "POST",
                    "/bots/reconcile?summary=1",
                    headers={
                        "x-zeus-api-key": "secret",
                        "idempotency-key": "adversarial-accepted",
                    },
                )

            self.assertEqual(200, accepted_status)
            actual_size = len(json.dumps(accepted, sort_keys=True, allow_nan=False).encode("utf-8"))
            self.assertLessEqual(actual_size, ceiling)
            for index, budget in enumerate(dict.fromkeys((actual_size - 1, ceiling - 1))):
                with (
                    self.subTest(budget=budget),
                    patch.object(
                        api_module,
                        "MAX_IDEMPOTENCY_RESPONSE_BYTES",
                        budget,
                    ),
                ):
                    status, body = request_json(
                        port,
                        "POST",
                        "/bots/reconcile?summary=1",
                        headers={
                            "x-zeus-api-key": "secret",
                            "idempotency-key": f"adversarial-rejected-{index}",
                        },
                    )
                    self.assertEqual(422, status)
                    self.assertEqual(
                        "idempotency_response_too_large",
                        body["error"]["code"],
                    )

            self.assertEqual(1, effects)
            with sqlite3.connect(state_dir / "zeus.db") as conn:
                self.assertEqual(
                    (0, 1),
                    (
                        conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                        conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0],
                    ),
                )

    def test_keyed_summary_over_replay_budget_is_rejected_before_run(self) -> None:
        with api_server_with_state({"ZEUS_API_KEY": "secret"}) as (port, state_dir):
            create_status, _created = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, create_status)
            with patch.object(api_module, "MAX_IDEMPOTENCY_RESPONSE_BYTES", 128):
                status, body = request_json(
                    port,
                    "POST",
                    "/bots/reconcile?summary=1",
                    headers={
                        "x-zeus-api-key": "secret",
                        "idempotency-key": "summary-too-large",
                    },
                )

            self.assertEqual(422, status)
            self.assertEqual("idempotency_response_too_large", body["error"]["code"])
            with sqlite3.connect(state_dir / "zeus.db") as conn:
                self.assertEqual(
                    (0, 0),
                    (
                        conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                        conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0],
                    ),
                )

    def test_openapi_documents_reconcile_summary_mode_and_schema(self) -> None:
        document = json.loads(Path("docs/openapi.json").read_text(encoding="utf-8"))
        summary_schema = document["components"]["schemas"]["ReconcileRunSummary"]
        self.assertEqual(
            {
                "run_id",
                "scope",
                "started_at",
                "finished_at",
                "outcome",
                "ok",
                "counts",
                "total",
                "results",
            },
            set(summary_schema["required"]),
        )
        self.assertEqual(
            "#/components/schemas/ReconcileResult",
            summary_schema["properties"]["results"]["items"]["$ref"],
        )
        for path in ("/bots/reconcile", "/bots/{bot_id}/reconcile"):
            operation = document["paths"][path]["post"]
            summary_parameter = next(
                parameter for parameter in operation["parameters"] if parameter["name"] == "summary"
            )
            self.assertEqual("1", summary_parameter["schema"]["const"])
            response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
            self.assertIn(
                {"$ref": "#/components/schemas/ReconcileRunSummary"},
                response_schema["oneOf"],
            )
        error_codes = document["components"]["schemas"]["Error"]["properties"]["error"][
            "properties"
        ]["code"]["enum"]
        self.assertIn("reconcile_locked", error_codes)

    def test_reconcile_summary_idempotency_query_is_distinct_from_legacy(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            headers = {
                "x-zeus-api-key": "secret",
                "idempotency-key": "reconcile-format",
            }
            legacy_status, _legacy = request_json(
                port,
                "POST",
                "/bots/reconcile",
                headers=headers,
            )
            summary_status, summary = request_json(
                port,
                "POST",
                "/bots/reconcile?summary=1",
                headers=headers,
            )

        self.assertEqual(200, legacy_status)
        self.assertEqual(409, summary_status)
        self.assertEqual("idempotency_key_conflict", summary["error"]["code"])

    def test_status_requests_for_different_bots_are_not_globally_locked(self) -> None:
        slow_entered = threading.Event()
        release_slow = threading.Event()

        class ConcurrentStatusSupervisor:
            def __init__(self, *args: object, **kwargs: object) -> None:
                return

            def status(
                self,
                bot_id: str,
                *,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                if bot_id == "slow":
                    slow_entered.set()
                    release_slow.wait(timeout=5)
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.stopped,
                    pid=None,
                    profile_path="/tmp/profile",
                )

        with (
            patch("zeus.api.Supervisor", ConcurrentStatusSupervisor),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
        ):
            slow_response: list[tuple[int, dict[str, Any]]] = []

            def request_slow_status() -> None:
                slow_response.append(
                    request_json(
                        port,
                        "GET",
                        "/bots/slow/status",
                        headers={"x-zeus-api-key": "secret"},
                    )
                )

            thread = threading.Thread(target=request_slow_status)
            thread.start()
            self.assertTrue(slow_entered.wait(timeout=2))

            status, body = request_json(
                port,
                "GET",
                "/bots/fast/status",
                headers={"x-zeus-api-key": "secret"},
            )

            release_slow.set()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(200, status)
            self.assertEqual("fast", body["bot_id"])
            self.assertEqual(200, slow_response[0][0])

    def test_wrong_and_correct_api_keys_for_read_endpoint(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(port, "GET", "/bots", headers={"x-zeus-api-key": "wrong"})
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

            status, body = request_json(port, "GET", "/bots", headers={"x-zeus-api-key": "secret"})
            self.assertEqual(200, status)
            self.assertEqual([], body)

    def test_post_bots_without_key_is_rejected(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers={"content-type": "application/json"},
            )
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

    def test_allow_unauth_reads_does_not_allow_post(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(port, "GET", "/bots")
            self.assertEqual(200, status)
            self.assertEqual([], body)

            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers={"content-type": "application/json"},
            )
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

    def test_bot_inspect_requires_key_even_when_unauth_reads_are_allowed(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body(
                    {
                        "bot_id": "coder",
                        "template_id": "coding-bot",
                        "env": {"OPENROUTER_API_KEY": "env-secret"},
                    }
                ),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)

            status, body = request_json(port, "GET", "/bots/coder/inspect")

            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

    def test_bot_logs_requires_key_even_when_unauth_reads_are_allowed(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)

            status, body = request_json(port, "GET", "/bots/coder/logs")

            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

            status, body = request_json(
                port,
                "GET",
                "/bots/coder/logs",
                headers={"x-zeus-api-key": "secret"},
            )

            self.assertEqual(200, status)
            self.assertEqual("coder", body["bot_id"])

    def test_history_api_requires_strict_key_and_supports_v1_alias(self) -> None:
        with api_server({"ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(port, "GET", "/bots/coder/history")
            self.assertEqual(503, status)
            self.assertEqual("missing_api_key", body["error"]["code"])

        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            status, body = request_json(port, "GET", "/bots/coder/history")
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])
            status, body = request_json(port, "GET", "/bots/coder/history?debug=1")
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

            create_status, _ = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, create_status)
            status, body = request_json(
                port,
                "GET",
                "/v1/bots/coder/history?limit=1",
                headers={"x-zeus-api-key": "secret"},
            )

            self.assertEqual(200, status)
            self.assertEqual("coder", body["bot_id"])
            self.assertEqual(1, len(body["events"]))
            self.assertIsNone(body["next_before"])

    def test_history_api_validates_queries_and_unknown_bot(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            headers = {"x-zeus-api-key": "secret"}
            cases = (
                ("/bots/coder/history?debug=1", "unknown query parameter: debug"),
                (
                    "/bots/coder/history?limit=1&limit=2",
                    "query parameter limit must be specified once",
                ),
                ("/bots/coder/history?limit=no", "limit must be an integer"),
                ("/bots/coder/history?limit=0", "limit must be between 1 and 1000"),
                ("/bots/coder/history?limit=1001", "limit must be between 1 and 1000"),
                ("/bots/coder/history?before=0", "before must be positive"),
            )
            for path, message in cases:
                with self.subTest(path=path):
                    status, body = request_json(port, "GET", path, headers=headers)
                    self.assertEqual(400, status)
                    self.assertEqual("invalid_request", body["error"]["code"])
                    self.assertEqual(message, body["error"]["message"])

            status, body = request_json(port, "GET", "/bots/never-seen/history", headers=headers)
            self.assertEqual(404, status)
            self.assertEqual("unknown_bot", body["error"]["code"])

    def test_bot_inspect_returns_diagnostics_and_redacts_logs(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body(
                    {
                        "bot_id": "coder",
                        "template_id": "coding-bot",
                        "env": {"OPENROUTER_API_KEY": "env-secret"},
                    }
                ),
                headers=auth_json_headers(),
            )
            self.assertEqual(200, status)
            profile_path = Path(body["profile_path"])
            log_path = profile_path / "logs" / "zeus-gateway.log"
            log_path.write_text(
                "OPENAI_API_KEY=log-secret\nAuthorization: Bearer bearer-secret\n",
                encoding="utf-8",
            )

            status, body = request_json(
                port, "GET", "/bots/coder/inspect", headers={"x-zeus-api-key": "secret"}
            )

            self.assertEqual(200, status)
            self.assertEqual("coder", body["bot"]["bot_id"])
            self.assertTrue(body["profile_files"]["config.yaml"])
            self.assertTrue(body["profile_files"][".env"])
            self.assertEqual({"exists": False}, body["pid_marker"])
            self.assertFalse(body["live_cmdline_verified"])
            self.assertIn("[redacted]", body["recent_logs"])
            serialized = json.dumps(body)
            self.assertNotIn("env-secret", serialized)
            self.assertNotIn("log-secret", serialized)
            self.assertNotIn("bearer-secret", serialized)

            status, body = request_json(
                port, "GET", "/bots/missing/inspect", headers={"x-zeus-api-key": "secret"}
            )
            self.assertEqual(404, status)
            self.assertEqual("unknown_bot", body["error"]["code"])

    def test_rejects_malformed_json(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=b"{",
                headers=auth_json_headers(),
            )
            self.assertEqual(400, status)
            self.assertEqual("invalid_request", body["error"]["code"])

    def test_rejects_duplicate_json_object_keys(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=b'{"bot_id":"coder","bot_id":"other","template_id":"coding-bot"}',
                headers=auth_json_headers(),
            )

            self.assertEqual(400, status)
            self.assertEqual("invalid_request", body["error"]["code"])
            self.assertEqual("duplicate JSON field: bot_id", body["error"]["message"])

    def test_rejects_nonstandard_json_constants(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            for constant in ("NaN", "Infinity", "-Infinity"):
                with self.subTest(constant=constant):
                    status, body = request_json(
                        port,
                        "POST",
                        "/bots",
                        body=(
                            '{"bot_id":"coder","template_id":"coding-bot",'
                            f'"restart_backoff_seconds":{constant}}}'
                        ).encode(),
                        headers=auth_json_headers(),
                    )

                    self.assertEqual(400, status)
                    self.assertEqual("invalid_request", body["error"]["code"])
                    self.assertEqual(f"invalid JSON constant: {constant}", body["error"]["message"])

    def test_rejects_unknown_create_fields(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body(
                    {"bot_id": "coder", "template_id": "coding-bot", "temlate_id": "typo"}
                ),
                headers=auth_json_headers(),
            )

            self.assertEqual(400, status)
            self.assertEqual("unknown request field: temlate_id", body["error"]["message"])

    def test_rejects_duplicate_query_parameters(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots?replace=0&replace=1",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=auth_json_headers(),
            )

            self.assertEqual(400, status)
            self.assertEqual(
                "query parameter replace must be specified once", body["error"]["message"]
            )

    def test_rejects_unknown_query_parameters(self) -> None:
        with api_server() as port:
            status, body = request_json(port, "GET", "/health?debug=1")

            self.assertEqual(400, status)
            self.assertEqual("unknown query parameter: debug", body["error"]["message"])

    def test_limits_query_parameter_count(self) -> None:
        query = "&".join(f"field{index}=1" for index in range(17))
        with api_server() as port:
            status, body = request_json(port, "GET", f"/health?{query}")

            self.assertEqual(400, status)
            self.assertEqual("too many query parameters", body["error"]["message"])

    def test_rejects_request_target_fragments(self) -> None:
        with api_server() as port:
            status, body = request_json(port, "GET", "/health#internal")

            self.assertEqual(400, status)
            self.assertEqual("request target must not include a fragment", body["error"]["message"])

    def test_rejects_unexpected_lifecycle_request_bodies(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots/reconcile",
                body=b"{}",
                headers=auth_json_headers(),
            )

            self.assertEqual(400, status)
            self.assertEqual(
                "request body is not allowed for this endpoint", body["error"]["message"]
            )

    def test_rejects_encoded_json_request_bodies(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            headers = auth_json_headers()
            headers["content-encoding"] = "gzip"
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                headers=headers,
            )

            self.assertEqual(415, status)
            self.assertEqual("content-encoding is not supported", body["error"]["message"])

    def test_requires_content_length_for_json_request_bodies(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = raw_post_without_content_length(
                port,
                json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
            )

            self.assertEqual(400, status)
            self.assertEqual("content-length is required", body["error"]["message"])

    def test_limits_json_nesting_depth(self) -> None:
        nested = "[" * 65 + "0" + "]" * 65
        body = ('{"bot_id":"coder","template_id":"coding-bot","extra":' + nested + "}").encode()
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, response = request_json(
                port,
                "POST",
                "/bots",
                body=body,
                headers=auth_json_headers(),
            )

            self.assertEqual(400, status)
            self.assertEqual("request JSON nesting exceeds 64", response["error"]["message"])

    def test_options_returns_json_405_with_allow_header(self) -> None:
        with api_server() as port:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request("OPTIONS", "/health")
                response = conn.getresponse()
                raw_body = response.read()
            finally:
                conn.close()

            self.assertEqual(405, response.status)
            self.assertEqual("GET, POST", response.getheader("allow"))
            body = json.loads(raw_body.decode("utf-8"))
            self.assertEqual("method_not_allowed", body["error"]["code"])

    def test_rejects_json_array_body(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body([]),
                headers=auth_json_headers(),
            )
            self.assertEqual(400, status)
            self.assertEqual("request body must be a JSON object", body["error"]["message"])

    def test_rejects_body_over_one_megabyte(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = raw_post_with_content_length(port, "1000001")
            self.assertEqual(400, status)
            self.assertEqual("request body too large", body["error"]["message"])

    def test_rejects_non_integer_content_length(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = raw_post_with_content_length(port, "not-an-int")
            self.assertEqual(400, status)
            self.assertEqual("content-length must be an integer", body["error"]["message"])

    def test_rejects_negative_content_length(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = raw_post_with_content_length(port, "-1")
            self.assertEqual(400, status)
            self.assertEqual("content-length must be non-negative", body["error"]["message"])

    def test_rejects_unsupported_content_type(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=b"{}",
                headers={"content-type": "text/plain", "x-zeus-api-key": "secret"},
            )
            self.assertEqual(415, status)
            self.assertEqual("unsupported_media_type", body["error"]["code"])

    def test_rejects_missing_or_lookalike_json_content_type(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            for content_type in (None, "text/application/jsonp"):
                with self.subTest(content_type=content_type):
                    headers = {"x-zeus-api-key": "secret"}
                    if content_type is not None:
                        headers["content-type"] = content_type
                    status, body = request_json(
                        port,
                        "POST",
                        "/bots",
                        body=json_request_body({"bot_id": "coder", "template_id": "coding-bot"}),
                        headers=headers,
                    )

                    self.assertEqual(415, status)
                    self.assertEqual("unsupported_media_type", body["error"]["code"])

    def test_rejects_unsupported_method(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(port, "PUT", "/bots", headers={"x-zeus-api-key": "secret"})
            self.assertEqual(405, status)
            self.assertEqual("method_not_allowed", body["error"]["code"])

    def test_unknown_bot_is_not_found(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port, "GET", "/bots/missing/status", headers={"x-zeus-api-key": "secret"}
            )
            self.assertEqual(404, status)
            self.assertEqual("unknown_bot", body["error"]["code"])

    def test_unknown_template_is_bad_request(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body({"bot_id": "coder", "template_id": "missing-bot"}),
                headers=auth_json_headers(),
            )
            self.assertEqual(400, status)
            self.assertEqual("unknown_template", body["error"]["code"])

    def test_unknown_env_key_is_bad_request(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "POST",
                "/bots",
                body=json_request_body(
                    {
                        "bot_id": "coder",
                        "template_id": "coding-bot",
                        "env": {"CUSTOM_FLAG": "enabled"},
                    }
                ),
                headers=auth_json_headers(),
            )
            self.assertEqual(400, status)
            self.assertEqual("invalid_request", body["error"]["code"])
            self.assertEqual(
                "env contains unknown key(s) for template coding-bot: CUSTOM_FLAG",
                body["error"]["message"],
            )

    def test_serve_does_not_write_pid_when_bind_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(state_dir),
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "4311",
                }
            )

            with (
                patch("zeus.api.ThreadingHTTPServer", side_effect=OSError("bind failed")),
                self.assertRaisesRegex(OSError, "bind failed"),
            ):
                serve("127.0.0.1", 4311, settings)

            self.assertFalse((state_dir / "zeus.pid").exists())

    def test_serve_removes_owned_pid_after_orderly_exit(self) -> None:
        observed_modes: list[int] = []
        shutdown_events: list[str] = []

        class FakeServer:
            closed = False

            def __init__(self, _address: object, _handler: object) -> None:
                pass

            def serve_forever(self) -> None:
                observed_modes.append((state_dir / "zeus.pid").stat().st_mode & 0o777)
                return

            def begin_draining(self) -> None:
                shutdown_events.append("begin_draining")

            def server_close(self) -> None:
                self.closed = True
                shutdown_events.append("server_close")

            def wait_for_drain(self, timeout_seconds: float) -> bool:
                shutdown_events.append(f"wait_for_drain:{timeout_seconds:g}")
                return True

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(state_dir),
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "4311",
                }
            )
            fake_server = FakeServer(("127.0.0.1", 4311), object())

            with patch("zeus.api.ThreadingHTTPServer", return_value=fake_server):
                serve("127.0.0.1", 4311, settings)

            self.assertTrue(fake_server.closed)
            self.assertEqual([0o600], observed_modes)
            self.assertEqual(
                ["begin_draining", "server_close", "wait_for_drain:20"], shutdown_events
            )
            self.assertFalse((state_dir / "zeus.pid").exists())

    def test_serve_preserves_pid_marker_replaced_by_another_owner(self) -> None:
        class FakeServer:
            def __init__(self, _address: object, _handler: object) -> None:
                pass

            def serve_forever(self) -> None:
                (state_dir / "zeus.pid").write_text("999999\n", encoding="utf-8")

            def server_close(self) -> None:
                return

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})

            with patch("zeus.api.ThreadingHTTPServer", FakeServer):
                serve("127.0.0.1", 4311, settings)

            self.assertEqual("999999\n", (state_dir / "zeus.pid").read_text(encoding="utf-8"))

    def test_serve_rejects_unsafe_public_bind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            missing_key = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(state_dir),
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "4311",
                }
            )
            unauthenticated_reads = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(state_dir),
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "4311",
                    "ZEUS_API_KEY": "a-strong-api-key-value",
                    "ZEUS_ALLOW_UNAUTH_READS": "1",
                }
            )
            short_key = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(state_dir),
                    "ZEUS_API_KEY": "too-short",
                }
            )

            with self.assertRaisesRegex(ValueError, "requires ZEUS_API_KEY"):
                serve("0.0.0.0", 4311, missing_key)
            with self.assertRaisesRegex(ValueError, "ZEUS_ALLOW_UNAUTH_READS"):
                serve("0.0.0.0", 4311, unauthenticated_reads)
            with self.assertRaisesRegex(ValueError, "at least 16 characters"):
                serve("0.0.0.0", 4311, short_key)

    def test_serve_allows_authenticated_public_bind(self) -> None:
        class FakeServer:
            def __init__(self, _address: object, _handler: object) -> None:
                pass

            def serve_forever(self) -> None:
                return

            def server_close(self) -> None:
                return

        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / "state"),
                    "ZEUS_API_KEY": "a-strong-api-key-value",
                }
            )

            with patch("zeus.api.ThreadingHTTPServer", FakeServer):
                serve("0.0.0.0", 4311, settings)

    def test_api_process_removes_pid_marker_on_sigterm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            pid_path = state_dir / "zeus.pid"
            active_request_path = Path(tmp) / "active-request"
            with socket.socket() as port_reservation:
                port_reservation.bind(("127.0.0.1", 0))
                port = int(port_reservation.getsockname()[1])
            env = {
                **os.environ,
                "ZEUS_STATE_DIR": str(state_dir),
                "ZEUS_API_KEY": "local-test-key",
                "ZEUS_API_MAX_CONCURRENT_REQUESTS": "1",
                "ZEUS_API_REQUEST_TIMEOUT_SECONDS": "5",
                "ZEUS_API_SHUTDOWN_DRAIN_SECONDS": "2",
                "ZEUS_TEST_ACTIVE_REQUEST_SENTINEL": str(active_request_path),
            }
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "tests.fixtures.api_process_harness",
                    "--port",
                    str(port),
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            slow_client: socket.socket | None = None
            try:
                deadline = time.monotonic() + 5
                while process.poll() is None:
                    try:
                        if request_json(port, "GET", "/health") == (200, {"status": "ok"}):
                            break
                    except (ConnectionError, OSError):
                        pass
                    if time.monotonic() >= deadline:
                        self.fail("API process did not become ready")
                    time.sleep(0.05)
                if process.poll() is not None:
                    _stdout, stderr = process.communicate()
                    self.fail(f"API process exited before startup: {stderr}")
                self.assertTrue(pid_path.exists())

                deadline = time.monotonic() + 2
                while True:
                    try:
                        readiness_state = active_request_path.read_text(encoding="ascii")
                    except (FileNotFoundError, OSError, UnicodeError):
                        readiness_state = ""
                    if readiness_state == "idle\n":
                        break
                    if process.poll() is not None:
                        _stdout, stderr = process.communicate()
                        self.fail(f"API process exited before releasing readiness slot: {stderr}")
                    if time.monotonic() >= deadline:
                        self.fail("API process did not release the readiness request slot")
                    time.sleep(0.01)
                active_request_path.unlink(missing_ok=True)
                slow_client = socket.create_connection(("127.0.0.1", port), timeout=2)
                slow_source_port = int(slow_client.getsockname()[1])
                slow_client.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
                expected_active_request = f"{slow_source_port}\n"
                deadline = time.monotonic() + 2
                active_request = ""
                while True:
                    try:
                        active_request = active_request_path.read_text(encoding="ascii")
                    except (FileNotFoundError, OSError, UnicodeError):
                        active_request = ""
                    if active_request == expected_active_request:
                        break
                    if process.poll() is not None:
                        _stdout, stderr = process.communicate()
                        self.fail(f"API process exited before holding request slot: {stderr}")
                    if time.monotonic() >= deadline:
                        self.fail(
                            "slow API request did not occupy the configured request slot: "
                            f"expected {expected_active_request!r}, observed {active_request!r}"
                        )
                    time.sleep(0.01)

                process.terminate()
                deadline = time.monotonic() + 3
                while True:
                    if process.poll() is not None:
                        _stdout, stderr = process.communicate()
                        self.fail(f"API process exited before serving drain response: {stderr}")
                    try:
                        status, body = request_json(port, "GET", "/health")
                    except (ConnectionError, OSError):
                        status, body = 0, {}
                    if status == 503 and body.get("error", {}).get("code") == "server_draining":
                        break
                    if time.monotonic() >= deadline:
                        self.fail("API process did not enter its draining response state")
                    time.sleep(0.05)

                slow_client.close()
                slow_client = None
                self.assertEqual(0, process.wait(timeout=5))
                self.assertFalse(pid_path.exists())
            finally:
                if slow_client is not None:
                    slow_client.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                process.communicate()

    def test_second_api_process_cannot_overwrite_pid_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            pid_path = state_dir / "zeus.pid"
            env = {
                **os.environ,
                "ZEUS_STATE_DIR": str(state_dir),
                "ZEUS_API_KEY": "local-test-key",
            }
            command = [sys.executable, "-B", "-m", "zeus.api", "--port", "0"]
            first = subprocess.Popen(
                command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not pid_path.exists() and first.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("first API process did not publish its PID marker")
                    time.sleep(0.05)
                if first.poll() is not None:
                    _stdout, stderr = first.communicate()
                    self.fail(f"first API process exited before startup: {stderr}")
                first_pid = pid_path.read_text(encoding="utf-8")

                second = subprocess.run(
                    command,
                    env=env,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                self.assertNotEqual(0, second.returncode)
                self.assertIn("timed out waiting for lock", second.stderr)
                self.assertEqual(first_pid, pid_path.read_text(encoding="utf-8"))
            finally:
                if first.poll() is None:
                    first.terminate()
                    try:
                        first.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        first.kill()
                        first.wait(timeout=5)


class ApiRateLimitTests(unittest.TestCase):
    def test_rate_limit_settings_have_defaults_overrides_and_bounds(self) -> None:
        defaults = Settings.from_env({})
        configured = Settings.from_env(
            {
                "ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE": "6000",
                "ZEUS_API_AUTH_FAILURE_BURST": "1000",
                "ZEUS_API_MUTATION_RATE_PER_MINUTE": "1",
                "ZEUS_API_MUTATION_BURST": "1",
            }
        )

        self.assertEqual(30, getattr(defaults, "api_auth_failure_rate_per_minute", None))
        self.assertEqual(10, getattr(defaults, "api_auth_failure_burst", None))
        self.assertEqual(120, getattr(defaults, "api_mutation_rate_per_minute", None))
        self.assertEqual(30, getattr(defaults, "api_mutation_burst", None))
        self.assertEqual(6000, getattr(configured, "api_auth_failure_rate_per_minute", None))
        self.assertEqual(1000, getattr(configured, "api_auth_failure_burst", None))
        self.assertEqual(1, getattr(configured, "api_mutation_rate_per_minute", None))
        self.assertEqual(1, getattr(configured, "api_mutation_burst", None))

        for name in (
            "ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE",
        ):
            for value in ("0", "6001", "not-an-int"):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    Settings.from_env({name: value})
        for name in ("ZEUS_API_AUTH_FAILURE_BURST", "ZEUS_API_MUTATION_BURST"):
            for value in ("0", "1001", "not-an-int"):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    Settings.from_env({name: value})

    def test_valid_key_bypasses_exhausted_global_invalid_auth_bucket(self) -> None:
        env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE": "1",
            "ZEUS_API_AUTH_FAILURE_BURST": "2",
        }
        with api_server_with_state(env) as (port, state_dir):
            for path, forwarded_for in (
                ("/bots", "198.51.100.1"),
                ("/v1/bots", "198.51.100.2"),
            ):
                status, body = request_json(
                    port,
                    "GET",
                    path,
                    headers={
                        "x-zeus-api-key": "wrong",
                        "x-forwarded-for": forwarded_for,
                    },
                )
                self.assertEqual(401, status)
                self.assertEqual("invalid_api_key", body["error"]["code"])

            status, response_headers, body = request_json_with_headers(
                port,
                "GET",
                "/bots",
                headers={
                    "x-zeus-api-key": "wrong",
                    "x-forwarded-for": "198.51.100.3",
                },
            )
            self.assertEqual(429, status)
            self.assertIsInstance(body, dict)
            self.assertEqual("auth_rate_limited", body["error"]["code"])
            self.assertGreaterEqual(int(response_headers["retry-after"]), 1)
            self.assertRegex(response_headers["x-request-id"], r"^[0-9a-f]{32}$")

            valid_status, valid_body = request_json(
                port,
                "GET",
                "/bots",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(200, valid_status)
            self.assertEqual([], valid_body)

            rows = wait_for_access_rows(state_dir, 4)

        limited_row = rows[2]
        self.assertEqual(response_headers["x-request-id"], limited_row["request_id"])
        self.assertEqual(429, limited_row["status"])
        self.assertEqual("auth_rate_limited", limited_row["error_code"])
        self.assertEqual("/bots", limited_row["route"])
        self.assertEqual("rejected", limited_row["auth_outcome"])
        serialized = json.dumps(rows)
        self.assertNotIn("198.51.100", serialized)
        self.assertNotIn("x-forwarded-for", serialized)
        self.assertNotIn("client", serialized)

    def test_missing_server_key_remains_unconfigured_without_rate_limiting(self) -> None:
        env = {
            "ZEUS_API_KEY": "",
            "ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE": "1",
            "ZEUS_API_AUTH_FAILURE_BURST": "1",
        }
        with api_server(env) as port:
            for _attempt in range(3):
                status, response_headers, body = request_json_with_headers(port, "GET", "/bots")
                self.assertEqual(503, status)
                self.assertIsInstance(body, dict)
                self.assertEqual("missing_api_key", body["error"]["code"])
                self.assertNotIn("retry-after", response_headers)

    def test_non_mutating_and_unknown_routes_do_not_consume_mutation_capacity(self) -> None:
        env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "1",
            "ZEUS_API_MUTATION_BURST": "1",
        }
        with api_server(env) as port:
            self.assertEqual(200, request_json(port, "GET", "/health")[0])
            self.assertEqual(
                200,
                request_json(
                    port,
                    "GET",
                    "/bots",
                    headers={"x-zeus-api-key": "secret"},
                )[0],
            )
            self.assertEqual(
                405,
                request_json(
                    port,
                    "PUT",
                    "/bots",
                    headers={"x-zeus-api-key": "secret"},
                )[0],
            )
            self.assertEqual(
                404,
                request_json(
                    port,
                    "POST",
                    "/not-a-route",
                    headers={"x-zeus-api-key": "secret"},
                )[0],
            )

            first_status, first_body = request_json(
                port,
                "POST",
                "/bots/coder/start",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(404, first_status)
            self.assertEqual("unknown_bot", first_body["error"]["code"])

            status, response_headers, body = request_json_with_headers(
                port,
                "POST",
                "/v1/bots/coder/start",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(429, status)
            self.assertIsInstance(body, dict)
            self.assertEqual("mutation_rate_limited", body["error"]["code"])
            self.assertGreaterEqual(int(response_headers["retry-after"]), 1)

    def test_malformed_and_conflicting_mutations_consume_capacity(self) -> None:
        malformed_env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "1",
            "ZEUS_API_MUTATION_BURST": "1",
        }
        with api_server(malformed_env) as port:
            malformed_status, _ = request_json(
                port,
                "POST",
                "/bots",
                body=b"{",
                headers=auth_json_headers(),
            )
            self.assertEqual(400, malformed_status)
            limited_status, limited_body = request_json(
                port,
                "POST",
                "/bots",
                body=b"{",
                headers=auth_json_headers(),
            )
            self.assertEqual(429, limited_status)
            self.assertEqual("mutation_rate_limited", limited_body["error"]["code"])

        conflict_env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "1",
            "ZEUS_API_MUTATION_BURST": "2",
        }
        create_body = json_request_body({"bot_id": "coder", "template_id": "coding-bot"})
        with api_server(conflict_env) as port:
            first_status, _ = request_json(
                port, "POST", "/bots", body=create_body, headers=auth_json_headers()
            )
            conflict_status, _ = request_json(
                port, "POST", "/bots", body=create_body, headers=auth_json_headers()
            )
            limited_status, limited_body = request_json(
                port, "POST", "/bots", body=b"{", headers=auth_json_headers()
            )
            self.assertEqual(200, first_status)
            self.assertEqual(409, conflict_status)
            self.assertEqual(429, limited_status)
            self.assertEqual("mutation_rate_limited", limited_body["error"]["code"])

    def test_idempotency_replays_consume_mutation_capacity(self) -> None:
        env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "1",
            "ZEUS_API_MUTATION_BURST": "2",
        }
        body = json_request_body({"bot_id": "coder", "template_id": "coding-bot"})
        headers = {**auth_json_headers(), "idempotency-key": "create-coder"}
        with api_server(env) as port:
            first_status, _, _ = request_json_with_headers(
                port, "POST", "/bots", body=body, headers=headers
            )
            replay_status, replay_headers, _ = request_json_with_headers(
                port, "POST", "/bots", body=body, headers=headers
            )
            limited_status, limited_body = request_json(
                port, "POST", "/bots", body=b"{", headers=auth_json_headers()
            )

            self.assertEqual(200, first_status)
            self.assertEqual(200, replay_status)
            self.assertEqual("true", replay_headers.get("idempotency-replayed"))
            self.assertEqual(429, limited_status)
            self.assertEqual("mutation_rate_limited", limited_body["error"]["code"])

    def test_rate_limited_mutation_creates_no_idempotency_claim_and_is_correlated(self) -> None:
        env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "1",
            "ZEUS_API_MUTATION_BURST": "1",
        }
        with api_server_with_state(env) as (port, state_dir):
            first_status, _ = request_json(
                port,
                "POST",
                "/bots/coder/start",
                headers={"x-zeus-api-key": "secret"},
            )
            self.assertEqual(404, first_status)

            status, response_headers, body = request_json_with_headers(
                port,
                "POST",
                "/bots/coder/start",
                headers={
                    "x-zeus-api-key": "secret",
                    "idempotency-key": "must-not-be-claimed",
                    "x-forwarded-for": "203.0.113.77",
                },
            )
            self.assertEqual(429, status)
            self.assertIsInstance(body, dict)
            self.assertEqual("mutation_rate_limited", body["error"]["code"])
            self.assertGreaterEqual(int(response_headers["retry-after"]), 1)
            self.assertRegex(response_headers["x-request-id"], r"^[0-9a-f]{32}$")

            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                claim_count = int(
                    connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
                )
            self.assertEqual(0, claim_count)
            rows = wait_for_access_rows(state_dir, 2)

        limited_row = rows[1]
        self.assertEqual(response_headers["x-request-id"], limited_row["request_id"])
        self.assertEqual(429, limited_row["status"])
        self.assertEqual("mutation_rate_limited", limited_row["error_code"])
        self.assertEqual("/bots/{bot_id}/start", limited_row["route"])
        self.assertEqual("authenticated", limited_row["auth_outcome"])
        self.assertEqual("not_applicable", limited_row["idempotency_outcome"])
        self.assertNotIn("203.0.113.77", json.dumps(rows))

    def test_mutation_capacity_refills_with_injected_clock(self) -> None:
        clock = ApiFakeClock()

        def bucket_factory(rate_per_minute: int, burst: int) -> TokenBucket:
            return TokenBucket(rate_per_minute, burst, clock=clock)

        env = {
            "ZEUS_API_KEY": "secret",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "60",
            "ZEUS_API_MUTATION_BURST": "1",
        }
        with (
            patch.object(api_module, "TokenBucket", side_effect=bucket_factory, create=True),
            api_server(env) as port,
        ):
            first_status, _ = request_json(
                port,
                "POST",
                "/bots/coder/start",
                headers={"x-zeus-api-key": "secret"},
            )
            limited_status, _ = request_json(
                port,
                "POST",
                "/bots/coder/start",
                headers={"x-zeus-api-key": "secret"},
            )
            clock.advance(1.0)
            refilled_status, _ = request_json(
                port,
                "POST",
                "/bots/coder/start",
                headers={"x-zeus-api-key": "secret"},
            )

        self.assertEqual(404, first_status)
        self.assertEqual(429, limited_status)
        self.assertEqual(404, refilled_status)


if __name__ == "__main__":
    unittest.main()
