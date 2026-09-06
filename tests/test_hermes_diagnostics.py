from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from collections.abc import Callable
from contextlib import AbstractContextManager
from types import TracebackType
from unittest.mock import patch

from zeus.hermes_diagnostics import MAX_HEALTH_RESPONSE_BYTES, probe_gateway_health

_KEY = "fake-test-gateway-key-0123456789"
_PID = 4321


def _payload() -> dict:
    return {
        "status": "ok",
        "platform": "hermes-agent",
        "version": "0.21.0",
        "pid": _PID,
        "gateway_state": "running",
        "active_agents": 2,
        "gateway_busy": True,
        "gateway_drainable": True,
        "readiness": {
            "status": "ok",
            "checks": {
                "state_db": {"status": "ok"},
                "session_store": {"status": "ok"},
                "config": {"status": "ok"},
                "model": {"status": "ok"},
                "disk": {"status": "ok", "used_percent": 25.5, "free_bytes": 1024},
                "gateway": {
                    "status": "ok",
                    "state": "running",
                    "connected_platforms": 1,
                    "platforms": 1,
                },
                "background_queues": {
                    "status": "ok",
                    "active_api_runs": 1,
                    "process_completions": 0,
                    "active_delegations": 2,
                },
            },
        },
    }


def _http(body: bytes, *, status: int = 200, headers: bytes | None = None) -> bytes:
    if headers is None:
        headers = f"Content-Length: {len(body)}\r\n".encode("ascii")
    return f"HTTP/1.1 {status} Test\r\n".encode("ascii") + headers + b"\r\n" + body


class _Server(AbstractContextManager["_Server"]):
    def __init__(
        self,
        response: bytes | Callable[[socket.socket, threading.Event], None],
        *,
        ipv6: bool = False,
    ) -> None:
        self.response = response
        self.stopped = threading.Event()
        self.requests: list[bytes] = []
        self.listener = socket.socket(
            socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM
        )
        self.listener.bind(("::1" if ipv6 else "127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.05)
        host = "[::1]" if ipv6 else "127.0.0.1"
        self.url = f"http://{host}:{self.listener.getsockname()[1]}/health"
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> _Server:
        self.thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stopped.set()
        self.listener.close()
        self.thread.join(1)
        if self.thread.is_alive():
            raise AssertionError("diagnostics test server did not stop")

    def _serve(self) -> None:
        while not self.stopped.is_set():
            try:
                connection, _address = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                try:
                    request = bytearray()
                    while b"\r\n\r\n" not in request and len(request) < 8192:
                        block = connection.recv(4096)
                        if not block:
                            return
                        request.extend(block)
                    self.requests.append(bytes(request))
                    if isinstance(self.response, bytes):
                        connection.sendall(self.response)
                    else:
                        self.response(connection, self.stopped)
                except OSError:
                    pass
            return


class HermesDiagnosticsTests(unittest.TestCase):
    def _probe_payload(self, payload: object) -> tuple[str, dict[str, object] | None]:
        with _Server(_http(json.dumps(payload).encode())) as server:
            return probe_gateway_health(server.url, _KEY, _PID)

    def test_projects_live_health_without_raw_or_unknown_fields(self) -> None:
        payload = _payload()
        payload.update(platforms={"secret": _KEY}, exit_reason=_KEY, updated_at=_KEY, unknown=_KEY)
        for check in payload["readiness"]["checks"].values():
            check.update(detail=_KEY, unknown=_KEY)
        payload["readiness"]["checks"]["unknown"] = {"secret": _KEY}

        reason, projected = self._probe_payload(payload)

        expected = _payload()
        del expected["platform"]
        self.assertEqual("ok", reason)
        self.assertEqual(expected, projected)
        self.assertNotIn(_KEY, json.dumps(projected))

    def test_degraded_response_preserves_safe_statuses_and_optional_disk_failure(self) -> None:
        payload = _payload()
        payload["status"] = payload["readiness"]["status"] = "degraded"
        payload["readiness"]["checks"]["disk"] = {"status": "degraded", "detail": _KEY}
        payload["readiness"]["checks"]["session_store"] = {"status": "retrying"}
        reason, projected = self._probe_payload(payload)
        self.assertEqual("degraded", reason)
        assert projected is not None
        self.assertEqual({"status": "degraded"}, projected["readiness"]["checks"]["disk"])
        self.assertNotIn(_KEY, json.dumps(projected))

    def test_absent_runtime_state_is_projected_as_unknown(self) -> None:
        payload = _payload()
        payload["status"] = payload["readiness"]["status"] = "degraded"
        payload["gateway_state"] = None
        payload["readiness"]["checks"]["gateway"].update(status="degraded", state="unknown")
        reason, projected = self._probe_payload(payload)
        self.assertEqual("degraded", reason)
        assert projected is not None
        self.assertEqual("unknown", projected["gateway_state"])

    def test_rejects_endpoint_and_credentials_before_connecting(self) -> None:
        urls = (
            "https://127.0.0.1:8642/health",
            "http://127.0.0.1/health",
            "http://127.0.0.1:0/health",
            "http://127.0.0.1:65536/health",
            "http://127.0.0.2:8642/health",
            "http://localhost.evil:8642/health",
            "http://user@127.0.0.1:8642/health",
            "http://127.0.0.1:8642/health?key=x",
            "http://127.0.0.1:8642/health#fragment",
            "http://127.0.0.1:8642/health/detailed",
            " http://127.0.0.1:8642/health",
            "http://127.0.0.1:8642/health\n",
        )
        with patch("zeus.hermes_diagnostics.socket.socket") as connect:
            for url in urls:
                with self.subTest(url=url):
                    self.assertEqual(
                        ("invalid_endpoint", None), probe_gateway_health(url, _KEY, _PID)
                    )
            for key in (
                "",
                "x" * 15,
                "x" * 4097,
                "x" * 16 + "\r\nInjected: yes",
                "x" * 16 + "é",
                "x" * 16 + " ",
            ):
                with self.subTest(key_length=len(key)):
                    self.assertEqual(
                        ("credentials_unavailable", None),
                        probe_gateway_health("http://127.0.0.1:8642/health", key, _PID),
                    )
            connect.assert_not_called()

    def test_localhost_uses_numeric_address_and_ignores_ambient_proxy(self) -> None:
        with (
            _Server(_http(json.dumps(_payload()).encode())) as server,
            patch.dict(
                "os.environ",
                {"http_proxy": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9"},
            ),
            patch("socket.getaddrinfo", side_effect=AssertionError("unexpected DNS resolution")),
        ):
            reason, _health = probe_gateway_health(
                server.url.replace("127.0.0.1", "localhost"), _KEY, _PID
            )
        self.assertEqual("ok", reason)
        self.assertIn(b"GET /health/detailed HTTP/1.1\r\n", server.requests[0])
        self.assertIn(f"Authorization: Bearer {_KEY}\r\n".encode(), server.requests[0])

    def test_ipv6_literal(self) -> None:
        try:
            server = _Server(_http(json.dumps(_payload()).encode()), ipv6=True)
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {type(exc).__name__}")
        with server:
            reason, _health = probe_gateway_health(server.url, _KEY, _PID)
        self.assertEqual("ok", reason)

    def test_http_errors_return_only_fixed_reasons_and_redirects_are_not_followed(self) -> None:
        with _Server(_http(json.dumps(_payload()).encode())) as target:
            for status, reason in (
                (401, "authentication_failed"),
                (403, "authentication_failed"),
                (404, "unsupported_runtime"),
                (500, "health_unavailable"),
                (302, "health_unavailable"),
            ):
                with self.subTest(status=status):
                    headers = (
                        f"Location: {target.url}?{_KEY}\r\nContent-Length: {len(_KEY)}\r\n".encode()
                    )
                    with _Server(_http(_KEY.encode(), status=status, headers=headers)) as server:
                        self.assertEqual(
                            (reason, None), probe_gateway_health(server.url, _KEY, _PID)
                        )
            self.assertEqual([], target.requests)

    def test_runtime_version_platform_and_pid_are_bound(self) -> None:
        for field, value, reason in (
            ("version", "0.20.0", "unsupported_runtime"),
            ("version", "0.21.1", "unsupported_runtime"),
            ("platform", "other", "unsupported_runtime"),
            ("pid", _PID + 1, "pid_mismatch"),
            ("pid", True, "invalid_health"),
            ("pid", 0, "invalid_health"),
        ):
            with self.subTest(field=field, value=value):
                payload = _payload()
                payload[field] = value
                self.assertEqual((reason, None), self._probe_payload(payload))

    def test_missing_required_fields_and_unknown_enums_are_rejected(self) -> None:
        for field in _payload():
            with self.subTest(missing=field):
                payload = _payload()
                del payload[field]
                self.assertEqual(("invalid_health", None), self._probe_payload(payload))
        for name in _payload()["readiness"]["checks"]:
            with self.subTest(check=name):
                payload = _payload()
                del payload["readiness"]["checks"][name]
                self.assertEqual(("invalid_health", None), self._probe_payload(payload))
        for name in _payload()["readiness"]["checks"]:
            with self.subTest(unknown_status=name):
                payload = _payload()
                payload["readiness"]["checks"][name]["status"] = _KEY
                self.assertEqual(("invalid_health", None), self._probe_payload(payload))
        payload = _payload()
        payload["gateway_state"] = _KEY
        self.assertEqual(("invalid_health", None), self._probe_payload(payload))

    def test_counters_percentages_booleans_and_status_consistency_are_strict(self) -> None:
        cases = []
        for value in (True, -1, 2**63, 1.5, float("inf"), "2"):
            payload = _payload()
            payload["active_agents"] = value
            cases.append(payload)
            payload = _payload()
            payload["readiness"]["checks"]["background_queues"]["active_delegations"] = value
            cases.append(payload)
            payload = _payload()
            payload["readiness"]["checks"]["gateway"]["platforms"] = value
            cases.append(payload)
            payload = _payload()
            payload["readiness"]["checks"]["disk"]["free_bytes"] = value
            cases.append(payload)
        for value in (True, -1, 100.1, float("nan"), float("inf"), "25"):
            payload = _payload()
            payload["readiness"]["checks"]["disk"]["used_percent"] = value
            cases.append(payload)
        for field in ("gateway_busy", "gateway_drainable"):
            payload = _payload()
            payload[field] = 1
            cases.append(payload)
        payload = _payload()
        payload["readiness"]["status"] = "degraded"
        cases.append(payload)
        payload = _payload()
        payload["readiness"]["checks"]["model"]["status"] = "degraded"
        cases.append(payload)
        payload = _payload()
        payload["readiness"]["checks"]["gateway"]["connected_platforms"] = 2
        cases.append(payload)
        for index, payload in enumerate(cases):
            with self.subTest(case=index):
                self.assertEqual(("invalid_health", None), self._probe_payload(payload))

    def test_malformed_json_and_oversized_or_invalid_http_are_rejected(self) -> None:
        oversized = b"x" * (MAX_HEALTH_RESPONSE_BYTES + 1)
        oversized_chunk = f"{len(oversized):x}\r\n".encode() + oversized + b"\r\n0\r\n\r\n"
        responses = [
            _http(b"[]"),
            _http(b"not json " + _KEY.encode()),
            _http(b"\xff"),
            _http(b'{"status":"ok","status":"degraded"}'),
            _http(b"{" + b"x" * MAX_HEALTH_RESPONSE_BYTES),
            _http(oversized, headers=b""),
            _http(oversized_chunk, headers=b"Transfer-Encoding: chunked\r\n"),
            _http(b"{}", headers=b"Content-Length: -1\r\n"),
            _http(b"{}", headers=b"Content-Length: 2\r\nContent-Length: 3\r\n"),
            _http(b"{}", headers=b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"),
            _http(b"{}", headers=b"Content-Length: 3\r\n"),
            _http(b"{}", headers=b"Content-Encoding: gzip\r\nContent-Length: 2\r\n"),
            _http(b"{}", headers=b"X-Large: " + b"x" * MAX_HEALTH_RESPONSE_BYTES + b"\r\n"),
            _http(b"{}", headers=(b"X-Pad: " + b"x" * 4000 + b"\r\n") * 17),
            b"not an HTTP status\r\n\r\n" + _KEY.encode(),
            _http(b"[" * 2000 + b"]" * 2000),
        ]
        for index, response in enumerate(responses):
            with self.subTest(case=index), _Server(response) as server:
                self.assertEqual(
                    ("invalid_health", None), probe_gateway_health(server.url, _KEY, _PID)
                )

    def test_unavailable_network_and_invalid_budgets_return_fixed_reasons(self) -> None:
        with patch("zeus.hermes_diagnostics.socket.socket", side_effect=OSError(_KEY)):
            self.assertEqual(
                ("health_unavailable", None),
                probe_gateway_health("http://127.0.0.1:8642/health", _KEY, _PID),
            )
        with patch("zeus.hermes_diagnostics.socket.socket") as connect:
            for timeout in (0, -1, float("nan"), float("inf")):
                with self.subTest(timeout=timeout):
                    self.assertEqual(
                        ("timeout", None),
                        probe_gateway_health(
                            "http://127.0.0.1:8642/health", _KEY, _PID, timeout_seconds=timeout
                        ),
                    )
            for pid in (0, True, -1, 2**63):
                with self.subTest(pid=pid):
                    self.assertEqual(
                        ("pid_mismatch", None),
                        probe_gateway_health("http://127.0.0.1:8642/health", _KEY, pid),
                    )
            connect.assert_not_called()

    def test_chunked_and_eof_bodies_and_fixed_length_keepalive_are_supported(self) -> None:
        body = json.dumps(_payload()).encode()
        chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        for wire in (
            _http(chunked, headers=b"Transfer-Encoding: chunked\r\n"),
            _http(body, headers=b""),
        ):
            with _Server(wire) as server:
                self.assertEqual("ok", probe_gateway_health(server.url, _KEY, _PID)[0])

        def keepalive(connection: socket.socket, stopped: threading.Event) -> None:
            connection.sendall(_http(body))
            stopped.wait(1)

        with _Server(keepalive) as server:
            self.assertEqual(
                "ok", probe_gateway_health(server.url, _KEY, _PID, timeout_seconds=0.2)[0]
            )

    def test_total_deadline_interrupts_slow_drip_headers_and_body(self) -> None:
        for prefix in (
            b"HTTP/1.1 200 OK\r\nX-Drip: ",
            b"HTTP/1.1 200 OK\r\nContent-Length: 60000\r\n\r\n",
        ):

            def drip(
                connection: socket.socket,
                stopped: threading.Event,
                prefix: bytes = prefix,
            ) -> None:
                connection.sendall(prefix)
                while not stopped.wait(0.02):
                    connection.sendall(b"x")

            with self.subTest(prefix=prefix), _Server(drip) as server:
                started = time.monotonic()
                self.assertEqual(
                    ("timeout", None),
                    probe_gateway_health(server.url, _KEY, _PID, timeout_seconds=0.15),
                )
                self.assertLess(time.monotonic() - started, 0.8)

    def test_timer_is_cancelled_and_joined_when_parsing_is_interrupted(self) -> None:
        real_timer = threading.Timer
        timers = []

        def record_timer(*args, **kwargs):
            timer = real_timer(*args, **kwargs)
            timers.append(timer)
            return timer

        with (
            _Server(_http(json.dumps(_payload()).encode())) as server,
            patch("zeus.hermes_diagnostics.threading.Timer", side_effect=record_timer),
            patch("zeus.hermes_diagnostics.json.loads", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            probe_gateway_health(server.url, _KEY, _PID)
        self.assertEqual(1, len(timers))
        self.assertFalse(timers[0].is_alive())


if __name__ == "__main__":
    unittest.main()
