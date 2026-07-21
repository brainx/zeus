from __future__ import annotations

import contextlib
import json
import os
import socket
import socketserver
import threading
import unittest
from email.message import Message
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from unittest.mock import patch

import zeus.readiness as readiness_module
from zeus.readiness import (
    MAX_READINESS_RESPONSE_BYTES,
    ReadinessProbe,
    probe_once,
    readiness_probe_from_env,
    wait_until_ready,
)


class _HealthHandler(BaseHTTPRequestHandler):
    payload: ClassVar[dict[str, Any]] = {"status": "ok", "platform": "hermes-agent"}

    def do_GET(self) -> None:
        data = json.dumps(self.payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        return


class _IPv6ThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class ReadinessTests(unittest.TestCase):
    def _run_server(
        self,
        handler: type[BaseHTTPRequestHandler],
        *,
        ipv6: bool = False,
    ) -> tuple[ThreadingHTTPServer, threading.Thread]:
        server_class = _IPv6ThreadingHTTPServer if ipv6 else ThreadingHTTPServer
        host = "::1" if ipv6 else "127.0.0.1"
        server = server_class((host, 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 1)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, thread

    def _run_raw_server(
        self,
        handler: type[socketserver.BaseRequestHandler],
    ) -> tuple[socketserver.ThreadingTCPServer, threading.Thread]:
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 1)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, thread

    def test_readiness_probe_from_env_builds_loopback_health_url(self) -> None:
        probe = readiness_probe_from_env(
            {
                "API_SERVER_ENABLED": "1",
                "API_SERVER_HOST": "0.0.0.0",
                "API_SERVER_PORT": "4312",
            },
            timeout_seconds=10,
            interval_seconds=0.25,
        )

        self.assertIsNotNone(probe)
        assert probe is not None
        self.assertEqual("http://127.0.0.1:4312/health", probe.url)
        self.assertEqual(10, probe.timeout_seconds)
        self.assertEqual(0.25, probe.interval_seconds)

    def test_readiness_probe_from_env_ignores_non_loopback_host(self) -> None:
        probe = readiness_probe_from_env(
            {
                "API_SERVER_ENABLED": "1",
                "API_SERVER_HOST": "example.com",
                "API_SERVER_PORT": "4312",
            },
            timeout_seconds=10,
            interval_seconds=0.25,
        )

        self.assertIsNone(probe)

    def test_probe_once_accepts_expected_health_payload(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = probe_once(f"http://127.0.0.1:{server.server_port}/health")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        self.assertTrue(result.ready)
        self.assertEqual("ready", result.message)

    def test_probe_once_accepts_expected_health_payload_over_ipv6(self) -> None:
        try:
            server, _thread = self._run_server(_HealthHandler, ipv6=True)
        except OSError as exc:
            self.skipTest(f"IPv6 loopback is unavailable: {exc}")

        result = probe_once(f"http://[::1]:{server.server_port}/health")

        self.assertTrue(result.ready)
        self.assertEqual("ready", result.message)
        self.assertEqual(_HealthHandler.payload, result.payload)

    def test_probe_once_accepts_health_payload_without_content_length(self) -> None:
        class NoContentLengthHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                data = json.dumps(_HealthHandler.payload).encode("utf-8")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server, _thread = self._run_server(NoContentLengthHandler)

        result = probe_once(f"http://127.0.0.1:{server.server_port}/health")

        self.assertTrue(result.ready)
        self.assertEqual("ready", result.message)
        self.assertEqual(_HealthHandler.payload, result.payload)

    def test_probe_once_accepts_chunked_health_payload(self) -> None:
        class ChunkedHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                data = json.dumps(_HealthHandler.payload).encode("utf-8")
                self.send_response(200)
                self.send_header("transfer-encoding", "chunked")
                self.end_headers()
                self.wfile.write(f"{len(data):x}\r\n".encode("ascii"))
                self.wfile.write(data + b"\r\n0\r\n\r\n")

            def log_message(self, format: str, *args: Any) -> None:
                return

        server, _thread = self._run_server(ChunkedHandler)

        result = probe_once(f"http://127.0.0.1:{server.server_port}/health")

        self.assertTrue(result.ready)
        self.assertEqual("ready", result.message)
        self.assertEqual(_HealthHandler.payload, result.payload)

    def test_probe_once_does_not_follow_redirects_or_leak_location(self) -> None:
        class RedirectTargetHandler(_HealthHandler):
            requests = 0

            def do_GET(self) -> None:
                self.__class__.requests += 1
                super().do_GET()

        target, _target_thread = self._run_server(RedirectTargetHandler)
        secret = "API_KEY=sentinel-secret"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header(
                    "location",
                    f"http://127.0.0.1:{target.server_port}/health?{secret}",
                )
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        redirect, _redirect_thread = self._run_server(RedirectHandler)

        result = probe_once(f"http://127.0.0.1:{redirect.server_port}/health")

        self.assertFalse(result.ready)
        self.assertEqual("readiness endpoint returned an HTTP error", result.message)
        self.assertIsNone(result.payload)
        self.assertNotIn(secret, repr(result))
        self.assertEqual(0, RedirectTargetHandler.requests)

    def test_probe_once_ignores_proxy_environment(self) -> None:
        secret = "API_KEY=sentinel-secret"

        class TargetHandler(BaseHTTPRequestHandler):
            requests = 0

            def do_GET(self) -> None:
                self.__class__.requests += 1
                data = json.dumps({"status": "not-ready", "detail": secret}).encode("utf-8")
                self.send_response(200)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        class ProxyHandler(_HealthHandler):
            requests = 0

            def do_GET(self) -> None:
                self.__class__.requests += 1
                super().do_GET()

        target, _target_thread = self._run_server(TargetHandler)
        proxy, _proxy_thread = self._run_server(ProxyHandler)
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        proxy_env = {
            "HTTP_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "NO_PROXY": "",
            "no_proxy": "",
        }

        with (
            patch.dict(os.environ, proxy_env, clear=True),
            patch.object(
                readiness_module,
                "build_opener",
                wraps=readiness_module.build_opener,
            ) as build_opener,
        ):
            result = probe_once(f"http://127.0.0.1:{target.server_port}/health")

        self.assertFalse(result.ready)
        self.assertEqual("unexpected readiness health payload", result.message)
        self.assertIsNone(result.payload)
        self.assertNotIn(secret, repr(result))
        self.assertEqual(1, TargetHandler.requests)
        self.assertEqual(0, ProxyHandler.requests)
        build_opener.assert_called_once()

    def test_probe_once_rejects_oversized_responses_with_bounded_failures(self) -> None:
        max_response_bytes = 64 * 1024
        health_payload = json.dumps(_HealthHandler.payload).encode("utf-8")
        oversized_body = health_payload + b" " * max_response_bytes

        def oversized_handler(include_content_length: bool) -> type[BaseHTTPRequestHandler]:
            class OversizedHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    self.send_response(200)
                    if include_content_length:
                        self.send_header("content-length", str(len(oversized_body)))
                    self.end_headers()
                    with contextlib.suppress(BrokenPipeError):
                        self.wfile.write(oversized_body)

                def log_message(self, format: str, *args: Any) -> None:
                    return

            return OversizedHandler

        for include_content_length in (True, False):
            with self.subTest(include_content_length=include_content_length):
                server, _thread = self._run_server(oversized_handler(include_content_length))
                result = probe_once(f"http://127.0.0.1:{server.server_port}/health")

                self.assertFalse(result.ready)
                self.assertEqual("readiness response exceeds size limit", result.message)
                self.assertIsNone(result.payload)

    def test_probe_once_rejects_trailing_data_after_false_low_content_length(self) -> None:
        health_payload = json.dumps(_HealthHandler.payload).encode("utf-8")
        oversized_body = health_payload + b" " * MAX_READINESS_RESPONSE_BYTES

        class FalseLowContentLengthHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("content-length", str(len(health_payload)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(oversized_body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server, _thread = self._run_server(FalseLowContentLengthHandler)

        result = probe_once(f"http://127.0.0.1:{server.server_port}/health")

        self.assertFalse(result.ready)
        self.assertEqual("readiness response exceeds size limit", result.message)
        self.assertIsNone(result.payload)

    def test_probe_once_requests_exactly_one_max_plus_one_bounded_read(self) -> None:
        class TrackingResponse:
            def __init__(self) -> None:
                self.headers = Message()
                self.length: int | None = None
                self.read_amounts: list[int] = []

            def __enter__(self) -> TrackingResponse:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, amount: int) -> bytes:
                self.read_amounts.append(amount)
                return b"x" * amount

        class TrackingOpener:
            def __init__(self, response: TrackingResponse) -> None:
                self.response = response
                self.requests: list[object] = []

            def open(self, *args: object, **kwargs: object) -> TrackingResponse:
                self.requests.append(args[0])
                return self.response

        response = TrackingResponse()
        opener = TrackingOpener(response)

        with patch.object(readiness_module, "_build_readiness_opener", return_value=opener):
            result = probe_once("http://127.0.0.1:4312/health")

        self.assertEqual([MAX_READINESS_RESPONSE_BYTES + 1], response.read_amounts)
        request = opener.requests[0]
        get_header = getattr(request, "get_header", lambda _name: None)
        self.assertEqual("close", get_header("Connection"))
        self.assertFalse(result.ready)
        self.assertEqual("readiness response exceeds size limit", result.message)
        self.assertIsNone(result.payload)

    def test_probe_once_maps_malformed_http_to_safe_failure(self) -> None:
        secret = "API_KEY=sentinel-secret"

        class MalformedProtocolHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.recv(4096)
                self.request.sendall(f"NOT-HTTP {secret}\r\n\r\n".encode("ascii"))

        server, _thread = self._run_raw_server(MalformedProtocolHandler)

        try:
            result = probe_once(f"http://127.0.0.1:{server.server_address[1]}/health")
        except HTTPException:
            result = None

        self.assertIsNotNone(result)
        assert result is not None
        self.assertFalse(result.ready)
        self.assertEqual("readiness endpoint returned a malformed HTTP response", result.message)
        self.assertIsNone(result.payload)
        self.assertNotIn(secret, repr(result))

    def test_probe_once_rejects_url_data_before_network_io(self) -> None:
        class TrackingHandler(_HealthHandler):
            requests = 0

            def do_GET(self) -> None:
                self.__class__.requests += 1
                super().do_GET()

        server, _thread = self._run_server(TrackingHandler)
        port = server.server_port
        urls = (
            f"http://user:password@127.0.0.1:{port}/health",
            f"http://127.0.0.1:{port}/health?API_KEY=sentinel-secret",
            f"http://127.0.0.1:{port}/health#API_KEY=sentinel-secret",
        )

        for url in urls:
            with self.subTest(url=url):
                result = probe_once(url)
                self.assertFalse(result.ready)
                self.assertEqual("readiness URL must be loopback HTTP", result.message)
                self.assertIsNone(result.payload)
                self.assertNotIn("sentinel-secret", repr(result))

        self.assertEqual(0, TrackingHandler.requests)

    def test_probe_once_never_returns_unexpected_payload_data(self) -> None:
        secret = "API_KEY=sentinel-secret"

        class SecretHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                data = json.dumps({"status": "not-ready", "detail": secret}).encode("utf-8")
                self.send_response(200)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server, _thread = self._run_server(SecretHandler)

        result = probe_once(f"http://127.0.0.1:{server.server_port}/health")

        self.assertFalse(result.ready)
        self.assertEqual("unexpected readiness health payload", result.message)
        self.assertIsNone(result.payload)
        self.assertNotIn(secret, repr(result))

    def test_wait_until_ready_returns_timeout_result(self) -> None:
        result = wait_until_ready(
            ReadinessProbe(
                url="http://127.0.0.1:9/health",
                timeout_seconds=0.1,
                interval_seconds=0.05,
            )
        )

        self.assertFalse(result.ready)
        self.assertIn("readiness timeout", result.message)


if __name__ == "__main__":
    unittest.main()
