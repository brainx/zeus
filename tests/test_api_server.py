from __future__ import annotations

import http.client
import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from typing import Any
from unittest.mock import patch

from zeus.api import ThreadingHTTPServer as public_server
from zeus.api_server import ThreadingHTTPServer as extracted_server
from zeus.api_server import _RequestReadDeadlineSocket


def request_json(port: int, method: str, path: str) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path)
        response = conn.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        return response.status, body
    finally:
        conn.close()


class ApiServerTests(unittest.TestCase):
    def test_public_server_is_extracted_server(self) -> None:
        self.assertIs(public_server, extracted_server)

    def test_header_lines_cannot_refresh_request_read_deadline(self) -> None:
        clock = [10.0]
        accepted, peer = socket.socketpair()
        with (
            patch("zeus.api_server.time.monotonic", side_effect=lambda: clock[0]),
            _RequestReadDeadlineSocket(accepted, 1.0) as request,
            peer,
        ):
            request.settimeout(2.0)
            with request.makefile("rb") as incoming:
                peer.sendall(b"GET /health HTTP/1.1\r\n")
                clock[0] = 10.25
                self.assertEqual(b"GET /health HTTP/1.1\r\n", incoming.readline())
                peer.sendall(b"Host: localhost\r\n")
                clock[0] = 10.75
                self.assertEqual(b"Host: localhost\r\n", incoming.readline())
                self.assertEqual(2.0, request.gettimeout())
                peer.sendall(b"\r\n")
                clock[0] = 11.01
                with self.assertRaisesRegex(TimeoutError, "read deadline expired"):
                    incoming.readline()

    def test_body_read_uses_the_remaining_header_read_budget(self) -> None:
        clock = [10.0]
        accepted, peer = socket.socketpair()
        with (
            patch("zeus.api_server.time.monotonic", side_effect=lambda: clock[0]),
            _RequestReadDeadlineSocket(accepted, 1.0) as request,
            peer,
        ):
            request.settimeout(2.0)
            with request.makefile("rb") as incoming:
                peer.sendall(b"Content-Length: 2\r\n\r\n")
                clock[0] = 10.4
                self.assertEqual(b"Content-Length: 2\r\n", incoming.readline())
                self.assertEqual(b"\r\n", incoming.readline())
                peer.sendall(b"a")
                clock[0] = 10.8
                self.assertEqual(b"a", incoming.read(1))
                self.assertEqual(2.0, request.gettimeout())
                peer.sendall(b"b")
                clock[0] = 11.01
                with self.assertRaisesRegex(TimeoutError, "read deadline expired"):
                    incoming.read(1)

    def test_completed_request_can_run_and_drain_past_read_deadline(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class SlowHandler(BaseHTTPRequestHandler):
            api_request_timeout_seconds = 0.05

            def do_GET(self) -> None:
                entered.set()
                release.wait(timeout=2)
                data = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = extracted_server(("127.0.0.1", 0), SlowHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        results = []
        client_thread = threading.Thread(
            target=lambda: results.append(request_json(server.server_port, "GET", "/health"))
        )
        server_thread.start()
        client_thread.start()
        try:
            self.assertTrue(entered.wait(timeout=1))
            server.begin_draining()
            self.assertFalse(server.wait_for_drain(0.1))
            release.set()
            client_thread.join(timeout=2)
            self.assertTrue(server.wait_for_drain(1))
            self.assertEqual([(200, {"status": "ok"})], results)
        finally:
            release.set()
            client_thread.join(timeout=2)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
        self.assertFalse(client_thread.is_alive())

    def test_single_body_read_cannot_extend_deadline_with_trickled_bytes(self) -> None:
        clock = [10.0]
        accepted, peer = socket.socketpair()

        class TrickleSocket(_RequestReadDeadlineSocket):
            def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
                clock[0] += 0.4
                peer.sendall(b"a")
                return super().recv_into(buffer, nbytes, flags)

        with (
            patch("zeus.api_server.time.monotonic", side_effect=lambda: clock[0]),
            TrickleSocket(accepted, 1.0) as request,
            peer,
        ):
            request.settimeout(2.0)
            with (
                request.makefile("rb") as incoming,
                self.assertRaisesRegex(TimeoutError, "read deadline expired"),
            ):
                incoming.read(3)
            self.assertEqual(2.0, request.gettimeout())

    def test_rejects_requests_above_concurrency_limit(self) -> None:
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

        server = extracted_server(("127.0.0.1", 0), LimitedHandler)
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

    def test_drains_active_requests_and_rejects_new_work(self) -> None:
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

        server = extracted_server(("127.0.0.1", 0), DrainHandler)
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

    def test_times_out_incomplete_requests_and_releases_capacity(self) -> None:
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

        class TrackingServer(extracted_server):
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


if __name__ == "__main__":
    unittest.main()
