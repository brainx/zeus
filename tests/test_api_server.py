from __future__ import annotations

import http.client
import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from typing import Any

from zeus.api import ThreadingHTTPServer as public_server
from zeus.api_server import ThreadingHTTPServer as extracted_server


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
