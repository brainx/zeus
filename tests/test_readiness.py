from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

from zeus.readiness import (
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


class ReadinessTests(unittest.TestCase):
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
