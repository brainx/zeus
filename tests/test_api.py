from __future__ import annotations

import http.client
import json
import socket
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from zeus.api import make_handler
from zeus.config import Settings

JsonPayload = dict[str, Any] | list[Any]


@contextmanager
def api_server(env: dict[str, str] | None = None) -> Iterator[int]:
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
        handler = make_handler(Settings.from_env(settings_env))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)


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


def json_request_body(payload: JsonPayload) -> bytes:
    return json.dumps(payload).encode("utf-8")


def auth_json_headers(key: str = "secret") -> dict[str, str]:
    return {"content-type": "application/json", "x-zeus-api-key": key}


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


class ApiBehaviorTests(unittest.TestCase):
    def test_health_is_public_but_missing_api_key_rejects_bots_list(self) -> None:
        with api_server() as port:
            status, body = request_json(port, "GET", "/health")
            self.assertEqual(200, status)
            self.assertEqual({"status": "ok"}, body)

            status, body = request_json(port, "GET", "/bots")
            self.assertEqual(503, status)
            self.assertEqual("missing_api_key", body["error"]["code"])

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


if __name__ == "__main__":
    unittest.main()
