from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from unittest.mock import patch

from tests.test_hermes_diagnostics import _http
from tests.test_hermes_diagnostics import _Server as _HealthServer
from zeus.hermes_runs_client import (
    MAX_INPUT_BYTES,
    MAX_STATUS_RESPONSE_BYTES,
    RUN_STATES,
    TERMINAL_STATES,
    HermesRunsClientError,
    capabilities,
    status,
    stop,
    submit,
)

_KEY = "fake-runs-api-key-0123456789"
_ID = "run_0123456789abcdef0123456789abcdef"
_OTHER_ID = "run_fedcba9876543210fedcba9876543210"
_IDEMPOTENCY_KEY = "zeus-test-request-key"


def _capabilities() -> dict:
    return {
        "object": "hermes.api_server.capabilities",
        "platform": "hermes-agent",
        "auth": {"type": "bearer", "required": True},
        "features": {
            "run_submission": True,
            "run_status": True,
            "run_stop": True,
            "runs_idempotency": {"supported": True, "durable": True, "retention_seconds": 86400},
        },
    }


def _run(state: str = "completed") -> dict:
    return {"object": "hermes.run", "run_id": _ID, "status": state}


def _json(payload: object, http_status: int = 200) -> bytes:
    return _http(json.dumps(payload).encode(), status=http_status)


class _Server(_HealthServer):
    """Read complete mutation bodies before responding or dropping the acknowledgement."""

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
                    while b"\r\n\r\n" not in request:
                        block = connection.recv(4096)
                        if not block or len(request) > 16384:
                            return
                        request.extend(block)
                    headers, body = bytes(request).split(b"\r\n\r\n", 1)
                    length = 0
                    for line in headers.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":", 1)[1])
                    while len(body) < length:
                        block = connection.recv(min(4096, length - len(body)))
                        if not block:
                            return
                        body += block
                    self.requests.append(headers + b"\r\n\r\n" + body)
                    if isinstance(self.response, bytes):
                        connection.sendall(self.response)
                    else:
                        self.response(connection, self.stopped)
                except OSError:
                    pass
            return


class HermesRunsClientTests(unittest.TestCase):
    def assert_client_error(self, code: str, uncertain: bool, callback, *args, **kwargs):
        with self.assertRaises(HermesRunsClientError) as caught:
            callback(*args, **kwargs)
        self.assertEqual(code, caught.exception.code)
        self.assertIs(uncertain, caught.exception.uncertain)
        self.assertEqual(code, str(caught.exception))
        self.assertNotIn(_KEY, repr(caught.exception))

    def test_capabilities_are_authenticated_and_projected_without_extra_fields(self) -> None:
        payload = _capabilities()
        payload.update(model=_KEY, runtime={"description": _KEY})
        payload["features"]["arbitrary"] = _KEY
        with (
            _Server(_json(payload)) as server,
            patch("socket.getaddrinfo", side_effect=AssertionError("unexpected DNS")),
            patch.dict("os.environ", {"http_proxy": "http://127.0.0.1:9"}),
        ):
            self.assertEqual(
                _capabilities(), capabilities(server.url.replace("127.0.0.1", "localhost"), _KEY)
            )
        self.assertIn(b"GET /v1/capabilities HTTP/1.1\r\n", server.requests[0])
        self.assertIn(f"Authorization: Bearer {_KEY}\r\n".encode(), server.requests[0])

    def test_capabilities_require_all_operations_and_durable_retention(self) -> None:
        cases = []
        for path, bad_values in (
            (("object",), ("other", None)),
            (("platform",), ("other", None)),
            (("auth", "type"), ("none", None)),
            (("auth", "required"), (False, 1)),
            (("features", "run_submission"), (False, 1)),
            (("features", "run_status"), (False, 1)),
            (("features", "run_stop"), (False, 1)),
            (("features", "runs_idempotency", "supported"), (False, 1)),
            (("features", "runs_idempotency", "durable"), (False, 1)),
            (
                ("features", "runs_idempotency", "retention_seconds"),
                (0, -1, True, "86400", 2**63, None),
            ),
        ):
            for value in (*bad_values, "missing"):
                payload = _capabilities()
                target = payload
                for key in path[:-1]:
                    target = target[key]
                if value == "missing":
                    del target[path[-1]]
                else:
                    target[path[-1]] = value
                cases.append(payload)
        for index, payload in enumerate(cases):
            with self.subTest(index=index), _Server(_json(payload)) as server:
                self.assert_client_error(
                    "unsupported_runtime", False, capabilities, server.url, _KEY
                )
        for value in (float("nan"), float("inf")):
            payload = _capabilities()
            payload["features"]["runs_idempotency"]["retention_seconds"] = value
            with _Server(_json(payload)) as server:
                self.assert_client_error("invalid_response", False, capabilities, server.url, _KEY)

    def test_submit_sends_only_input_and_idempotency_key_and_projects_receipt(self) -> None:
        receipt = {"run_id": _ID, "status": "started", "replayed": False}
        with _Server(_json({**receipt, "secret": _KEY}, 202)) as server:
            self.assertEqual(
                receipt, submit(server.url, _KEY, "A Unicode message: λ", _IDEMPOTENCY_KEY)
            )
        headers, body = server.requests[0].split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"POST /v1/runs HTTP/1.1\r\n"))
        self.assertIn(f"Idempotency-Key: {_IDEMPOTENCY_KEY}\r\n".encode(), headers + b"\r\n")
        self.assertEqual({"input": "A Unicode message: λ"}, json.loads(body))

    def test_replay_receipts_accept_all_actual_run_states(self) -> None:
        for state in RUN_STATES:
            receipt = {"run_id": _ID, "status": state, "replayed": True}
            with self.subTest(state=state), _Server(_json(receipt, 202)) as server:
                self.assertEqual(receipt, submit(server.url, _KEY, "hello", _IDEMPOTENCY_KEY))

    def test_malformed_or_inconsistent_receipts_are_uncertain(self) -> None:
        receipt = {"run_id": _ID, "status": "started", "replayed": False}
        cases = [
            {},
            {**receipt, "run_id": "run_abc123"},
            {**receipt, "run_id": _OTHER_ID.upper()},
            {**receipt, "status": "running"},
            {**receipt, "status": "unknown"},
            {**receipt, "replayed": True},
            {**receipt, "replayed": 0},
        ]
        for payload in cases:
            with self.subTest(payload=payload), _Server(_json(payload, 202)) as server:
                self.assert_client_error(
                    "invalid_response", True, submit, server.url, _KEY, "hello", _IDEMPOTENCY_KEY
                )

    def test_status_returns_output_only_explicitly_and_discards_sensitive_details(self) -> None:
        payload = {
            **_run(),
            "output": "the answer",
            "error": _KEY,
            "approval": {"command": _KEY},
            "session_id": _KEY,
            "usage": {"secret": _KEY},
            "model": _KEY,
        }
        for include_output in (False, True):
            expected = {"run_id": _ID, "status": "completed"}
            if include_output:
                expected["output"] = "the answer"
            with _Server(_json(payload)) as server:
                self.assertEqual(
                    expected, status(server.url, _KEY, _ID, include_output=include_output)
                )
            self.assertTrue(server.requests[0].startswith(f"GET /v1/runs/{_ID} HTTP/1.1".encode()))

    def test_status_validates_matching_id_object_state_and_explicit_output(self) -> None:
        cases = [
            {**_run(), "run_id": _OTHER_ID},
            {**_run(), "object": "other"},
            {**_run(), "status": "started"},
            {**_run(), "status": "unknown"},
            {**_run(), "output": {"secret": _KEY}},
            {**_run(), "output": "\ud800"},
        ]
        for payload in cases:
            with _Server(_json(payload)) as server:
                self.assert_client_error(
                    "invalid_response", False, status, server.url, _KEY, _ID, include_output=True
                )
        for state in RUN_STATES:
            with _Server(_json(_run(state))) as server:
                self.assertEqual({"run_id": _ID, "status": state}, status(server.url, _KEY, _ID))

    def test_stop_is_exact_cooperative_and_preserves_already_terminal_states(self) -> None:
        for state in TERMINAL_STATES | {"stopping"}:
            payload = {"run_id": _ID, "status": state}
            if state != "stopping":
                payload.update(object="hermes.run", output=_KEY, error=_KEY)
            with _Server(_json(payload)) as server:
                self.assertEqual({"run_id": _ID, "status": state}, stop(server.url, _KEY, _ID))
            headers, body = server.requests[0].split(b"\r\n\r\n", 1)
            self.assertTrue(headers.startswith(f"POST /v1/runs/{_ID}/stop HTTP/1.1".encode()))
            self.assertEqual(b"", body)
            self.assertNotIn(b"Idempotency-Key", headers)

    def test_stop_mismatch_and_nonterminal_acknowledgements_remain_uncertain(self) -> None:
        for payload in (
            {"run_id": _OTHER_ID, "status": "stopping"},
            _run("running"),
            {"run_id": _ID, "status": "completed"},
        ):
            with _Server(_json(payload)) as server:
                self.assert_client_error("invalid_response", True, stop, server.url, _KEY, _ID)

    def test_http_rejections_and_ambiguous_responses_never_expose_error_body(self) -> None:
        for http_status, code, uncertain in (
            (400, "invalid_request", False),
            (401, "authentication_failed", False),
            (403, "authentication_failed", False),
            (404, "not_found", False),
            (409, "conflict", False),
            (422, "invalid_request", False),
            (429, "rate_limited", False),
            (500, "gateway_unavailable", True),
            (503, "gateway_unavailable", True),
            (200, "invalid_response", True),
        ):
            with (
                self.subTest(http_status=http_status),
                _Server(_http(_KEY.encode(), status=http_status)) as server,
            ):
                self.assert_client_error(
                    code, uncertain, submit, server.url, _KEY, "hi", _IDEMPOTENCY_KEY
                )
            with _Server(_http(_KEY.encode(), status=http_status)) as server:
                self.assert_client_error(code, False, status, server.url, _KEY, _ID)

    def test_redirect_does_not_forward_credential_or_mutation(self) -> None:
        with _Server(_json({})) as target:
            headers = f"Location: {target.url}\r\nContent-Length: 0\r\n".encode()
            with _Server(_http(b"", status=307, headers=headers)) as server:
                self.assert_client_error("invalid_response", True, stop, server.url, _KEY, _ID)
            self.assertEqual([], target.requests)

    def test_lost_acceptance_is_uncertain_and_submission_is_not_retried(self) -> None:
        with _Server(b"") as server:
            self.assert_client_error(
                "gateway_unavailable",
                True,
                submit,
                server.url,
                _KEY,
                "accepted then lost",
                _IDEMPOTENCY_KEY,
            )
        self.assertEqual(1, len(server.requests))
        self.assertEqual(
            {"input": "accepted then lost"}, json.loads(server.requests[0].split(b"\r\n\r\n")[1])
        )

    def test_malformed_framing_json_and_body_limits_fail_closed(self) -> None:
        responses = [
            _http(b"{}", status=202, headers=b"Content-Length: 3\r\n"),
            _http(
                b"{}", status=202, headers=b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"
            ),
            _http(b"{}", status=202, headers=b"Content-Length: 2\r\nContent-Length: 3\r\n"),
            _http(b"{}", status=202, headers=b"Content-Encoding: gzip\r\nContent-Length: 2\r\n"),
            _http(b' {"run_id":"x","run_id":"y"}', status=202),
            _http(b'{"x":NaN}', status=202),
            _http(b"[" * 2000 + b"]" * 2000, status=202),
            _http(b"\xff", status=202),
            _http(b"[]", status=202),
            _http(b"{}", status=202, headers=(b"X-Pad: " + b"x" * 4000 + b"\r\n") * 17),
        ]
        for index, wire in enumerate(responses):
            with self.subTest(index=index), _Server(wire) as server:
                self.assert_client_error(
                    "invalid_response", True, submit, server.url, _KEY, "hi", _IDEMPOTENCY_KEY
                )
        oversized = b"x" * (MAX_STATUS_RESPONSE_BYTES + 1)
        chunked = f"{len(oversized):x}\r\n".encode() + oversized + b"\r\n0\r\n\r\n"
        for wire in (
            _http(oversized),
            _http(oversized, headers=b""),
            _http(chunked, headers=b"Transfer-Encoding: chunked\r\n"),
        ):
            with _Server(wire) as server:
                self.assert_client_error("invalid_response", False, status, server.url, _KEY, _ID)

    def test_total_deadline_bounds_mutation_headers_body_and_chunk_drips(self) -> None:
        for prefix, dripped in (
            (b"HTTP/1.1 202 Accepted\r\nX-Drip: ", b"x"),
            (b"HTTP/1.1 202 Accepted\r\nContent-Length: 60000\r\n\r\n", b"x"),
            (b"HTTP/1.1 202 Accepted\r\nTransfer-Encoding: chunked\r\n\r\n", b"1;"),
        ):

            def drip(
                connection: socket.socket,
                stopped: threading.Event,
                prefix: bytes = prefix,
                dripped: bytes = dripped,
            ) -> None:
                connection.sendall(prefix)
                while not stopped.wait(0.02):
                    connection.sendall(dripped)

            with _Server(drip) as server:
                started = time.monotonic()
                self.assert_client_error(
                    "timeout",
                    True,
                    submit,
                    server.url,
                    _KEY,
                    "hi",
                    _IDEMPOTENCY_KEY,
                    timeout_seconds=0.15,
                )
                self.assertLess(time.monotonic() - started, 0.8)

    def test_local_validation_refuses_unsafe_endpoints_keys_input_and_ids(self) -> None:
        url = "http://127.0.0.1:12345/health"
        with patch("zeus.gateway_http.socket.socket") as connect:
            for bad in (
                url + "?x",
                url + "/",
                url.replace("127.0.0.1", "remote.example"),
                url.replace("http:", "https:"),
                url.replace(":12345", ""),
            ):
                self.assert_client_error(
                    "invalid_endpoint", False, submit, bad, _KEY, "hi", _IDEMPOTENCY_KEY
                )
            for bad in ("short", _KEY + "\r\nInjected:yes", _KEY + "é", "x" * 4097):
                self.assert_client_error(
                    "credentials_unavailable", False, submit, url, bad, "hi", _IDEMPOTENCY_KEY
                )
            for bad in ("", " ", "\ud800", "x" * (MAX_INPUT_BYTES + 1)):
                self.assert_client_error(
                    "invalid_request", False, submit, url, _KEY, bad, _IDEMPOTENCY_KEY
                )
            for bad in ("", "x" * 256, "x\r\nInjected:y", "contains space"):
                self.assert_client_error("invalid_request", False, submit, url, _KEY, "hi", bad)
            for bad in ("", "../stop", _ID + "?x", "run_" + "f" * 31):
                self.assert_client_error("invalid_request", False, status, url, _KEY, bad)
                self.assert_client_error("invalid_request", False, stop, url, _KEY, bad)
            connect.assert_not_called()

    def test_network_errors_are_fixed_and_post_outcomes_remain_uncertain(self) -> None:
        with patch("zeus.gateway_http.socket.socket", side_effect=OSError(_KEY)):
            self.assert_client_error(
                "gateway_unavailable", False, capabilities, "http://127.0.0.1:9/health", _KEY
            )
            self.assert_client_error(
                "gateway_unavailable",
                True,
                submit,
                "http://127.0.0.1:9/health",
                _KEY,
                "hi",
                _IDEMPOTENCY_KEY,
            )

    def test_timer_start_failure_does_not_join_unstarted_thread_or_leak_socket(self) -> None:
        with (
            patch("zeus.gateway_http.socket.socket") as connection,
            patch("zeus.gateway_http.threading.Timer.start", side_effect=RuntimeError(_KEY)),
        ):
            self.assert_client_error(
                "gateway_unavailable", False, capabilities, "http://127.0.0.1:9/health", _KEY
            )
        connection.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
