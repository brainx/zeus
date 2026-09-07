"""Bounded HTTP for a gateway's captured loopback readiness endpoint."""

from __future__ import annotations

import contextlib
import io
import json
import math
import re
import socket
import threading
import time
from http.client import HTTPException, HTTPResponse
from typing import cast

MAX_HEADER_BYTES = 64 * 1024
_ENDPOINT = re.compile(r"http://(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})/health", re.I)


class GatewayHTTPError(ValueError):
    """A fixed transport code; never contains endpoint, credential, or payload text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def visible_ascii(value: str, minimum: int, maximum: int) -> bool:
    return minimum <= len(value) <= maximum and all(33 <= ord(char) <= 126 for char in value)


class _HeaderReader(io.BufferedReader):
    """Bound aggregate headers and chunk framing, including slow-drip lines."""

    remaining = MAX_HEADER_BYTES

    def readline(self, size: int | None = -1) -> bytes:
        limit = self.remaining + 1
        if size is not None and size >= 0:
            limit = min(limit, size)
        line = super().readline(limit)
        self.remaining -= len(line)
        if self.remaining < 0:
            raise GatewayHTTPError("invalid_response")
        return line


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GatewayHTTPError("invalid_response")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise GatewayHTTPError("invalid_response")


def _validate_headers(response: HTTPResponse, max_bytes: int) -> None:
    lengths = response.headers.get_all("Content-Length", [])
    if any(re.fullmatch(r"[0-9]+", value) is None for value in lengths):
        raise GatewayHTTPError("invalid_response")
    parsed_lengths = {int(value) for value in lengths}
    if len(parsed_lengths) > 1:
        raise GatewayHTTPError("invalid_response")
    encodings = response.headers.get_all("Transfer-Encoding", [])
    if encodings and (lengths or encodings != ["chunked"]):
        raise GatewayHTTPError("invalid_response")
    content_encoding = response.headers.get_all("Content-Encoding", [])
    if content_encoding and content_encoding != ["identity"]:
        raise GatewayHTTPError("invalid_response")
    if parsed_lengths and max(parsed_lengths) > max_bytes:
        raise GatewayHTTPError("response_too_large")


def request_json(
    url: str,
    api_key: str,
    path: str,
    *,
    method: str = "GET",
    body: bytes = b"",
    idempotency_key: str | None = None,
    success_status: int = 200,
    max_bytes: int = 64 * 1024,
    timeout_seconds: float = 2.0,
) -> tuple[int, dict[str, object] | None]:
    """Issue one request, returning no body for unexpected HTTP status codes.

    Callers supply fixed routes, never a caller-controlled path. No retry,
    redirect, proxy, DNS resolution, or error-body disclosure is performed.
    """
    match = _ENDPOINT.fullmatch(url)
    if match is None or not 1 <= int(match[2]) <= 65535:
        raise GatewayHTTPError("invalid_endpoint")
    if not visible_ascii(api_key, 16, 4096):
        raise GatewayHTTPError("credentials_unavailable")
    if (
        method not in {"GET", "POST"}
        or not path.startswith("/")
        or not visible_ascii(path, 1, 256)
        or any(char in path for char in "?#")
        or (idempotency_key is not None and not visible_ascii(idempotency_key, 1, 255))
    ):
        raise GatewayHTTPError("invalid_request")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise GatewayHTTPError("timeout")
    host = match[1].lower()
    if host == "localhost":
        host = "127.0.0.1"
    family = socket.AF_INET6 if host == "[::1]" else socket.AF_INET
    address = "::1" if family == socket.AF_INET6 else host
    deadline = time.monotonic() + timeout_seconds
    expired = threading.Event()
    connection: socket.socket | None = None
    response: HTTPResponse | None = None
    timer: threading.Timer | None = None
    timer_started = False

    def expire() -> None:
        expired.set()
        if connection is not None:
            # Closing alone does not interrupt a socket's buffered file reads.
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)

    def check_deadline() -> None:
        if expired.is_set() or time.monotonic() >= deadline:
            raise GatewayHTTPError("timeout")

    try:
        connection = socket.socket(family, socket.SOCK_STREAM)
        timer = threading.Timer(max(0.0, deadline - time.monotonic()), expire)
        timer.daemon = True
        try:
            timer.start()
        except RuntimeError:
            raise GatewayHTTPError("gateway_unavailable") from None
        timer_started = True
        check_deadline()
        connection.settimeout(deadline - time.monotonic())
        connection.connect((address, int(match[2])))
        check_deadline()
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}:{int(match[2])}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            "Accept: application/json\r\nConnection: close\r\n"
        )
        if method == "POST":
            request += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        if idempotency_key is not None:
            request += f"Idempotency-Key: {idempotency_key}\r\n"
        connection.sendall((request + "\r\n").encode("ascii") + body)
        response = HTTPResponse(connection, method=method)
        if not isinstance(response.fp, io.BufferedReader):
            raise GatewayHTTPError("invalid_response")
        # A nested buffered reader may wait for a full buffer on keepalive.
        response.fp = _HeaderReader(response.fp.detach())
        response.begin()
        _validate_headers(response, max_bytes)
        check_deadline()
        if response.status != success_status:
            return response.status, None
        data = response.read(max_bytes + 1)
        check_deadline()
        if len(data) > max_bytes:
            raise GatewayHTTPError("response_too_large")
        if response.length not in {0, None}:
            raise GatewayHTTPError("invalid_response")
        payload = json.loads(
            data.decode("utf-8"), object_pairs_hook=_json_object, parse_constant=_reject_constant
        )
        if not isinstance(payload, dict):
            raise GatewayHTTPError("invalid_response")
        check_deadline()
        return response.status, cast(dict[str, object], payload)
    except GatewayHTTPError:
        check_deadline()
        raise
    except TimeoutError:
        raise GatewayHTTPError("timeout") from None
    except OSError:
        check_deadline()
        raise GatewayHTTPError("gateway_unavailable") from None
    except (HTTPException, ValueError, RecursionError):
        check_deadline()
        raise GatewayHTTPError("invalid_response") from None
    finally:
        if timer is not None:
            timer.cancel()
            if timer_started:
                timer.join()
        if response is not None:
            with contextlib.suppress(OSError):
                response.close()
        if connection is not None:
            with contextlib.suppress(OSError):
                connection.close()
