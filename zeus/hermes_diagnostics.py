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

MAX_HEALTH_RESPONSE_BYTES = 64 * 1024
MAX_HEALTH_COUNTER = 2**63 - 1
HERMES_VERSION = "0.21.0"

# Hermes 0.21 agent/monitoring/gateway_health.py's bounded gateway states.
GATEWAY_STATES = frozenset(
    {
        "starting",
        "running",
        "connected",
        "ok",
        "ready",
        "draining",
        "stopping",
        "stopped",
        "startup_failed",
        "unknown",
        "fatal",
        "degraded",
        "error",
        "failed",
    }
)
_HEALTH_STATES = frozenset({"ok", "degraded"})
_SESSION_STATES = frozenset({"ok", "unavailable", "retrying"})
_ENDPOINT = re.compile(r"http://(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})/health", re.I)


class _InvalidHealth(ValueError):
    pass


class _HeaderReader(io.BufferedReader):
    """Bound aggregate headers as well as the HTTP parser's individual lines."""

    remaining = MAX_HEALTH_RESPONSE_BYTES

    def readline(self, size: int | None = -1) -> bytes:
        limit = self.remaining + 1
        if size is not None and size >= 0:
            limit = min(limit, size)
        line = super().readline(limit)
        self.remaining -= len(line)
        if self.remaining < 0:
            raise _InvalidHealth
        return line


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _InvalidHealth
    return cast(dict[str, object], value)


def _enum(value: object, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _InvalidHealth
    return value


def _count(value: object, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _InvalidHealth
    if not int(positive) <= value <= MAX_HEALTH_COUNTER:
        raise _InvalidHealth
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise _InvalidHealth
    return value


def _percentage(value: object) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _InvalidHealth
    if not 0 <= value <= 100 or not math.isfinite(value):
        raise _InvalidHealth
    return value


def _project(payload: dict[str, object]) -> dict[str, object]:
    status = _enum(payload["status"], _HEALTH_STATES)
    readiness = _mapping(payload["readiness"])
    if _enum(readiness["status"], _HEALTH_STATES) != status:
        raise _InvalidHealth
    raw_checks = _mapping(readiness["checks"])
    checks: dict[str, object] = {}
    check_statuses: list[str] = []
    for name in (
        "state_db",
        "session_store",
        "config",
        "model",
        "disk",
        "gateway",
        "background_queues",
    ):
        raw = _mapping(raw_checks[name])
        allowed = _SESSION_STATES if name == "session_store" else _HEALTH_STATES
        if name == "background_queues":
            allowed = frozenset({"ok"})
        check_status = _enum(raw["status"], allowed)
        check_statuses.append(check_status)
        projected: dict[str, object] = {"status": check_status}
        if name == "disk":
            if "used_percent" in raw:
                projected["used_percent"] = _percentage(raw["used_percent"])
            if "free_bytes" in raw:
                projected["free_bytes"] = _count(raw["free_bytes"])
        elif name == "gateway":
            projected["state"] = _enum(raw["state"], GATEWAY_STATES)
            connected = _count(raw["connected_platforms"])
            platforms = _count(raw["platforms"])
            if connected > platforms:
                raise _InvalidHealth
            projected.update(connected_platforms=connected, platforms=platforms)
        elif name == "background_queues":
            for field in ("active_api_runs", "process_completions", "active_delegations"):
                projected[field] = _count(raw[field])
        checks[name] = projected
    if (status == "ok") != all(item == "ok" for item in check_statuses):
        raise _InvalidHealth
    gateway_state = payload["gateway_state"]
    if gateway_state is None:
        gateway_state = "unknown"
    return {
        "status": status,
        "version": HERMES_VERSION,
        "pid": _count(payload["pid"], positive=True),
        "gateway_state": _enum(gateway_state, GATEWAY_STATES),
        "active_agents": _count(payload["active_agents"]),
        "gateway_busy": _boolean(payload["gateway_busy"]),
        "gateway_drainable": _boolean(payload["gateway_drainable"]),
        "readiness": {"status": status, "checks": checks},
    }


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidHealth
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise _InvalidHealth


def _validate_headers(response: HTTPResponse) -> None:
    lengths = response.headers.get_all("Content-Length", [])
    if any(re.fullmatch(r"[0-9]+", value) is None for value in lengths):
        raise _InvalidHealth
    if lengths:
        parsed = {int(value) for value in lengths}
        if len(parsed) != 1 or max(parsed) > MAX_HEALTH_RESPONSE_BYTES:
            raise _InvalidHealth
    encodings = response.headers.get_all("Transfer-Encoding", [])
    if encodings and (lengths or encodings != ["chunked"]):
        raise _InvalidHealth
    content_encoding = response.headers.get_all("Content-Encoding", [])
    if content_encoding and content_encoding != ["identity"]:
        raise _InvalidHealth


def probe_gateway_health(
    url: str,
    api_key: str,
    expected_pid: int,
    *,
    timeout_seconds: float = 2.0,
) -> tuple[str, dict[str, object] | None]:
    """Observe one pinned gateway; this never proves provider health or safe shutdown."""
    match = _ENDPOINT.fullmatch(url)
    if match is None or not 1 <= int(match[2]) <= 65535:
        return "invalid_endpoint", None
    if not 16 <= len(api_key) <= 4096 or any(not 33 <= ord(char) <= 126 for char in api_key):
        return "credentials_unavailable", None
    try:
        _count(expected_pid, positive=True)
    except _InvalidHealth:
        return "pid_mismatch", None
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        return "timeout", None
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

    def expire() -> None:
        expired.set()
        if connection is not None:
            # Closing a socket alone does not interrupt its buffered file reads.
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)

    try:
        connection = socket.socket(family, socket.SOCK_STREAM)
        timer = threading.Timer(max(0.0, deadline - time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        # Numeric addresses avoid DNS; direct sockets use no ambient proxy settings.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout", None
        connection.settimeout(remaining)
        connection.connect((address, int(match[2])))
        if expired.is_set() or time.monotonic() >= deadline:
            return "timeout", None
        request = (
            "GET /health/detailed HTTP/1.1\r\n"
            f"Host: {host}:{int(match[2])}\r\n"
            f"Authorization: Bearer {api_key}\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = HTTPResponse(connection, method="GET")
        if not isinstance(response.fp, io.BufferedReader):
            raise _InvalidHealth
        # Reuse the raw socket reader: nesting buffered readers can wait for a
        # full buffer even when a complete fixed-length response has arrived.
        response.fp = _HeaderReader(response.fp.detach())
        response.begin()
        _validate_headers(response)
        if expired.is_set() or time.monotonic() >= deadline:
            return "timeout", None
        if response.status in {401, 403}:
            return "authentication_failed", None
        if response.status == 404:
            return "unsupported_runtime", None
        if response.status != 200:
            return "health_unavailable", None
        # HTTPResponse honors fixed lengths/chunks; the timer also interrupts
        # slow-drip headers, chunk framing, and bodies that defeat idle timeouts.
        body = response.read(MAX_HEALTH_RESPONSE_BYTES + 1)
        if expired.is_set() or time.monotonic() >= deadline:
            return "timeout", None
        if len(body) > MAX_HEALTH_RESPONSE_BYTES or response.length not in {0, None}:
            return "invalid_health", None
        payload = _mapping(
            json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_json_object,
                parse_constant=_reject_constant,
            )
        )
        if not isinstance(payload["platform"], str) or not isinstance(payload["version"], str):
            return "invalid_health", None
        if payload["platform"] != "hermes-agent" or payload["version"] != HERMES_VERSION:
            return "unsupported_runtime", None
        if _count(payload["pid"], positive=True) != expected_pid:
            return "pid_mismatch", None
        projected = _project(payload)
        if expired.is_set() or time.monotonic() >= deadline:
            return "timeout", None
        return str(projected["status"]), projected
    except TimeoutError:
        return "timeout", None
    except OSError:
        if expired.is_set() or time.monotonic() >= deadline:
            return "timeout", None
        return "health_unavailable", None
    except (HTTPException, ValueError, KeyError, RecursionError):
        if expired.is_set() or time.monotonic() >= deadline:
            return "timeout", None
        return "invalid_health", None
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        if response is not None:
            with contextlib.suppress(OSError):
                response.close()
        if connection is not None:
            with contextlib.suppress(OSError):
                connection.close()
