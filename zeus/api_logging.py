from __future__ import annotations

import json
import math
import os
import re
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from zeus.request_context import AUTH_OUTCOMES, IDEMPOTENCY_OUTCOMES, route_template

_HTTP_METHODS = frozenset({"GET", "POST", "UNSUPPORTED"})
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_LOWER_HEX = frozenset("0123456789abcdef")
_GENERIC_ERROR_TYPE = "Exception"
_GENERIC_ERROR_MESSAGE = "Unexpected API error"
_SAFE_ERROR_TYPES: dict[type[Exception], str] = {
    AssertionError: "AssertionError",
    KeyError: "KeyError",
    OSError: "OSError",
    RuntimeError: "RuntimeError",
    TimeoutError: "TimeoutError",
    TypeError: "TypeError",
    ValueError: "ValueError",
}


def _is_request_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 32
        and all(character in _LOWER_HEX for character in value)
    )


def _access_payload(fields: Mapping[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {}
    if "request_id" in fields:
        request_id = fields["request_id"]
        if not _is_request_id(request_id):
            raise ValueError("request_id must be lowercase UUID hex")
        payload["request_id"] = request_id

    if "method" in fields:
        method = fields["method"]
        if method is not None and method not in _HTTP_METHODS:
            raise ValueError("method must be an allowed HTTP method or null")
        payload["method"] = method

    if "route" in fields:
        route = fields["route"]
        if route is not None and (not isinstance(route, str) or route_template(route) != route):
            raise ValueError("route must be a normalized route template or null")
        payload["route"] = route

    if "error_code" in fields:
        error_code = fields["error_code"]
        if error_code is not None and (
            not isinstance(error_code, str) or _ERROR_CODE.fullmatch(error_code) is None
        ):
            raise ValueError("error_code must be a lowercase symbolic identifier or null")
        payload["error_code"] = error_code

    if "status" in fields:
        status = fields["status"]
        if isinstance(status, bool) or not isinstance(status, int):
            raise TypeError("status must be an integer")
        payload["status"] = status

    if "duration_ms" in fields:
        duration_ms = fields["duration_ms"]
        if (
            isinstance(duration_ms, bool)
            or not isinstance(duration_ms, int | float)
            or not math.isfinite(duration_ms)
        ):
            raise TypeError("duration_ms must be a finite number")
        payload["duration_ms"] = duration_ms

    if "auth_outcome" in fields:
        auth_outcome = fields["auth_outcome"]
        if auth_outcome not in AUTH_OUTCOMES:
            raise ValueError("auth_outcome must be an allowed value")
        payload["auth_outcome"] = auth_outcome

    if "idempotency_outcome" in fields:
        idempotency_outcome = fields["idempotency_outcome"]
        if idempotency_outcome not in IDEMPOTENCY_OUTCOMES:
            raise ValueError("idempotency_outcome must be an allowed value")
        payload["idempotency_outcome"] = idempotency_outcome

    return payload


class ApiLogWriter:
    def __init__(self, path: Path, *, enabled: bool) -> None:
        self.path = path
        self.enabled = enabled
        self._lock = threading.Lock()

    def access(self, fields: Mapping[str, object]) -> None:
        if not self.enabled:
            return
        try:
            payload: dict[str, object] = {
                "schema_version": 1,
                "ts": datetime.now(UTC).isoformat(),
                "level": "info",
                "event": "api.access",
            }
            payload.update(_access_payload(fields))
            self._write(payload)
        except Exception:
            return

    def error(self, request_id: str, exc: Exception) -> None:
        if not self.enabled:
            return
        try:
            if not _is_request_id(request_id):
                return
            error_type = _SAFE_ERROR_TYPES.get(type(exc), _GENERIC_ERROR_TYPE)
            self._write(
                {
                    "schema_version": 1,
                    "ts": datetime.now(UTC).isoformat(),
                    "level": "error",
                    "event": "api.error",
                    "request_id": request_id,
                    "error_type": error_type,
                    "message": _GENERIC_ERROR_MESSAGE,
                }
            )
        except Exception:
            return

    def _write(self, payload: Mapping[str, object]) -> None:
        if not self.enabled:
            return
        try:
            line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                directory_flags = os.O_RDONLY
                directory_flags |= getattr(os, "O_DIRECTORY", 0)
                directory_flags |= getattr(os, "O_CLOEXEC", 0)
                directory_flags |= getattr(os, "O_NOFOLLOW", 0)
                file_flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
                file_flags |= getattr(os, "O_CLOEXEC", 0)
                file_flags |= getattr(os, "O_NOFOLLOW", 0)
                directory_fd: int | None = None
                file_fd: int | None = None
                try:
                    directory_fd = os.open(self.path.parent, directory_flags)
                    os.fchmod(directory_fd, 0o700)
                    file_fd = os.open(
                        self.path.name,
                        file_flags,
                        0o600,
                        dir_fd=directory_fd,
                    )
                    os.fchmod(file_fd, 0o600)
                    with os.fdopen(file_fd, "a", encoding="utf-8") as handle:
                        file_fd = None
                        handle.write(line)
                finally:
                    try:
                        if file_fd is not None:
                            os.close(file_fd)
                    finally:
                        if directory_fd is not None:
                            os.close(directory_fd)
        except (OSError, TypeError, ValueError):
            return
