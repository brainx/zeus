from __future__ import annotations

import json
import math
import re
from types import MappingProxyType
from typing import TypeAlias

JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

MAX_SANITIZED_JSON_BYTES = 8192
MAX_DETAIL_KEY_LENGTH = 128
MAX_EVENT_TEXT_LENGTH = 2048

REDACTED_VALUE = "[redacted]"
TRUNCATED_VALUE = "[truncated]"
CYCLE_VALUE = "[cycle]"
UNSUPPORTED_VALUE = "[unsupported]"

_CAMEL_ACRONYM_BOUNDARY_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_WORD_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_NON_NAME_CHARACTER_RE = re.compile(r"[^a-z0-9]+")
_SECRET_NAME_PARTS = frozenset({"apikey", "key", "token", "secret", "password"})
_FORBIDDEN_DETAIL_NAMES = frozenset(
    {
        "authorization",
        "authorization_header",
        "authorization_headers",
        "header",
        "headers",
        "request_body",
        "response_body",
        "body",
        "raw_query",
        "query_string",
        "query",
        "forwarded_for",
        "x_forwarded_for",
        "client_address",
        "client_ip",
        "client_port",
        "remote_addr",
        "traceback",
        "exception_trace",
        "idempotency_key",
    }
)

_SECRET_KV_RE = re.compile(
    r"""(?ix)
    (?P<prefix>["']?)
    (?P<name>
        [A-Z0-9_.-]*(?:API[_-]?KEY|KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_.-]*
        | AUTHORIZATION
    )
    (?P=prefix)
    (?P<sep>\s*[:=]\s*)
    (?P<value>
        "(?:[^"\\]|\\.)*" |
        '(?:[^'\\]|\\.)*' |
        [^\s,}]+
    )
    """
)
_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]+)")


def redact_secrets(text: str) -> str:
    """Redact common secret assignments and bearer credentials from free text."""

    redacted = _BEARER_RE.sub(r"\1[redacted]", text)
    return _SECRET_KV_RE.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('name')}{match.group('prefix')}"
            f"{match.group('sep')}[redacted]"
        ),
        redacted,
    )


def sanitize_text(value: str, *, max_length: int = MAX_EVENT_TEXT_LENGTH) -> str:
    """Return bounded, redacted text without coercing non-string objects."""

    if type(value) is not str:
        return UNSUPPORTED_VALUE
    if type(max_length) is not int or max_length < 0:
        raise ValueError("max_length must be a non-negative integer")
    return redact_secrets(value[:max_length])[:max_length]


def _normalize_detail_name(key: str) -> str:
    separated = _CAMEL_ACRONYM_BOUNDARY_RE.sub(r"\1_\2", key)
    separated = _CAMEL_WORD_BOUNDARY_RE.sub(r"\1_\2", separated).lower()
    return _NON_NAME_CHARACTER_RE.sub("_", separated).strip("_")


def _contains_name(normalized: str, candidate: str) -> bool:
    return f"_{candidate}_" in f"_{normalized}_"


def _is_forbidden_detail_name(key: str) -> bool:
    normalized = _normalize_detail_name(key)
    if any(_contains_name(normalized, name) for name in _FORBIDDEN_DETAIL_NAMES):
        return True
    return any(_contains_name(normalized, part) for part in _SECRET_NAME_PARTS)


def _sanitize_key(value: object, *, max_length: int) -> str | None:
    if type(value) is str:
        return sanitize_text(value, max_length=max_length)
    if type(value) is int:
        try:
            return str(value)[:max_length]
        except ValueError:
            return None
    if type(value) is float and math.isfinite(value):
        return str(value)[:max_length]
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    return None


class _SanitizationState:
    def __init__(
        self,
        *,
        max_depth: int,
        max_items: int,
        max_string_length: int,
    ) -> None:
        self.max_depth = max_depth
        self.remaining_items = max_items
        self.max_string_length = max_string_length
        self.active_container_ids: set[int] = set()

    def consume_item(self) -> bool:
        if self.remaining_items <= 0:
            return False
        self.remaining_items -= 1
        return True


def _sanitize_value(
    value: object,
    *,
    state: _SanitizationState,
    depth: int,
    key: str | None,
) -> JSONValue:
    if key is not None and _is_forbidden_detail_name(key):
        return REDACTED_VALUE
    if value is None:
        return None
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        return value if math.isfinite(value) else None
    if type(value) is str:
        return sanitize_text(value, max_length=state.max_string_length)

    if type(value) is dict or type(value) is MappingProxyType:
        if depth >= state.max_depth:
            return TRUNCATED_VALUE
        container_id = id(value)
        if container_id in state.active_container_ids:
            return CYCLE_VALUE
        state.active_container_ids.add(container_id)
        try:
            result: dict[str, JSONValue] = {}
            for raw_key, child_value in value.items():
                if not state.consume_item():
                    break
                child_key = _sanitize_key(raw_key, max_length=MAX_DETAIL_KEY_LENGTH)
                if child_key is None:
                    continue
                if type(raw_key) is str and len(raw_key) > MAX_DETAIL_KEY_LENGTH:
                    result[child_key] = REDACTED_VALUE
                else:
                    result[child_key] = _sanitize_value(
                        child_value,
                        state=state,
                        depth=depth + 1,
                        key=child_key,
                    )
            return result
        finally:
            state.active_container_ids.remove(container_id)

    if type(value) is list or type(value) is tuple:
        if depth >= state.max_depth:
            return TRUNCATED_VALUE
        container_id = id(value)
        if container_id in state.active_container_ids:
            return CYCLE_VALUE
        state.active_container_ids.add(container_id)
        try:
            result_list: list[JSONValue] = []
            for child_value in value:
                if not state.consume_item():
                    break
                result_list.append(
                    _sanitize_value(
                        child_value,
                        state=state,
                        depth=depth + 1,
                        key=key,
                    )
                )
            return result_list
        finally:
            state.active_container_ids.remove(container_id)

    return UNSUPPORTED_VALUE


def _validate_limit(value: int, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _canonical_json_bytes(value: JSONValue) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sanitize_details(
    value: object,
    *,
    max_depth: int = 6,
    max_items: int = 64,
    max_string_length: int = 2048,
) -> JSONValue:
    """Produce a bounded JSON value without invoking arbitrary conversions."""

    state = _SanitizationState(
        max_depth=_validate_limit(max_depth, "max_depth"),
        max_items=_validate_limit(max_items, "max_items"),
        max_string_length=_validate_limit(max_string_length, "max_string_length"),
    )
    sanitized = _sanitize_value(value, state=state, depth=0, key=None)
    try:
        if len(_canonical_json_bytes(sanitized)) <= MAX_SANITIZED_JSON_BYTES:
            return sanitized
    except (TypeError, ValueError, RecursionError, UnicodeError):
        pass
    if type(sanitized) is dict:
        return {"truncated": True}
    return TRUNCATED_VALUE
