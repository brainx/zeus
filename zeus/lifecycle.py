from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType

from zeus.logging_utils import redact_secrets

MAX_DETAILS_JSON_LENGTH = 8192
MAX_DETAIL_DEPTH = 4
MAX_DETAIL_ITEMS = 32
MAX_DETAIL_STRING_LENGTH = 2048
MAX_EVENT_TEXT_LENGTH = 2048

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


def _safe_text(value: str, *, maximum: int = MAX_EVENT_TEXT_LENGTH) -> str:
    return redact_secrets(value)[:maximum]


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


def _safe_detail_value(key: str, value: object, *, depth: int) -> object:
    if _is_forbidden_detail_name(key):
        return "[redacted]"
    if depth >= MAX_DETAIL_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _safe_text(value, maximum=MAX_DETAIL_STRING_LENGTH)
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for raw_child_key, child_value in list(value.items())[:MAX_DETAIL_ITEMS]:
            child_key = _safe_text(str(raw_child_key), maximum=128)
            result[child_key] = _safe_detail_value(
                child_key,
                child_value,
                depth=depth + 1,
            )
        return result
    if isinstance(value, list | tuple):
        return [_safe_detail_value(key, item, depth=depth + 1) for item in value[:MAX_DETAIL_ITEMS]]
    return "[unsupported]"


def safe_lifecycle_details(details: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for raw_key, value in list(details.items())[:MAX_DETAIL_ITEMS]:
        key = _safe_text(str(raw_key), maximum=128)
        result[key] = _safe_detail_value(key, value, depth=0)
    if len(json.dumps(result, sort_keys=True, separators=(",", ":"))) > MAX_DETAILS_JSON_LENGTH:
        return {"truncated": True}
    return result


def _freeze_detail_value(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_detail_value(child_value) for key, child_value in value.items()}
        )
    if isinstance(value, list | tuple):
        return tuple(_freeze_detail_value(child_value) for child_value in value)
    return value


def freeze_lifecycle_details(details: Mapping[str, object]) -> Mapping[str, object]:
    frozen = _freeze_detail_value(safe_lifecycle_details(details))
    if not isinstance(frozen, Mapping):
        raise TypeError("lifecycle event details must be a mapping")
    return frozen


def _thaw_detail_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_detail_value(child_value) for key, child_value in value.items()}
    if isinstance(value, list | tuple):
        return [_thaw_detail_value(child_value) for child_value in value]
    return value


def thaw_lifecycle_details(details: Mapping[str, object]) -> dict[str, object]:
    return {str(key): _thaw_detail_value(value) for key, value in details.items()}


def serialize_lifecycle_details(details: Mapping[str, object]) -> str:
    return json.dumps(
        thaw_lifecycle_details(safe_lifecycle_details(details)),
        sort_keys=True,
        separators=(",", ":"),
    )


def deserialize_lifecycle_details(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("lifecycle event details must be a JSON object")
    return safe_lifecycle_details(parsed)


@dataclass(frozen=True)
class LifecycleEventInput:
    bot_id: str
    operation_id: str
    source: str
    action: str
    outcome: str
    request_id: str | None = None
    reason: str = ""
    error_code: str | None = None
    error_message: str | None = None
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _safe_text(self.reason))
        if self.error_message is not None:
            object.__setattr__(self, "error_message", _safe_text(self.error_message))
        object.__setattr__(self, "details", freeze_lifecycle_details(self.details))


@dataclass(frozen=True)
class LifecycleEvent:
    event_id: int
    bot_id: str
    operation_id: str
    request_id: str | None
    occurred_at: datetime
    source: str
    action: str
    outcome: str
    status_before: str | None
    status_after: str | None
    pid_before: int | None
    pid_after: int | None
    reason: str
    error_code: str | None
    error_message: str | None
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _safe_text(self.reason))
        if self.error_message is not None:
            object.__setattr__(self, "error_message", _safe_text(self.error_message))
        object.__setattr__(self, "details", freeze_lifecycle_details(self.details))

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "bot_id": self.bot_id,
            "operation_id": self.operation_id,
            "request_id": self.request_id,
            "occurred_at": self.occurred_at.isoformat(),
            "source": self.source,
            "action": self.action,
            "outcome": self.outcome,
            "status_before": self.status_before,
            "status_after": self.status_after,
            "pid_before": self.pid_before,
            "pid_after": self.pid_after,
            "reason": self.reason,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "details": thaw_lifecycle_details(self.details),
        }
