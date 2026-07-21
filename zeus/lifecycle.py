from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType

from zeus.sanitization import JSONValue, sanitize_details, sanitize_text

MAX_EVENT_TEXT_LENGTH = 2048


def _safe_text(value: str, *, maximum: int = MAX_EVENT_TEXT_LENGTH) -> str:
    return sanitize_text(value, max_length=maximum)


def safe_lifecycle_details(details: Mapping[str, object]) -> dict[str, JSONValue]:
    result = sanitize_details(details)
    if type(result) is not dict:
        raise TypeError("lifecycle event details must be a mapping")
    return result


def _freeze_detail_value(value: JSONValue) -> object:
    if type(value) is dict:
        return MappingProxyType(
            {key: _freeze_detail_value(child_value) for key, child_value in value.items()}
        )
    if type(value) is list:
        return tuple(_freeze_detail_value(child_value) for child_value in value)
    return value


def freeze_lifecycle_details(details: Mapping[str, object]) -> Mapping[str, object]:
    frozen = _freeze_detail_value(safe_lifecycle_details(details))
    if not isinstance(frozen, Mapping):
        raise TypeError("lifecycle event details must be a mapping")
    return frozen


def thaw_lifecycle_details(details: Mapping[str, object]) -> dict[str, JSONValue]:
    return safe_lifecycle_details(details)


def serialize_lifecycle_details(details: Mapping[str, object]) -> str:
    return json.dumps(
        safe_lifecycle_details(details),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def deserialize_lifecycle_details(value: str) -> dict[str, JSONValue]:
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
