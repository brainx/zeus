from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class UnsupportedFeishuWebhookModeError(ValueError):
    """Raised when a Zeus-managed Hermes profile enables unsafe Feishu webhooks."""


def validate_hermes_profile_security(
    config: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> None:
    """Reject Hermes Feishu webhook mode at every Zeus-managed profile boundary."""
    if _is_webhook(environment.get("FEISHU_CONNECTION_MODE")):
        raise UnsupportedFeishuWebhookModeError(
            "Feishu webhook mode is unsupported with Hermes 0.20; remove "
            "FEISHU_CONNECTION_MODE or set it to WebSocket"
        )

    mode = _nested_value(
        config,
        "platforms",
        "feishu",
        "extra",
        "connection_mode",
    )
    if _is_webhook(mode):
        raise UnsupportedFeishuWebhookModeError(
            "Feishu webhook mode is unsupported with Hermes 0.20; remove "
            "platforms.feishu.extra.connection_mode or set it to WebSocket"
        )


def _nested_value(value: Mapping[str, Any], *path: str) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _is_webhook(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "webhook"
