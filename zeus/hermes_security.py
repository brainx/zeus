from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_FEISHU_PLATFORM_LOCATIONS = (
    (("platforms",), "platforms.feishu.extra.connection_mode"),
    (("gateway", "platforms"), "gateway.platforms.feishu.extra.connection_mode"),
    (("gateway",), "gateway.feishu.extra.connection_mode"),
)


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

    modes = _root_feishu_connection_modes(config)
    modes.extend(_feishu_connection_modes(config))
    for field, mode in modes:
        if _uses_environment_interpolation(mode):
            raise UnsupportedFeishuWebhookModeError(
                "Feishu connection mode interpolation is unsupported; set "
                f"{field} directly to WebSocket"
            )
        if _is_webhook(mode):
            raise UnsupportedFeishuWebhookModeError(
                "Feishu webhook mode is unsupported with Hermes 0.20; remove "
                f"{field} or set it to WebSocket"
            )


def _nested_value(value: Mapping[str, Any], *path: str) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _root_feishu_connection_modes(config: Mapping[str, Any]) -> list[tuple[str, Any]]:
    matches = [
        value
        for key, value in config.items()
        if isinstance(key, str) and key.strip().casefold() == "feishu_connection_mode"
    ]
    if len(matches) > 1:
        raise UnsupportedFeishuWebhookModeError(
            "Feishu connection mode configuration is ambiguous; set "
            "FEISHU_CONNECTION_MODE only once"
        )
    return [("FEISHU_CONNECTION_MODE", matches[0])] if matches else []


def _feishu_connection_modes(config: Mapping[str, Any]) -> list[tuple[str, Any]]:
    modes: list[tuple[str, Any]] = []
    for location, field in _FEISHU_PLATFORM_LOCATIONS:
        platform_map = _nested_value(config, *location)
        if not isinstance(platform_map, Mapping):
            continue
        matches = [
            value
            for key, value in platform_map.items()
            if isinstance(key, str) and key.strip().casefold() == "feishu"
        ]
        if len(matches) > 1:
            raise UnsupportedFeishuWebhookModeError(
                f"Feishu platform configuration is ambiguous; set {field} only once"
            )
        if matches:
            value = matches[0]
            mode = (
                _nested_value(value, "extra", "connection_mode")
                if isinstance(value, Mapping)
                else None
            )
            modes.append((field, mode))
    return modes


def _is_webhook(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "webhook"


def _uses_environment_interpolation(value: Any) -> bool:
    return isinstance(value, str) and "${" in value
