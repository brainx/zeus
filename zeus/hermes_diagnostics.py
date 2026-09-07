from __future__ import annotations

import math
from typing import cast

from .gateway_http import GatewayHTTPError, request_json

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


class _InvalidHealth(ValueError):
    pass


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


def probe_gateway_health(
    url: str,
    api_key: str,
    expected_pid: int,
    *,
    timeout_seconds: float = 2.0,
) -> tuple[str, dict[str, object] | None]:
    """Observe one pinned gateway; this never proves provider health or safe shutdown."""
    try:
        _count(expected_pid, positive=True)
    except _InvalidHealth:
        return "pid_mismatch", None
    try:
        status, payload = request_json(
            url,
            api_key,
            "/health/detailed",
            max_bytes=MAX_HEALTH_RESPONSE_BYTES,
            timeout_seconds=timeout_seconds,
        )
        if status in {401, 403}:
            return "authentication_failed", None
        if status == 404:
            return "unsupported_runtime", None
        if status != 200:
            return "health_unavailable", None
        if payload is None:
            return "invalid_health", None
        if not isinstance(payload["platform"], str) or not isinstance(payload["version"], str):
            return "invalid_health", None
        if payload["platform"] != "hermes-agent" or payload["version"] != HERMES_VERSION:
            return "unsupported_runtime", None
        if _count(payload["pid"], positive=True) != expected_pid:
            return "pid_mismatch", None
        projected = _project(payload)
        return str(projected["status"]), projected
    except GatewayHTTPError as exc:
        reason = {
            "gateway_unavailable": "health_unavailable",
            "invalid_response": "invalid_health",
            "response_too_large": "invalid_health",
            "invalid_request": "invalid_health",
        }.get(exc.code, exc.code)
        return reason, None
    except (ValueError, KeyError, RecursionError):
        return "invalid_health", None
