from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Literal

AuthOutcome = Literal[
    "not_checked",
    "not_required",
    "authenticated",
    "missing",
    "rejected",
    "unconfigured",
    "allowed_unauthenticated",
]
IdempotencyOutcome = Literal[
    "not_applicable",
    "claimed",
    "replayed",
    "conflict",
    "in_progress",
    "indeterminate",
    "unavailable",
]

AUTH_OUTCOMES = frozenset(
    {
        "not_checked",
        "not_required",
        "authenticated",
        "missing",
        "rejected",
        "unconfigured",
        "allowed_unauthenticated",
    }
)
IDEMPOTENCY_OUTCOMES = frozenset(
    {
        "not_applicable",
        "claimed",
        "replayed",
        "conflict",
        "in_progress",
        "indeterminate",
        "unavailable",
    }
)

_STATIC_ROUTE_TEMPLATES = {
    "/health": "/health",
    "/ready": "/ready",
    "/doctor": "/doctor",
    "/templates": "/templates",
    "/bots": "/bots",
    "/bots/reconcile": "/bots/reconcile",
}
_BOT_ACTIONS = frozenset(
    {"history", "inspect", "logs", "reconcile", "restart", "start", "status", "stop"}
)


@dataclass
class RequestContext:
    request_id: str
    started_at: float
    method: str | None = None
    route: str | None = None
    auth_outcome: AuthOutcome = "not_checked"
    idempotency_outcome: IdempotencyOutcome = "not_applicable"

    def finish(self, status: int, error_code: str | None) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "route": self.route,
            "status": status,
            "error_code": error_code,
            "duration_ms": max(0.0, (time.monotonic() - self.started_at) * 1000),
            "auth_outcome": self.auth_outcome,
            "idempotency_outcome": self.idempotency_outcome,
        }


def new_request_id() -> str:
    return uuid.uuid4().hex


def route_template(path: str) -> str | None:
    if path.startswith("/v1/"):
        path = path[3:]
    elif path == "/v1":
        path = "/"

    static_template = _STATIC_ROUTE_TEMPLATES.get(path)
    if static_template is not None:
        return static_template

    parts = path.split("/")
    if (
        len(parts) == 4
        and parts[0] == ""
        and parts[1] == "bots"
        and parts[2]
        and parts[3] in _BOT_ACTIONS
    ):
        return f"/bots/{{bot_id}}/{parts[3]}"
    return None
