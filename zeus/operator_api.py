"""Read-only operator routes; callers must authenticate before dispatch."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from zeus.api_request import parse_query
from zeus.bot_diagnostics import diagnose_bot
from zeus.fleet_overview import FleetOverviewReader
from zeus.reconcile_history import ReconcileHistoryReader
from zeus.state import StateReadinessError

if TYPE_CHECKING:
    from zeus.supervisor import Supervisor


def is_operator_path(path: str) -> bool:
    return (
        path == "/fleet"
        or path == "/reconcile/runs"
        or path.startswith("/reconcile/runs/")
        or (path.startswith("/bots/") and path.endswith("/diagnostics"))
    )


def _integer(value: str | None, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError("pagination parameters must be integers") from exc


def _error(status: HTTPStatus, code: str, message: str) -> tuple[HTTPStatus, dict[str, Any]]:
    return status, {"error": {"code": code, "message": message, "status": status.value}}


def operator_response(
    path: str, target: str, supervisor: Supervisor
) -> tuple[HTTPStatus, dict[str, Any]]:
    if path.startswith("/bots/") and path.endswith("/diagnostics"):
        parse_query(target, frozenset())
        parts = path.split("/")
        if len(parts) != 4 or not parts[2]:
            raise ValueError("invalid bot diagnostics route")
        try:
            bot_id = unquote(parts[2], errors="strict")
        except UnicodeError as exc:
            raise ValueError("invalid bot identifier") from exc
        try:
            return HTTPStatus.OK, diagnose_bot(supervisor, bot_id)
        except StateReadinessError:
            return _error(HTTPStatus.SERVICE_UNAVAILABLE, "not_ready", "bot state is unavailable")
    database_path = supervisor.store.database_path
    if path == "/fleet":
        allowed = {"limit", "after", "attention_only", "stale_after_seconds"}
    elif path == "/reconcile/runs":
        allowed = {"limit", "before", "outcome", "bot_id"}
    else:
        allowed = {"limit", "after"}
    query = {name: values[0] for name, values in parse_query(target, frozenset(allowed)).items()}
    limit = _integer(query.get("limit"))
    if limit is None:
        limit = 50
    try:
        if path == "/fleet":
            attention = query.get("attention_only", "false").lower()
            if attention not in {"true", "false", "1", "0"}:
                raise ValueError("attention_only must be true, false, 1, or 0")
            try:
                stale = float(query.get("stale_after_seconds", "120"))
            except ValueError as exc:
                raise ValueError("stale_after_seconds must be a number") from exc
            payload = FleetOverviewReader(database_path).overview(
                limit=limit,
                after=query.get("after"),
                attention_only=attention in {"true", "1"},
                stale_after_seconds=stale,
            )
        elif path == "/reconcile/runs":
            payload = ReconcileHistoryReader(database_path).list_runs(
                limit=limit,
                before=query.get("before"),
                outcome=query.get("outcome"),
                bot_id=query.get("bot_id"),
            )
        else:
            parts = path.split("/")
            if len(parts) != 4 or not parts[-1]:
                raise ValueError("invalid reconciliation run route")
            try:
                run_id = unquote(parts[-1], errors="strict")
            except UnicodeError as exc:
                raise ValueError("invalid reconciliation run identifier") from exc
            result = ReconcileHistoryReader(database_path).get_run(
                run_id, limit=limit, after=_integer(query.get("after"))
            )
            if result is None:
                return _error(
                    HTTPStatus.NOT_FOUND, "unknown_reconcile_run", "unknown reconciliation run"
                )
            payload = result
    except StateReadinessError:
        return _error(
            HTTPStatus.SERVICE_UNAVAILABLE, "not_ready", "operator evidence is unavailable"
        )
    return HTTPStatus.OK, payload
