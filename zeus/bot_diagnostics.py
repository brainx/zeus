from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime

from zeus.gateway_marker import GatewayGeneration, parse_runtime_marker
from zeus.hermes_diagnostics import probe_gateway_health
from zeus.models import BotRecord, validate_id
from zeus.process_identity import PidState
from zeus.readiness import ReadinessProbe
from zeus.schema import _assert_schema_current
from zeus.sqlite_db import StateReadinessError
from zeus.supervisor import Supervisor


def _read_record(supervisor: Supervisor, bot_id: str) -> BotRecord | None:
    try:
        uri = f"{supervisor.store.database_path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            _assert_schema_current(conn)
            row = conn.execute("SELECT * FROM bots WHERE bot_id = ?", (bot_id,)).fetchone()
            return supervisor.store._bot_lifecycle._row_to_record(row) if row is not None else None
    except (sqlite3.Error, OSError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
        raise StateReadinessError("bot diagnostics state is unavailable") from exc


def _pending(record: BotRecord) -> bool:
    return any(
        value is not None
        for value in (record.pending_operation_id, record.pending_action, record.pending_since)
    )


def _record_identity(record: BotRecord) -> tuple[object, ...]:
    return (
        record.bot_id,
        record.created_at,
        record.profile_path,
        record.pid,
        record.status,
        record.desired_state,
        record.desired_revision,
        record.desired_updated_at,
        record.started_at,
        record.stopped_at,
        record.pending_operation_id,
        record.pending_action,
        record.pending_since,
    )


def _capture_runtime(
    supervisor: Supervisor, record: BotRecord
) -> tuple[GatewayGeneration, ReadinessProbe | None] | None:
    runtime = supervisor._runtime
    observed = runtime.read_strict_runtime_marker(record.bot_id, record.profile_path)
    payload = observed.payload
    if observed.kind != "present" or payload is None:
        return None
    classified = runtime.classify_schema3_runtime_marker(
        record,
        payload,
        expected_pid=record.pid,
        expected_revision=record.desired_revision,
        require_live_command=True,
    )
    if classified.kind != "live":
        return None
    marker = parse_runtime_marker(payload)
    return marker.generation(), marker.readiness_probe


def diagnose_bot(supervisor: Supervisor, bot_id: str) -> dict[str, object]:
    """Observe one owned gateway without changing persisted lifecycle state."""
    validate_id(bot_id, "bot_id")
    record = _read_record(supervisor, bot_id)
    if record is None:
        raise KeyError(f"unknown bot: {bot_id}")
    pid = record.pid if type(record.pid) is int and record.pid > 0 else None

    def report(
        status: str,
        reason: str,
        *,
        verified: bool = False,
        health: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "bot_id": bot_id,
            "observed_at": datetime.now(UTC).isoformat(),
            "status": status,
            "reason": reason,
            "process": {"pid": pid, "verified": verified},
            "health": health,
        }

    if _pending(record):
        return report("unverified", "operation_pending")
    if record.pid is None:
        return report("not_running", "not_running")
    if pid is None:
        return report("unverified", "process_unverified")
    try:
        if supervisor._runtime.pid_state(pid) is PidState.dead:
            return report("not_running", "not_running")
        captured = _capture_runtime(supervisor, record)
    except (OSError, TypeError, ValueError):
        captured = None
    if captured is None:
        return report("unverified", "process_unverified")
    _generation, probe = captured
    if probe is None:
        return report("not_configured", "probe_not_configured", verified=True)
    try:
        _argv, env = supervisor.adapter.command(bot_id, "gateway", "run")
    except (OSError, TypeError, ValueError):
        return report("unavailable", "configuration_invalid", verified=True)
    api_key = env.get("API_SERVER_KEY")
    if not api_key:
        return report("unavailable", "credentials_unavailable", verified=True)
    try:
        reason, health = probe_gateway_health(probe.url, api_key=api_key, expected_pid=pid)
    except (OSError, TypeError, ValueError):
        reason, health = "health_unavailable", None

    # No lock spans the network request. Only retain health while both the
    # database identity and the launch-time endpoint still belong to this PID.
    try:
        current = _read_record(supervisor, bot_id)
        unchanged = (
            current is not None
            and _record_identity(current) == _record_identity(record)
            and not _pending(current)
            and _capture_runtime(supervisor, current) == captured
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        unchanged = False
    if not unchanged:
        return report("unverified", "runtime_changed")
    if health is not None and reason in {"ok", "degraded"}:
        return report(reason, reason, verified=True, health=health)
    return report("unavailable", reason, verified=True)
