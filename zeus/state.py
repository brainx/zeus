from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from zeus.idempotency import IdempotencyClaim
from zeus.idempotency_store import IDEMPOTENCY_HASH_RE as IDEMPOTENCY_HASH_RE
from zeus.idempotency_store import IDEMPOTENCY_OWNER_RE as IDEMPOTENCY_OWNER_RE
from zeus.idempotency_store import MAX_IDEMPOTENCY_RESPONSE_BYTES as MAX_IDEMPOTENCY_RESPONSE_BYTES
from zeus.idempotency_store import IdempotencyStore
from zeus.lifecycle import (
    LifecycleEvent,
    LifecycleEventInput,
    deserialize_lifecycle_details,
    serialize_lifecycle_details,
)
from zeus.models import BotRecord, BotStatus, DesiredState, RestartPolicy
from zeus.private_io import append_private_bytes, nofollow_absolute_path
from zeus.reconcile_store import RECONCILE_COUNTER_COLUMNS as RECONCILE_COUNTER_COLUMNS
from zeus.reconcile_store import ReconcileStore
from zeus.reconciliation import (
    BotReconcileResult,
    PersistedReconcileRun,
    ReconcileRunStart,
    ReconcileRunSummary,
)
from zeus.sanitization import MAX_SANITIZED_JSON_BYTES, sanitize_details, sanitize_text
from zeus.schema import SCHEMA_VERSION as SCHEMA_VERSION
from zeus.schema import SchemaManager
from zeus.sqlite_db import SQLiteDatabase

LIFECYCLE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
LIFECYCLE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
LIFECYCLE_SOURCES = frozenset({"api", "cli", "migration", "reconcile", "recovery", "system"})
LIFECYCLE_INTENT_ACTIONS = frozenset({"start", "stop", "restart"})


def _sanitize_optional_persisted_text(value: str | None) -> str | None:
    if value is None:
        return None
    return sanitize_text(value)


class StateStore:
    def __init__(self, database_path: Path | str) -> None:
        self._database = SQLiteDatabase(database_path)
        self._schema = SchemaManager(self._database)
        self._idempotency = IdempotencyStore(self._database)
        self._reconcile = ReconcileStore(self._database)

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def connect(self) -> sqlite3.Connection:
        return self._database.connect()

    def init(self) -> None:
        self._schema.init()

    def migrate(self) -> None:
        self._schema.migrate()

    def claim_idempotency(
        self,
        *,
        key_hash: str,
        request_hash: str,
        owner_instance_id: str,
        expires_at: datetime,
        max_records: int = 10_000,
    ) -> IdempotencyClaim:
        return self._idempotency.claim_idempotency(
            key_hash=key_hash,
            request_hash=request_hash,
            owner_instance_id=owner_instance_id,
            expires_at=expires_at,
            max_records=max_records,
        )

    def lookup_idempotency(
        self,
        *,
        key_hash: str,
        request_hash: str,
        owner_instance_id: str,
    ) -> IdempotencyClaim | None:
        return self._idempotency.lookup_idempotency(
            key_hash=key_hash,
            request_hash=request_hash,
            owner_instance_id=owner_instance_id,
        )

    def complete_idempotency(
        self,
        *,
        key_hash: str,
        request_hash: str,
        owner_instance_id: str,
        response_status: int,
        response_json: str,
        completed_at: datetime,
        expires_at: datetime,
    ) -> None:
        self._idempotency.complete_idempotency(
            key_hash=key_hash,
            request_hash=request_hash,
            owner_instance_id=owner_instance_id,
            response_status=response_status,
            response_json=response_json,
            completed_at=completed_at,
            expires_at=expires_at,
        )

    def begin_reconcile_run(self, run: ReconcileRunStart) -> None:
        self._reconcile.begin_reconcile_run(run)

    def append_reconcile_result(
        self,
        run_id: str,
        result: BotReconcileResult,
    ) -> None:
        self._reconcile.append_reconcile_result(run_id, result)

    def finish_reconcile_run(
        self,
        summary: ReconcileRunSummary,
    ) -> PersistedReconcileRun:
        return self._reconcile.finish_reconcile_run(summary)

    def interrupt_stale_reconcile_runs(self, *, interrupted_at: datetime) -> int:
        return self._reconcile.interrupt_stale_reconcile_runs(interrupted_at=interrupted_at)

    def get_reconcile_run(self, run_id: str) -> PersistedReconcileRun | None:
        return self._reconcile.get_reconcile_run(run_id)

    def begin_lifecycle_intent(
        self,
        bot_id: str,
        *,
        action: str,
        operation_id: str,
        source: str,
        request_id: str | None = None,
        reason: str = "",
    ) -> BotRecord:
        self._validate_intent_action(action)
        desired_state = DesiredState.stopped if action == "stop" else DesiredState.running
        event = LifecycleEventInput(
            bot_id=bot_id,
            operation_id=operation_id,
            source=source,
            action=f"bot.{action}.intent",
            outcome="pending",
            request_id=request_id,
            reason=reason,
            details={"action": action, "desired_state": desired_state.value},
        )
        self._validate_event_target(bot_id, event)
        now = datetime.now(UTC)
        now_text = now.isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                if prior_row["pending_operation_id"] is not None:
                    raise RuntimeError("bot already has a pending lifecycle intent")
                desired_revision = int(prior_row["desired_revision"]) + 1
                cursor = conn.execute(
                    """
                    UPDATE bots
                    SET desired_state = ?,
                        desired_revision = ?,
                        desired_updated_at = ?,
                        pending_operation_id = ?,
                        pending_action = ?,
                        pending_since = ?,
                        updated_at = ?
                    WHERE bot_id = ? AND pending_operation_id IS NULL
                    """,
                    (
                        desired_state.value,
                        desired_revision,
                        now_text,
                        operation_id,
                        action,
                        now_text,
                        now_text,
                        bot_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("lifecycle intent could not be started")
                event = LifecycleEventInput(
                    bot_id=bot_id,
                    operation_id=operation_id,
                    source=source,
                    action=f"bot.{action}.intent",
                    outcome="pending",
                    request_id=request_id,
                    reason=reason,
                    details={
                        "action": action,
                        "desired_state": desired_state.value,
                        "desired_revision": desired_revision,
                    },
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=str(prior_row["status"]),
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored_event = self._materialize_lifecycle_event(conn, event_id)
                record = self._record_in_transaction(conn, bot_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored_event)
        return record

    def complete_lifecycle_intent(
        self,
        bot_id: str,
        *,
        action: str,
        operation_id: str,
        desired_revision: int,
        status: BotStatus,
        pid: int | None,
        source: str,
        outcome: Literal["success", "failure"] = "success",
        request_id: str | None = None,
        reason: str = "",
        error_code: str | None = None,
        error_message: str | None = None,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
    ) -> BotRecord:
        self._validate_intent_action(action)
        self._validate_intent_revision(desired_revision)
        self._validate_intent_correlation(bot_id, operation_id, source, request_id)
        self._validate_intent_completion(
            action,
            outcome=outcome,
            status=status,
            pid=pid,
            error_code=error_code,
            error_message=error_message,
        )
        desired_state = DesiredState.stopped if action == "stop" else DesiredState.running
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._require_matching_intent(
                    prior_row,
                    action,
                    operation_id,
                    desired_revision,
                )
                self._update_lifecycle_row(
                    conn,
                    bot_id,
                    status,
                    pid,
                    started_at=started_at,
                    ready_at=ready_at,
                    stopped_at=stopped_at,
                    last_exit_code=last_exit_code,
                    last_error=last_error,
                    last_transition_reason=last_transition_reason,
                    reset_restart=reset_restart,
                    clear_ready_at=clear_ready_at,
                    clear_stopped_at=clear_stopped_at,
                    now=now,
                )
                cursor = conn.execute(
                    """
                    UPDATE bots
                    SET pending_operation_id = NULL,
                        pending_action = NULL,
                        pending_since = NULL
                    WHERE bot_id = ?
                      AND pending_operation_id = ?
                      AND pending_action = ?
                      AND desired_revision = ?
                      AND desired_state = ?
                    """,
                    (bot_id, operation_id, action, desired_revision, desired_state.value),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("pending lifecycle intent does not match")
                event = LifecycleEventInput(
                    bot_id=bot_id,
                    operation_id=operation_id,
                    source=source,
                    action=f"bot.{action}.complete",
                    outcome=outcome,
                    request_id=request_id,
                    reason=reason,
                    error_code=error_code,
                    error_message=error_message,
                    details={
                        "action": action,
                        "desired_revision": desired_revision,
                    },
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=status.value,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored_event = self._materialize_lifecycle_event(conn, event_id)
                record = self._record_in_transaction(conn, bot_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored_event)
        return record

    def clear_stale_intent(
        self,
        bot_id: str,
        *,
        action: str,
        operation_id: str,
        desired_revision: int,
        source: str,
        reason: str,
        request_id: str | None = None,
    ) -> BotRecord:
        self._validate_intent_action(action)
        self._validate_intent_revision(desired_revision)
        self._validate_intent_correlation(bot_id, operation_id, source, request_id)
        desired_state = DesiredState.stopped if action == "stop" else DesiredState.running
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._require_matching_intent(
                    prior_row,
                    action,
                    operation_id,
                    desired_revision,
                )
                cursor = conn.execute(
                    """
                    UPDATE bots
                    SET pending_operation_id = NULL,
                        pending_action = NULL,
                        pending_since = NULL,
                        updated_at = ?
                    WHERE bot_id = ?
                      AND pending_operation_id = ?
                      AND pending_action = ?
                      AND desired_revision = ?
                      AND desired_state = ?
                    """,
                    (
                        now,
                        bot_id,
                        operation_id,
                        action,
                        desired_revision,
                        desired_state.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("pending lifecycle intent does not match")
                event = LifecycleEventInput(
                    bot_id=bot_id,
                    operation_id=operation_id,
                    source=source,
                    action=f"bot.{action}.intent.clear",
                    outcome="cleared",
                    request_id=request_id,
                    reason=reason,
                    details={
                        "action": action,
                        "desired_revision": desired_revision,
                    },
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=str(prior_row["status"]),
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored_event = self._materialize_lifecycle_event(conn, event_id)
                record = self._record_in_transaction(conn, bot_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored_event)
        return record

    def _validate_intent_action(self, action: str) -> None:
        if type(action) is not str or action not in LIFECYCLE_INTENT_ACTIONS:
            raise ValueError("invalid lifecycle intent action")

    def _validate_intent_completion(
        self,
        action: str,
        *,
        outcome: Literal["success", "failure"],
        status: BotStatus,
        pid: int | None,
        error_code: str | None,
        error_message: str | None,
    ) -> None:
        if outcome not in {"success", "failure"}:
            raise ValueError("invalid lifecycle intent outcome")
        if not isinstance(status, BotStatus):
            raise TypeError("lifecycle intent status must be a BotStatus")
        if pid is not None and (type(pid) is not int or pid <= 0):
            raise ValueError("lifecycle intent terminal state has an invalid PID")
        if error_code is not None and (
            type(error_code) is not str or LIFECYCLE_ERROR_CODE_RE.fullmatch(error_code) is None
        ):
            raise ValueError("invalid lifecycle intent error code")
        if error_message is not None and type(error_message) is not str:
            raise TypeError("lifecycle intent error message must be a string")
        if outcome == "success":
            if error_code is not None or error_message is not None:
                raise ValueError("successful lifecycle intent cannot include error metadata")
            if action == "stop":
                compatible = status is BotStatus.stopped and pid is None
            else:
                compatible = status in {BotStatus.starting, BotStatus.running} and pid is not None
        else:
            compatible = status in {BotStatus.failed, BotStatus.unknown, BotStatus.stopped}
            if status in {BotStatus.failed, BotStatus.stopped} and pid is not None:
                compatible = False
        if not compatible:
            raise ValueError("lifecycle intent terminal state is incompatible with action outcome")

    def _validate_intent_revision(self, desired_revision: int) -> None:
        if type(desired_revision) is not int or desired_revision < 1:
            raise ValueError("desired revision must be a positive integer")

    def _validate_intent_correlation(
        self,
        bot_id: str,
        operation_id: str,
        source: str,
        request_id: str | None,
    ) -> None:
        event = LifecycleEventInput(
            bot_id=bot_id,
            operation_id=operation_id,
            source=source,
            action="lifecycle.intent.validate",
            outcome="validation",
            request_id=request_id,
        )
        self._validate_event_target(bot_id, event)

    def _require_matching_intent(
        self,
        row: sqlite3.Row,
        action: str,
        operation_id: str,
        desired_revision: int,
    ) -> None:
        desired_state = (
            DesiredState.stopped.value if action == "stop" else DesiredState.running.value
        )
        if (
            row["pending_operation_id"] != operation_id
            or int(row["desired_revision"]) != desired_revision
            or row["pending_action"] != action
            or row["desired_state"] != desired_state
        ):
            raise RuntimeError("pending lifecycle intent does not match")

    def _record_in_transaction(self, conn: sqlite3.Connection, bot_id: str) -> BotRecord:
        row = conn.execute("SELECT * FROM bots WHERE bot_id = ?", (bot_id,)).fetchone()
        if row is None:
            raise sqlite3.IntegrityError("updated bot projection is missing")
        return self._row_to_record(row)

    def audit_log_path(self) -> Path:
        return self.database_path.parent / "logs" / "audit.jsonl"

    def append_audit_event(self, event: str, **fields: object) -> None:
        try:
            safe_fields = sanitize_details(fields)
            if type(safe_fields) is not dict:
                return
            timestamp = datetime.now(UTC).isoformat()
            safe_event = sanitize_text(event)
            payload = {
                "ts": timestamp,
                "event": safe_event,
                **safe_fields,
            }
            line = (json.dumps(payload, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            if len(line) > MAX_SANITIZED_JSON_BYTES:
                line = (
                    json.dumps(
                        {
                            "ts": timestamp,
                            "event": "audit.truncated",
                            "truncated": True,
                        },
                        sort_keys=True,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8")
            if len(line) > MAX_SANITIZED_JSON_BYTES:
                return
            append_private_bytes(nofollow_absolute_path(self.audit_log_path()), line)
        except Exception:
            return

    def upsert_bot(self, record: BotRecord) -> None:
        with closing(self.connect()) as conn:
            self._upsert_bot_row(conn, record)
            conn.commit()

    def _upsert_bot_row(self, conn: sqlite3.Connection, record: BotRecord) -> None:
        conn.execute(
            """
                INSERT INTO bots (
                    bot_id,
                    template_id,
                    display_name,
                    profile_path,
                    status,
                    pid,
                    restart_policy,
                    restart_backoff_seconds,
                    restart_max_attempts,
                    restart_attempts,
                    next_restart_at,
                    started_at,
                    ready_at,
                    stopped_at,
                    last_exit_code,
                    last_error,
                    last_transition_reason,
                    desired_state,
                    desired_revision,
                    desired_updated_at,
                    pending_operation_id,
                    pending_action,
                    pending_since,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bot_id) DO UPDATE SET
                    template_id = excluded.template_id,
                    display_name = excluded.display_name,
                    profile_path = excluded.profile_path,
                    status = excluded.status,
                    pid = excluded.pid,
                    restart_policy = excluded.restart_policy,
                    restart_backoff_seconds = excluded.restart_backoff_seconds,
                    restart_max_attempts = excluded.restart_max_attempts,
                    restart_attempts = excluded.restart_attempts,
                    next_restart_at = excluded.next_restart_at,
                    started_at = excluded.started_at,
                    ready_at = excluded.ready_at,
                    stopped_at = excluded.stopped_at,
                    last_exit_code = excluded.last_exit_code,
                    last_error = excluded.last_error,
                    last_transition_reason = excluded.last_transition_reason,
                    desired_state = excluded.desired_state,
                    desired_revision = excluded.desired_revision,
                    desired_updated_at = excluded.desired_updated_at,
                    pending_operation_id = excluded.pending_operation_id,
                    pending_action = excluded.pending_action,
                    pending_since = excluded.pending_since,
                    updated_at = excluded.updated_at
            """,
            (
                record.bot_id,
                record.template_id,
                record.display_name,
                record.profile_path,
                record.status.value,
                record.pid,
                record.restart_policy.value,
                record.restart_backoff_seconds,
                record.restart_max_attempts,
                record.restart_attempts,
                record.next_restart_at.isoformat() if record.next_restart_at else None,
                record.started_at.isoformat() if record.started_at else None,
                record.ready_at.isoformat() if record.ready_at else None,
                record.stopped_at.isoformat() if record.stopped_at else None,
                record.last_exit_code,
                _sanitize_optional_persisted_text(record.last_error),
                _sanitize_optional_persisted_text(record.last_transition_reason),
                record.desired_state.value,
                record.desired_revision,
                record.desired_updated_at.isoformat() if record.desired_updated_at else None,
                record.pending_operation_id,
                record.pending_action,
                record.pending_since.isoformat() if record.pending_since else None,
                record.created_at.isoformat(),
                record.updated_at.isoformat(),
            ),
        )

    def upsert_bot_with_event(
        self,
        record: BotRecord,
        *,
        event: LifecycleEventInput,
    ) -> LifecycleEvent:
        self._validate_event_target(record.bot_id, event)
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (record.bot_id,)
                ).fetchone()
                self._upsert_bot_row(conn, record)
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]) if prior_row else None,
                    status_after=record.status.value,
                    pid_before=int(prior_row["pid"]) if prior_row and prior_row["pid"] else None,
                    pid_after=record.pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, record.bot_id),
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return stored

    def get_bot(self, bot_id: str) -> BotRecord | None:
        with closing(self.connect()) as conn:
            row = conn.execute("SELECT * FROM bots WHERE bot_id = ?", (bot_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def list_bots(self) -> list[BotRecord]:
        with closing(self.connect()) as conn:
            rows = conn.execute("SELECT * FROM bots ORDER BY bot_id").fetchall()
        return [self._row_to_record(row) for row in rows]

    def update_status(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        reset_restart: bool = False,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            if reset_restart:
                conn.execute(
                    """
                    UPDATE bots
                    SET status = ?,
                        pid = ?,
                        restart_attempts = 0,
                        next_restart_at = NULL,
                        updated_at = ?
                    WHERE bot_id = ?
                    """,
                    (status.value, pid, now, bot_id),
                )
            else:
                conn.execute(
                    "UPDATE bots SET status = ?, pid = ?, updated_at = ? WHERE bot_id = ?",
                    (status.value, pid, now, bot_id),
                )
            conn.commit()

    def update_lifecycle_state(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            self._update_lifecycle_row(
                conn,
                bot_id,
                status,
                pid,
                started_at=started_at,
                ready_at=ready_at,
                stopped_at=stopped_at,
                last_exit_code=last_exit_code,
                last_error=last_error,
                last_transition_reason=last_transition_reason,
                reset_restart=reset_restart,
                clear_ready_at=clear_ready_at,
                clear_stopped_at=clear_stopped_at,
                now=now,
            )
            conn.commit()

    def _update_lifecycle_row(
        self,
        conn: sqlite3.Connection,
        bot_id: str,
        status: BotStatus,
        pid: int | None,
        *,
        started_at: datetime | None,
        ready_at: datetime | None,
        stopped_at: datetime | None,
        last_exit_code: int | None,
        last_error: str | None,
        last_transition_reason: str | None,
        reset_restart: bool,
        clear_ready_at: bool,
        clear_stopped_at: bool,
        now: str,
    ) -> None:
        cursor = conn.execute(
            """
            UPDATE bots
            SET status = ?,
                pid = ?,
                started_at = COALESCE(?, started_at),
                ready_at = CASE WHEN ? THEN NULL ELSE COALESCE(?, ready_at) END,
                stopped_at = CASE WHEN ? THEN NULL ELSE COALESCE(?, stopped_at) END,
                last_exit_code = ?,
                last_error = ?,
                last_transition_reason = COALESCE(?, last_transition_reason),
                updated_at = ?,
                restart_attempts = CASE WHEN ? THEN 0 ELSE restart_attempts END,
                next_restart_at = CASE WHEN ? THEN NULL ELSE next_restart_at END
            WHERE bot_id = ?
            """,
            (
                status.value,
                pid,
                started_at.isoformat() if started_at else None,
                int(clear_ready_at),
                ready_at.isoformat() if ready_at else None,
                int(clear_stopped_at),
                stopped_at.isoformat() if stopped_at else None,
                last_exit_code,
                _sanitize_optional_persisted_text(last_error),
                _sanitize_optional_persisted_text(last_transition_reason),
                now,
                int(reset_restart),
                int(reset_restart),
                bot_id,
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"unknown bot: {bot_id}")

    def update_lifecycle_with_event(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        event: LifecycleEventInput,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
    ) -> LifecycleEvent:
        self._validate_event_target(bot_id, event)
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._update_lifecycle_row(
                    conn,
                    bot_id,
                    status,
                    pid,
                    started_at=started_at,
                    ready_at=ready_at,
                    stopped_at=stopped_at,
                    last_exit_code=last_exit_code,
                    last_error=last_error,
                    last_transition_reason=last_transition_reason,
                    reset_restart=reset_restart,
                    clear_ready_at=clear_ready_at,
                    clear_stopped_at=clear_stopped_at,
                    now=now,
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=status.value,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return stored

    def update_restart_state(
        self,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            self._update_restart_row(
                conn,
                bot_id,
                status=status,
                pid=pid,
                restart_attempts=restart_attempts,
                next_restart_at=next_restart_at,
                now=now,
            )
            conn.commit()

    def _update_restart_row(
        self,
        conn: sqlite3.Connection,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
        now: str,
    ) -> None:
        cursor = conn.execute(
            """
            UPDATE bots
            SET status = ?,
                pid = ?,
                restart_attempts = ?,
                next_restart_at = ?,
                updated_at = ?
            WHERE bot_id = ?
            """,
            (
                status.value,
                pid,
                restart_attempts,
                next_restart_at.isoformat() if next_restart_at else None,
                now,
                bot_id,
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"unknown bot: {bot_id}")

    def update_restart_with_event(
        self,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
        event: LifecycleEventInput,
    ) -> LifecycleEvent:
        self._validate_event_target(bot_id, event)
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._update_restart_row(
                    conn,
                    bot_id,
                    status=status,
                    pid=pid,
                    restart_attempts=restart_attempts,
                    next_restart_at=next_restart_at,
                    now=now,
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=status.value,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return stored

    def delete_bot(self, bot_id: str) -> bool:
        with closing(self.connect()) as conn:
            cursor = conn.execute("DELETE FROM bots WHERE bot_id = ?", (bot_id,))
            conn.commit()
        return cursor.rowcount > 0

    def delete_bot_with_event(
        self,
        bot_id: str,
        *,
        event: LifecycleEventInput,
    ) -> bool:
        self._validate_event_target(bot_id, event)
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                cursor = conn.execute("DELETE FROM bots WHERE bot_id = ?", (bot_id,))
                if cursor.rowcount != 1:
                    raise KeyError(f"unknown bot: {bot_id}")
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=None,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=None,
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return True

    def _validate_event_target(self, bot_id: str, event: LifecycleEventInput) -> None:
        if event.bot_id != bot_id:
            raise ValueError("lifecycle event bot_id must match the projection target")
        if LIFECYCLE_ID_RE.fullmatch(event.operation_id) is None:
            raise ValueError("lifecycle operation_id must be generated UUID hex")
        if event.source not in LIFECYCLE_SOURCES:
            raise ValueError("invalid lifecycle event source")
        if event.source == "api":
            if event.request_id is None or LIFECYCLE_ID_RE.fullmatch(event.request_id) is None:
                raise ValueError("API lifecycle events require a generated request ID")
        elif event.request_id is not None:
            raise ValueError("only API lifecycle events may carry a request ID")

    def _insert_lifecycle_event(
        self,
        conn: sqlite3.Connection,
        event: LifecycleEventInput,
        *,
        status_before: str | None,
        status_after: str | None,
        pid_before: int | None,
        pid_after: int | None,
    ) -> int:
        cursor = conn.execute(
            """
            INSERT INTO lifecycle_events (
                bot_id,
                operation_id,
                request_id,
                occurred_at,
                source,
                action,
                outcome,
                status_before,
                status_after,
                pid_before,
                pid_after,
                reason,
                error_code,
                error_message,
                details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.bot_id,
                event.operation_id,
                event.request_id,
                datetime.now(UTC).isoformat(),
                event.source,
                event.action,
                event.outcome,
                status_before,
                status_after,
                pid_before,
                pid_after,
                event.reason,
                event.error_code,
                event.error_message,
                serialize_lifecycle_details(event.details),
            ),
        )
        if cursor.lastrowid is None:
            raise sqlite3.IntegrityError("lifecycle event insert returned no event id")
        return int(cursor.lastrowid)

    def _materialize_lifecycle_event(
        self,
        conn: sqlite3.Connection,
        event_id: int,
    ) -> LifecycleEvent:
        row = conn.execute(
            "SELECT * FROM lifecycle_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise sqlite3.IntegrityError("inserted lifecycle event is missing")
        return self._row_to_lifecycle_event(row)

    def _append_lifecycle_audit_fail_open(self, event: LifecycleEvent) -> None:
        try:
            self._append_lifecycle_audit(event)
        except Exception:
            return

    def _append_lifecycle_audit(self, event: LifecycleEvent) -> None:
        self.append_audit_event(
            event.action,
            bot_id=event.bot_id,
            operation_id=event.operation_id,
            request_id=event.request_id,
            source=event.source,
            outcome=event.outcome,
            status_before=event.status_before,
            status_after=event.status_after,
            pid_before=event.pid_before,
            pid_after=event.pid_after,
            reason=event.reason,
            error_code=event.error_code,
            error_message=event.error_message,
            details=event.details,
        )

    def list_lifecycle_events(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> list[LifecycleEvent]:
        self._validate_history_page(bot_id, limit, before)
        with closing(self.connect()) as conn:
            rows = self._list_lifecycle_event_rows(conn, bot_id, limit, before)
        return [self._row_to_lifecycle_event(row) for row in rows]

    def history_payload(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> dict[str, object]:
        self._validate_history_page(bot_id, limit, before)
        with closing(self.connect()) as conn:
            rows = self._list_lifecycle_event_rows(conn, bot_id, limit + 1, before)
            if not rows:
                bot_is_known = (
                    conn.execute(
                        """
                        SELECT 1 FROM bots WHERE bot_id = ?
                        UNION ALL
                        SELECT 1 FROM lifecycle_events WHERE bot_id = ?
                        LIMIT 1
                        """,
                        (bot_id, bot_id),
                    ).fetchone()
                    is not None
                )
                if not bot_is_known:
                    raise KeyError(f"unknown bot: {bot_id}")
        has_more = len(rows) > limit
        events = [self._row_to_lifecycle_event(row) for row in rows[:limit]]
        return {
            "bot_id": bot_id,
            "events": [event.to_dict() for event in events],
            "next_before": events[-1].event_id if has_more else None,
        }

    def _validate_history_page(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> None:
        if not isinstance(bot_id, str):
            raise TypeError("bot_id must be a string")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if before is not None:
            if isinstance(before, bool) or not isinstance(before, int):
                raise TypeError("before must be an integer or null")
            if before < 1:
                raise ValueError("before must be positive")

    def _list_lifecycle_event_rows(
        self,
        conn: sqlite3.Connection,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> list[sqlite3.Row]:
        if before is None:
            return conn.execute(
                """
                SELECT * FROM lifecycle_events
                WHERE bot_id = ?
                ORDER BY event_id DESC
                LIMIT ?
                """,
                (bot_id, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT * FROM lifecycle_events
            WHERE bot_id = ? AND event_id < ?
            ORDER BY event_id DESC
            LIMIT ?
            """,
            (bot_id, before, limit),
        ).fetchall()

    def _row_to_lifecycle_event(self, row: sqlite3.Row) -> LifecycleEvent:
        return LifecycleEvent(
            event_id=int(row["event_id"]),
            bot_id=str(row["bot_id"]),
            operation_id=str(row["operation_id"]),
            request_id=str(row["request_id"]) if row["request_id"] is not None else None,
            occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
            source=str(row["source"]),
            action=str(row["action"]),
            outcome=str(row["outcome"]),
            status_before=(str(row["status_before"]) if row["status_before"] is not None else None),
            status_after=(str(row["status_after"]) if row["status_after"] is not None else None),
            pid_before=int(row["pid_before"]) if row["pid_before"] is not None else None,
            pid_after=int(row["pid_after"]) if row["pid_after"] is not None else None,
            reason=str(row["reason"]),
            error_code=str(row["error_code"]) if row["error_code"] is not None else None,
            error_message=(str(row["error_message"]) if row["error_message"] is not None else None),
            details=deserialize_lifecycle_details(str(row["details_json"])),
        )

    def _row_to_record(self, row: sqlite3.Row) -> BotRecord:
        next_restart_at = row["next_restart_at"]
        started_at = row["started_at"]
        ready_at = row["ready_at"]
        stopped_at = row["stopped_at"]
        desired_updated_at = row["desired_updated_at"]
        pending_since = row["pending_since"]
        return BotRecord(
            bot_id=row["bot_id"],
            template_id=row["template_id"],
            display_name=row["display_name"],
            profile_path=row["profile_path"],
            status=BotStatus(row["status"]),
            pid=row["pid"],
            restart_policy=RestartPolicy(row["restart_policy"]),
            restart_backoff_seconds=float(row["restart_backoff_seconds"]),
            restart_max_attempts=int(row["restart_max_attempts"]),
            restart_attempts=int(row["restart_attempts"]),
            next_restart_at=datetime.fromisoformat(next_restart_at) if next_restart_at else None,
            started_at=datetime.fromisoformat(started_at) if started_at else None,
            ready_at=datetime.fromisoformat(ready_at) if ready_at else None,
            stopped_at=datetime.fromisoformat(stopped_at) if stopped_at else None,
            last_exit_code=row["last_exit_code"],
            last_error=row["last_error"],
            last_transition_reason=row["last_transition_reason"],
            desired_state=DesiredState(row["desired_state"]),
            desired_revision=int(row["desired_revision"]),
            desired_updated_at=(
                datetime.fromisoformat(desired_updated_at) if desired_updated_at else None
            ),
            pending_operation_id=row["pending_operation_id"],
            pending_action=row["pending_action"],
            pending_since=datetime.fromisoformat(pending_since) if pending_since else None,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
