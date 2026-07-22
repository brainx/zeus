from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

from zeus.bot_lifecycle_store import LIFECYCLE_ERROR_CODE_RE as LIFECYCLE_ERROR_CODE_RE
from zeus.bot_lifecycle_store import LIFECYCLE_ID_RE as LIFECYCLE_ID_RE
from zeus.bot_lifecycle_store import LIFECYCLE_INTENT_ACTIONS as LIFECYCLE_INTENT_ACTIONS
from zeus.bot_lifecycle_store import LIFECYCLE_SOURCES as LIFECYCLE_SOURCES
from zeus.bot_lifecycle_store import BotLifecycleStore
from zeus.config import SQLiteSynchronous
from zeus.idempotency import IdempotencyClaim
from zeus.idempotency_store import IDEMPOTENCY_HASH_RE as IDEMPOTENCY_HASH_RE
from zeus.idempotency_store import IDEMPOTENCY_OWNER_RE as IDEMPOTENCY_OWNER_RE
from zeus.idempotency_store import MAX_IDEMPOTENCY_RESPONSE_BYTES as MAX_IDEMPOTENCY_RESPONSE_BYTES
from zeus.idempotency_store import IdempotencyStore
from zeus.lifecycle import (
    LifecycleEvent,
    LifecycleEventInput,
)
from zeus.models import BotRecord, BotStatus
from zeus.reconcile_store import RECONCILE_COUNTER_COLUMNS as RECONCILE_COUNTER_COLUMNS
from zeus.reconcile_store import ReconcileStore
from zeus.reconciliation import (
    BotReconcileResult,
    PersistedReconcileRun,
    ReconcileRunStart,
    ReconcileRunSummary,
)
from zeus.schema import SCHEMA_VERSION as SCHEMA_VERSION
from zeus.schema import SchemaManager
from zeus.sqlite_db import SQLiteDatabase
from zeus.sqlite_db import StateReadinessError as StateReadinessError


class StateStore:
    def __init__(
        self,
        database_path: Path | str,
        *,
        synchronous: SQLiteSynchronous | str = SQLiteSynchronous.NORMAL,
    ) -> None:
        self._database = SQLiteDatabase(database_path, synchronous=synchronous)
        self._schema = SchemaManager(self._database)
        self._idempotency = IdempotencyStore(self._database)
        self._reconcile = ReconcileStore(self._database)
        self._bot_lifecycle = BotLifecycleStore(self._database)

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def connect(self) -> sqlite3.Connection:
        return self._database.connect()

    def check_readiness(self) -> int:
        return self._database.check_readiness()

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
        return self._bot_lifecycle.begin_lifecycle_intent(
            bot_id,
            action=action,
            operation_id=operation_id,
            source=source,
            request_id=request_id,
            reason=reason,
        )

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
        return self._bot_lifecycle.complete_lifecycle_intent(
            bot_id,
            action=action,
            operation_id=operation_id,
            desired_revision=desired_revision,
            status=status,
            pid=pid,
            source=source,
            outcome=outcome,
            request_id=request_id,
            reason=reason,
            error_code=error_code,
            error_message=error_message,
            started_at=started_at,
            ready_at=ready_at,
            stopped_at=stopped_at,
            last_exit_code=last_exit_code,
            last_error=last_error,
            last_transition_reason=last_transition_reason,
            reset_restart=reset_restart,
            clear_ready_at=clear_ready_at,
            clear_stopped_at=clear_stopped_at,
        )

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
        return self._bot_lifecycle.clear_stale_intent(
            bot_id,
            action=action,
            operation_id=operation_id,
            desired_revision=desired_revision,
            source=source,
            reason=reason,
            request_id=request_id,
        )

    def audit_log_path(self) -> Path:
        return self._bot_lifecycle.audit_log_path()

    def append_audit_event(self, event: str, **fields: object) -> None:
        self._bot_lifecycle.append_audit_event(event, **fields)

    def upsert_bot(self, record: BotRecord) -> None:
        self._bot_lifecycle.upsert_bot(record)

    def upsert_bot_with_event(
        self,
        record: BotRecord,
        *,
        event: LifecycleEventInput,
    ) -> LifecycleEvent:
        return self._bot_lifecycle.upsert_bot_with_event(record, event=event)

    def get_bot(self, bot_id: str) -> BotRecord | None:
        return self._bot_lifecycle.get_bot(bot_id)

    def list_bots(self) -> list[BotRecord]:
        return self._bot_lifecycle.list_bots()

    def update_status(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        reset_restart: bool = False,
    ) -> None:
        self._bot_lifecycle.update_status(
            bot_id,
            status,
            pid,
            reset_restart=reset_restart,
        )

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
        self._bot_lifecycle.update_lifecycle_state(
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
        )

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
        return self._bot_lifecycle.update_lifecycle_with_event(
            bot_id,
            status,
            pid,
            event=event,
            started_at=started_at,
            ready_at=ready_at,
            stopped_at=stopped_at,
            last_exit_code=last_exit_code,
            last_error=last_error,
            last_transition_reason=last_transition_reason,
            reset_restart=reset_restart,
            clear_ready_at=clear_ready_at,
            clear_stopped_at=clear_stopped_at,
        )

    def update_restart_state(
        self,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
    ) -> None:
        self._bot_lifecycle.update_restart_state(
            bot_id,
            status=status,
            pid=pid,
            restart_attempts=restart_attempts,
            next_restart_at=next_restart_at,
        )

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
        return self._bot_lifecycle.update_restart_with_event(
            bot_id,
            status=status,
            pid=pid,
            restart_attempts=restart_attempts,
            next_restart_at=next_restart_at,
            event=event,
        )

    def delete_bot(self, bot_id: str) -> bool:
        return self._bot_lifecycle.delete_bot(bot_id)

    def delete_bot_with_event(
        self,
        bot_id: str,
        *,
        event: LifecycleEventInput,
    ) -> bool:
        return self._bot_lifecycle.delete_bot_with_event(bot_id, event=event)

    def list_lifecycle_events(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> list[LifecycleEvent]:
        return self._bot_lifecycle.list_lifecycle_events(bot_id, limit, before)

    def history_payload(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> dict[str, object]:
        return self._bot_lifecycle.history_payload(bot_id, limit, before)
