from __future__ import annotations

import contextlib
import threading
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from zeus import process_identity as _process_identity
from zeus.gateway_runtime import (
    GatewayRuntime,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.intent_recovery import PendingIntentRecovery, _RecoveryHost
from zeus.lifecycle import LifecycleEvent
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
)
from zeus.process_lock import BotProcessLock
from zeus.readiness import ReadinessProbe
from zeus.reconciliation import (
    BotReconcileResult,
    ReconcileExecution,
    ReconcileOutcome,
    _ReconciliationSupervisor,
)
from zeus.state import StateStore
from zeus.supervisor_contracts import (
    _READINESS_PROBE_UNSET,
    _GatewayGeneration,
    _LifecycleContext,
    _MarkerObservation,
    _ReadinessProbeUnset,
    _ReconcileLaunch,
)

_PidState = _process_identity.PidState


class ReconcileHost(_RecoveryHost[_LifecycleContext], _ReconciliationSupervisor, Protocol):
    """Only the host capabilities required by reconcile operations."""

    def _bot_process_lock(self, bot_id: str) -> BotProcessLock: ...

    def _classify_exact_gateway_generation(
        self, record: BotRecord, generation: _GatewayGeneration
    ) -> _MarkerObservation: ...

    def _classify_existing_runtime_marker(
        self, record: BotRecord, *, expected_pid: int | None = None
    ) -> _MarkerObservation: ...

    def _gateway_generation(self, marker: _MarkerObservation) -> _GatewayGeneration | None: ...

    _intent_recovery: PendingIntentRecovery

    def _latest_reconcile_event(
        self, bot_id: str, prior_event_id: int | None
    ) -> LifecycleEvent | None: ...

    def _lifecycle_context(self, source: str, request_id: str | None) -> _LifecycleContext: ...

    def _marker_publication_lock(
        self, record: BotRecord
    ) -> contextlib.AbstractContextManager[object]: ...

    def _pending_action_required(self, record: BotRecord, reason: str) -> BotStatusResponse: ...

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool: ...

    def _pid_state(self, pid: int) -> _PidState: ...

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None: ...

    def _prepare_reconcile_dead_record_locked(
        self, record: BotRecord, now: datetime, *, force: bool, context: _LifecycleContext
    ) -> BotStatusResponse | _ReconcileLaunch: ...

    @staticmethod
    def _reconcile_outcome(
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event_action: str | None,
    ) -> ReconcileOutcome: ...

    def _reconcile_record(
        self,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        reset_restart: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse: ...

    def _reconcile_result_from_response(
        self,
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event: LifecycleEvent | None,
        started_at: datetime,
    ) -> BotReconcileResult: ...

    def _recover_pending_intent(
        self, record: BotRecord, *, context: _LifecycleContext, allow_launch: bool
    ) -> BotStatusResponse: ...

    def _recover_pending_stop_intent_locked(
        self, record: BotRecord, *, context: _LifecycleContext, allow_stop: bool
    ) -> BotStatusResponse: ...

    def _remove_gateway_generation_marker_locked(
        self, record: BotRecord, generation: _GatewayGeneration
    ) -> bool: ...

    def _require_bot(self, bot_id: str) -> BotRecord: ...

    def _restart_delay(self, record: BotRecord) -> float: ...

    _runtime: GatewayRuntime

    def _start_record(
        self,
        record: BotRecord,
        *,
        reset_restart: bool,
        message: str,
        wait: bool = False,
        timeout_seconds: float | None = None,
        context: _LifecycleContext,
        probe: ReadinessProbe | _ReadinessProbeUnset | None = _READINESS_PROBE_UNSET,
    ) -> BotStatusResponse: ...

    def _status_for_live_record(
        self, record: BotRecord, *, context: _LifecycleContext
    ) -> BotStatusResponse: ...

    def _unknown_pid_response(
        self, record: BotRecord, operation: str, *, context: _LifecycleContext
    ) -> BotStatusResponse: ...

    def _update_lifecycle(
        self,
        context: _LifecycleContext,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        action: str | None = None,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
        details: dict[str, object] | None = None,
    ) -> None: ...

    def _update_restart(
        self,
        context: _LifecycleContext,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
        action: str,
        reason: str,
        outcome: str = "success",
        error_code: str | None = None,
    ) -> None: ...

    adapter: HermesAdapter

    def bot_lock(self, bot_id: str) -> threading.RLock: ...

    def reconcile_execution(
        self,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Sequence[tuple[str, str]] | None = None,
    ) -> ReconcileExecution: ...

    def reconcile_one_execution(
        self,
        bot_id: str,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        expected_profile_path: str | None = None,
    ) -> tuple[BotReconcileResult, BotStatusResponse]: ...

    restart_backoff_cap_seconds: float

    store: StateStore
