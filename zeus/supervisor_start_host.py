from __future__ import annotations

import contextlib
import threading
from datetime import datetime
from typing import Protocol

from zeus import process_identity as _process_identity
from zeus.gateway_runtime import (
    GatewayRuntime,
)
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
)
from zeus.process_lock import BotProcessLock
from zeus.readiness import ReadinessProbe
from zeus.state import StateStore
from zeus.supervisor_contracts import (
    _READINESS_PROBE_UNSET,
    _GatewayGeneration,
    _LifecycleContext,
    _MarkerObservation,
    _ReadinessProbeUnset,
)

_PidState = _process_identity.PidState


class StartHost(Protocol):
    """Only the host capabilities required by start operations."""

    def _bot_process_lock(self, bot_id: str) -> BotProcessLock: ...

    def _classify_existing_runtime_marker(
        self, record: BotRecord, *, expected_pid: int | None = None
    ) -> _MarkerObservation: ...

    def _complete_failed_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        pid: int | None,
        message: str,
        reason: str,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
    ) -> BotRecord: ...

    def _complete_started_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        status: BotStatus,
        pid: int,
        reason: str,
        ready_at: datetime | None = None,
        last_error: str | None = None,
        reset_restart: bool = False,
    ) -> BotRecord: ...

    def _launch_completion_failure_response(
        self, record: BotRecord, generation: _GatewayGeneration
    ) -> BotStatusResponse: ...

    def _lifecycle_context(self, source: str, request_id: str | None) -> _LifecycleContext: ...

    def _marker_publication_lock(
        self, record: BotRecord
    ) -> contextlib.AbstractContextManager[object]: ...

    def _matching_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_fingerprint: str,
        expected_pid: int | None = None,
        require_live_command: bool,
    ) -> _MarkerObservation: ...

    def _pending_action_required(self, record: BotRecord, reason: str) -> BotStatusResponse: ...

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool: ...

    def _pid_state(self, pid: int) -> _PidState: ...

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None: ...

    def _read_launcher_ack(self, fd: int) -> bytes: ...

    def _remove_exact_schema3_marker(
        self, record: BotRecord, marker: _MarkerObservation
    ) -> bool: ...

    def _require_bot(self, bot_id: str) -> BotRecord: ...

    _runtime: GatewayRuntime

    def _start_locked(
        self,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        context: _LifecycleContext,
    ) -> BotStatusResponse: ...

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

    def _write_pipe_payload(self, fd: int, payload: bytes) -> None: ...

    def bot_lock(self, bot_id: str) -> threading.RLock: ...

    store: StateStore
