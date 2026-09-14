from __future__ import annotations

import contextlib
import threading
from datetime import datetime
from pathlib import Path
from typing import Protocol

from zeus import process_identity as _process_identity
from zeus.gateway_runtime import (
    OwnershipCheck,
)
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
)
from zeus.process_lock import BotProcessLock
from zeus.supervisor_contracts import (
    _GatewayGeneration,
    _LifecycleContext,
    _MarkerObservation,
)

_PidState = _process_identity.PidState


class StatusHost(Protocol):
    """Only the host capabilities required by status operations."""

    def _bot_process_lock(self, bot_id: str) -> BotProcessLock: ...

    def _classify_schema3_runtime_marker(
        self,
        record: BotRecord,
        payload: dict[str, object],
        *,
        expected_pid: int | None = None,
        expected_operation_id: str | None = None,
        expected_revision: int | None = None,
        expected_fingerprint: str | None = None,
        require_live_command: bool,
    ) -> _MarkerObservation: ...

    def _gateway_generation(self, marker: _MarkerObservation) -> _GatewayGeneration | None: ...

    def _lifecycle_context(self, source: str, request_id: str | None) -> _LifecycleContext: ...

    def _marker_publication_lock(
        self, record: BotRecord
    ) -> contextlib.AbstractContextManager[object]: ...

    def _pending_action_required(self, record: BotRecord, reason: str) -> BotStatusResponse: ...

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool: ...

    def _pid_state(self, pid: int) -> _PidState: ...

    def _read_pid_marker(self, profile_path: str) -> dict[str, object]: ...

    def _read_strict_runtime_marker(
        self, bot_id: str, registered_profile_path: str
    ) -> _MarkerObservation: ...

    def _recover_pending_intent(
        self, record: BotRecord, *, context: _LifecycleContext, allow_launch: bool
    ) -> BotStatusResponse: ...

    def _remove_gateway_generation_marker_locked(
        self, record: BotRecord, generation: _GatewayGeneration
    ) -> bool: ...

    def _require_bot(self, bot_id: str) -> BotRecord: ...

    def _status_dead_record_locked(
        self, record: BotRecord, *, context: _LifecycleContext
    ) -> BotStatusResponse: ...

    def _status_for_live_record(
        self, record: BotRecord, *, context: _LifecycleContext
    ) -> BotStatusResponse: ...

    def _status_locked(self, bot_id: str, *, context: _LifecycleContext) -> BotStatusResponse: ...

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

    def _verify_gateway_pid_ownership(
        self, profile_path: str, pid: int, bot_id: str
    ) -> OwnershipCheck: ...

    def bot_lock(self, bot_id: str) -> threading.RLock: ...

    def log_path(self, profile_path: str) -> Path: ...
