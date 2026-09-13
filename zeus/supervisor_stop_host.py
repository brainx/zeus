from __future__ import annotations

import contextlib
import threading
from datetime import datetime
from typing import Protocol

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


class StopHost(Protocol):
    """Only the host capabilities required by stop operations."""

    def _bot_process_lock(self, bot_id: str) -> BotProcessLock: ...

    def _classify_exact_gateway_generation(
        self, record: BotRecord, generation: _GatewayGeneration
    ) -> _MarkerObservation: ...

    def _classify_existing_runtime_marker(
        self, record: BotRecord, *, expected_pid: int | None = None
    ) -> _MarkerObservation: ...

    def _complete_stopped_intent(
        self, record: BotRecord, *, context: _LifecycleContext, reason: str
    ) -> BotRecord: ...

    def _lifecycle_context(self, source: str, request_id: str | None) -> _LifecycleContext: ...

    def _marker_publication_lock(
        self, record: BotRecord
    ) -> contextlib.AbstractContextManager[object]: ...

    def _pending_action_required(self, record: BotRecord, reason: str) -> BotStatusResponse: ...

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None: ...

    def _read_strict_runtime_marker(
        self, bot_id: str, registered_profile_path: str
    ) -> _MarkerObservation: ...

    def _remove_gateway_generation_marker_locked(
        self, record: BotRecord, generation: _GatewayGeneration
    ) -> bool: ...

    def _remove_owned_launch_marker_locked(
        self, record: BotRecord, *, observed: _MarkerObservation | None = None
    ) -> bool: ...

    def _require_bot(self, bot_id: str) -> BotRecord: ...

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

    def _stop_locked(
        self, bot_id: str, *, kill_after_timeout: bool | None = None, context: _LifecycleContext
    ) -> BotStatusResponse: ...

    def _stop_record_effect(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse: ...

    def _stop_record_effect_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        context: _LifecycleContext,
        complete_stop: bool,
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

    def bot_lock(self, bot_id: str) -> threading.RLock: ...

    store: StateStore
