from __future__ import annotations

import threading
from pathlib import Path
from typing import Protocol

from zeus import process_identity as _process_identity
from zeus.gateway_runtime import (
    GatewayRuntime,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.lifecycle import LifecycleEventInput
from zeus.models import (
    BotRecord,
    BotStatusResponse,
)
from zeus.process_lock import BotProcessLock
from zeus.profile_manager import ProfileManager
from zeus.readiness import ReadinessProbe
from zeus.state import StateStore
from zeus.supervisor_contracts import (
    _READINESS_PROBE_UNSET,
    _LifecycleContext,
    _ReadinessProbeUnset,
)

_PidState = _process_identity.PidState


class RegistryHost(Protocol):
    """Only the host capabilities required by registry operations."""

    def _assert_unregistered_profile_inactive(self, bot_id: str, profile_path: Path) -> None: ...

    def _bot_process_lock(self, bot_id: str) -> BotProcessLock: ...

    def _event(
        self,
        context: _LifecycleContext,
        bot_id: str,
        *,
        action: str,
        outcome: str = "success",
        reason: str = "",
        error_code: str | None = None,
        error_message: str | None = None,
        details: dict[str, object] | None = None,
    ) -> LifecycleEventInput: ...

    def _lifecycle_context(self, source: str, request_id: str | None) -> _LifecycleContext: ...

    def _pid_state(self, pid: int) -> _PidState: ...

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None: ...

    _profile_manager: ProfileManager

    def _record_may_be_active(self, record: BotRecord) -> bool: ...

    def _recover_previously_active_bot(
        self, record: BotRecord, operation: str, *, context: _LifecycleContext
    ) -> None: ...

    def _remove_pid_marker(self, profile_path: str) -> None: ...

    def _require_bot(self, bot_id: str) -> BotRecord: ...

    _runtime: GatewayRuntime

    def _safe_profile_path(self, bot_id: str, profile_path: str) -> Path: ...

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

    adapter: HermesAdapter

    def bot_lock(self, bot_id: str) -> threading.RLock: ...

    store: StateStore
