from __future__ import annotations

import os
import platform
import subprocess  # nosec B404
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.gateway_launcher import (
    _read_bounded_file,
    _remove_marker_if_owned_locked,
)
from zeus.gateway_marker import (
    GatewayGeneration,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.gateway_runtime import (
    KillFn,
    MarkerObservation,
    OwnershipCheck,
    PopenFactory,
    PopenLike,
    RuntimeHooks,
    SignalResult,
    StopEffect,
)
from zeus.lifecycle import LifecycleEvent
from zeus.models import (
    BotCreateRequest,
    BotRecord,
    BotStatus,
    BotStatusResponse,
    HermesTemplate,
)
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once
from zeus.reconciliation import (
    BotReconcileResult,
    ReconcileExecution,
    ReconcileOutcome,
    ReconcileRunSummary,
)
from zeus.supervisor_contracts import (
    _READINESS_PROBE_UNSET,
    _LifecycleContext,
    _ReadinessProbeUnset,
    _ReconcileLaunch,
)
from zeus.supervisor_reconcile import ReconcileOperations
from zeus.supervisor_registry import RegistryOperations
from zeus.supervisor_runtime import _SupervisorCore
from zeus.supervisor_start import StartOperations
from zeus.supervisor_status import StatusOperations
from zeus.supervisor_stop import StopOperations

PidAliveFn = _process_identity.PidAliveFn
CmdlineReader = _process_identity.CmdlineReader
ProcStartFingerprintReader = _process_identity.ProcStartFingerprintReader

_CommandCheck = _process_identity.CommandCheck
_PidState = _process_identity.PidState
_looks_like_python_interpreter = _process_identity.looks_like_python_interpreter
_read_linux_cmdline = _process_identity.read_linux_cmdline
_read_linux_process_start_fingerprint = _process_identity.read_linux_process_start_fingerprint
_resolve_executable = _process_identity.resolve_executable
_resolve_launcher_exec_target = _process_identity.resolve_launcher_exec_target
_safe_command_shape = _process_identity.safe_command_shape
_trusted_hermes_paths = _process_identity.trusted_hermes_paths
_verify_gateway_command = _process_identity.verify_gateway_command

_SignalResult = SignalResult
_MarkerObservation = MarkerObservation
_GatewayGeneration = GatewayGeneration

__all__ = [
    "CmdlineReader",
    "KillFn",
    "OwnershipCheck",
    "PidAliveFn",
    "PopenFactory",
    "PopenLike",
    "ProcStartFingerprintReader",
    "Supervisor",
    "_CommandCheck",
    "_GatewayGeneration",
    "_MarkerObservation",
    "_PidState",
    "_SignalResult",
    "_looks_like_python_interpreter",
    "_read_bounded_file",
    "_read_darwin_cmdline",
    "_read_darwin_process_start_fingerprint",
    "_read_linux_cmdline",
    "_read_linux_process_start_fingerprint",
    "_read_process_cmdline",
    "_read_process_start_fingerprint",
    "_readiness_probe_from_marker",
    "_readiness_probe_marker_payload",
    "_resolve_executable",
    "_resolve_launcher_exec_target",
    "_safe_command_shape",
    "_trusted_hermes_paths",
    "_verify_gateway_command",
]


_REGISTRY = RegistryOperations()
_STATUS = StatusOperations()
_START = StartOperations()
_STOP = StopOperations()
_RECONCILE = ReconcileOperations()


class Supervisor(_SupervisorCore):
    """Public lifecycle facade over one state-owning core and stateless operations.

    Delegates pass the current host so operation-to-operation calls resolve live
    methods, including supported instance patches and subclass overrides.
    """

    @staticmethod
    def _default_cmdline_reader(pid: int) -> list[str] | None:
        return _read_process_cmdline(pid)

    @staticmethod
    def _default_process_start_fingerprint_reader(pid: int) -> str | None:
        return _read_process_start_fingerprint(pid)

    @staticmethod
    def _probe_once(probe: ReadinessProbe) -> ReadinessResult:
        return probe_once(
            probe.url,
            timeout_seconds=min(1.0, max(0.2, probe.interval_seconds)),
            expected_status=probe.expected_status,
            expected_platform=probe.expected_platform,
        )

    def _runtime_hooks(self) -> RuntimeHooks:
        return RuntimeHooks(
            pipe=os.pipe,
            close=os.close,
            read_bounded_file=_read_bounded_file,
            remove_marker_if_owned_locked=_remove_marker_if_owned_locked,
            probe_once=probe_once,
        )

    def _pid_state(self, pid: int) -> _PidState:
        if "_runtime" in self.__dict__:
            return self._runtime.pid_state(pid)
        return _process_identity.pid_state(pid, pid_alive_fn=self.pid_alive_fn)

    @staticmethod
    def _process_start_fingerprint_required() -> bool:
        return platform.system() in {"Linux", "Darwin"}

    def create_bot(
        self,
        request: BotCreateRequest,
        template: HermesTemplate,
        *,
        replace_existing: bool = False,
        stop_if_running: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotRecord:
        return _REGISTRY.create_bot(
            self,
            request,
            template,
            replace_existing=replace_existing,
            stop_if_running=stop_if_running,
            source=source,
            request_id=request_id,
        )

    def delete_bot(
        self,
        bot_id: str,
        *,
        stop_if_running: bool = False,
        remove_profile: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        return _REGISTRY.delete_bot(
            self,
            bot_id,
            stop_if_running=stop_if_running,
            remove_profile=remove_profile,
            source=source,
            request_id=request_id,
        )

    def archive_bot(
        self,
        bot_id: str,
        *,
        stop_if_running: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> dict[str, object]:
        return _REGISTRY.archive_bot(
            self, bot_id, stop_if_running=stop_if_running, source=source, request_id=request_id
        )

    def _record_may_be_active(self, record: BotRecord) -> bool:
        return _REGISTRY._record_may_be_active(self, record)

    def _recover_previously_active_bot(
        self,
        record: BotRecord,
        operation: str,
        *,
        context: _LifecycleContext,
    ) -> None:
        return _REGISTRY._recover_previously_active_bot(self, record, operation, context=context)

    def _assert_unregistered_profile_inactive(
        self,
        bot_id: str,
        profile_path: Path,
    ) -> None:
        return _REGISTRY._assert_unregistered_profile_inactive(self, bot_id, profile_path)

    def _safe_profile_path(self, bot_id: str, profile_path: str) -> Path:
        return _REGISTRY._safe_profile_path(self, bot_id, profile_path)

    def _stage_profile_deletion(self, bot_id: str, profile_path: str) -> Path | None:
        return _REGISTRY._stage_profile_deletion(self, bot_id, profile_path)

    def _restore_tombstoned_profile(
        self,
        bot_id: str,
        profile_path: str,
        tombstone: Path,
    ) -> None:
        return _REGISTRY._restore_tombstoned_profile(self, bot_id, profile_path, tombstone)

    def _restore_archived_profile(
        self,
        bot_id: str,
        profile_path: str,
        archive_path: Path,
    ) -> None:
        return _REGISTRY._restore_archived_profile(self, bot_id, profile_path, archive_path)

    def status(
        self,
        bot_id: str,
        *,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        return _STATUS.status(self, bot_id, source=source, request_id=request_id)

    def _status_locked(self, bot_id: str, *, context: _LifecycleContext) -> BotStatusResponse:
        return _STATUS._status_locked(self, bot_id, context=context)

    def _status_dead_record_locked(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        return _STATUS._status_dead_record_locked(self, record, context=context)

    def logs(self, bot_id: str, max_bytes: int = 20_000) -> str:
        return _STATUS.logs(self, bot_id, max_bytes)

    def inspect(self, bot_id: str, max_log_bytes: int = 20_000) -> dict[str, object]:
        return _STATUS.inspect(self, bot_id, max_log_bytes)

    def start(
        self,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        return _START.start(
            self,
            bot_id,
            wait=wait,
            timeout_seconds=timeout_seconds,
            source=source,
            request_id=request_id,
        )

    def _start_locked(
        self,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        return _START._start_locked(
            self, bot_id, wait=wait, timeout_seconds=timeout_seconds, context=context
        )

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
    ) -> BotStatusResponse:
        return _START._start_record(
            self,
            record,
            reset_restart=reset_restart,
            message=message,
            wait=wait,
            timeout_seconds=timeout_seconds,
            context=context,
            probe=probe,
        )

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None:
        return _START._preflight_start(self, record, timeout_seconds=timeout_seconds)

    def _write_pipe_payload(self, fd: int, payload: bytes) -> None:
        return _START._write_pipe_payload(self, fd, payload)

    def _read_launcher_ack(self, fd: int) -> bytes:
        return _START._read_launcher_ack(self, fd)

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
    ) -> BotRecord:
        return _START._complete_started_intent(
            self,
            record,
            context=context,
            status=status,
            pid=pid,
            reason=reason,
            ready_at=ready_at,
            last_error=last_error,
            reset_restart=reset_restart,
        )

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
    ) -> BotRecord:
        return _START._complete_failed_intent(
            self,
            record,
            context=context,
            pid=pid,
            message=message,
            reason=reason,
            stopped_at=stopped_at,
            last_exit_code=last_exit_code,
        )

    def _cleanup_interrupted_intent_launch(
        self,
        record: BotRecord,
        process: PopenLike,
        *,
        expected_fingerprint: str,
    ) -> bool:
        return _START._cleanup_interrupted_intent_launch(
            self, record, process, expected_fingerprint=expected_fingerprint
        )

    def _launch_completion_failure_response(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> BotStatusResponse:
        return _START._launch_completion_failure_response(self, record, generation)

    def stop(
        self,
        bot_id: str,
        *,
        kill_after_timeout: bool | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        return _STOP.stop(
            self,
            bot_id,
            kill_after_timeout=kill_after_timeout,
            source=source,
            request_id=request_id,
        )

    def _stop_locked(
        self,
        bot_id: str,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        return _STOP._stop_locked(
            self, bot_id, kill_after_timeout=kill_after_timeout, context=context
        )

    def _stop_record_effect(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse:
        return _STOP._stop_record_effect(
            self,
            record,
            kill_after_timeout=kill_after_timeout,
            context=context,
            complete_stop=complete_stop,
        )

    def _stop_record_effect_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse:
        return _STOP._stop_record_effect_locked(
            self,
            record,
            kill_after_timeout=kill_after_timeout,
            context=context,
            complete_stop=complete_stop,
        )

    def _complete_stopped_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        reason: str,
    ) -> BotRecord:
        return _STOP._complete_stopped_intent(self, record, context=context, reason=reason)

    def _remove_owned_launch_marker_locked(
        self,
        record: BotRecord,
        *,
        observed: _MarkerObservation | None = None,
    ) -> bool:
        return _STOP._remove_owned_launch_marker_locked(self, record, observed=observed)

    def restart(
        self,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        return _STOP.restart(
            self,
            bot_id,
            wait=wait,
            timeout_seconds=timeout_seconds,
            source=source,
            request_id=request_id,
        )

    def reconcile(
        self,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Sequence[tuple[str, str]] | None = None,
    ) -> list[BotStatusResponse]:
        return _RECONCILE.reconcile(
            self,
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        )

    def reconcile_summary(
        self,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Sequence[tuple[str, str]] | None = None,
    ) -> ReconcileRunSummary:
        return _RECONCILE.reconcile_summary(
            self,
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        )

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
    ) -> ReconcileExecution:
        return _RECONCILE.reconcile_execution(
            self,
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        )

    def validate_reconcile_request(self, source: str, request_id: str | None) -> None:
        return _RECONCILE.validate_reconcile_request(self, source, request_id)

    def validate_reconcile_target(
        self,
        bot_id: str,
        *,
        expected_profile_path: str | None = None,
    ) -> str:
        return _RECONCILE.validate_reconcile_target(
            self, bot_id, expected_profile_path=expected_profile_path
        )

    def reconcile_one(
        self,
        bot_id: str,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        expected_profile_path: str | None = None,
    ) -> BotReconcileResult:
        return _RECONCILE.reconcile_one(
            self,
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            expected_profile_path=expected_profile_path,
        )

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
    ) -> tuple[BotReconcileResult, BotStatusResponse]:
        return _RECONCILE.reconcile_one_execution(
            self,
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            expected_profile_path=expected_profile_path,
        )

    def _latest_reconcile_event(
        self,
        bot_id: str,
        prior_event_id: int | None,
    ) -> LifecycleEvent | None:
        return _RECONCILE._latest_reconcile_event(self, bot_id, prior_event_id)

    def _reconcile_result_from_response(
        self,
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event: LifecycleEvent | None,
        started_at: datetime,
    ) -> BotReconcileResult:
        return _RECONCILE._reconcile_result_from_response(
            self, before, after, response, current_event=current_event, started_at=started_at
        )

    @staticmethod
    def _reconcile_outcome(
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event_action: str | None,
    ) -> ReconcileOutcome:
        return _RECONCILE._reconcile_outcome(
            before, after, response, current_event_action=current_event_action
        )

    def _reconcile_record(
        self,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        reset_restart: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        return _RECONCILE._reconcile_record(
            self, record, now, force=force, reset_restart=reset_restart, context=context
        )

    def _prepare_reconcile_dead_record_locked(
        self,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse | _ReconcileLaunch:
        return _RECONCILE._prepare_reconcile_dead_record_locked(
            self, record, now, force=force, context=context
        )

    @staticmethod
    def _is_compat_runtime_marker(payload: dict[str, object]) -> bool:
        return _RECONCILE._is_compat_runtime_marker(payload)

    def _recover_pending_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_launch: bool,
    ) -> BotStatusResponse:
        return _RECONCILE._recover_pending_intent(
            self, record, context=context, allow_launch=allow_launch
        )

    @staticmethod
    def _recovery_lifecycle_context(
        operation_id: str,
        context: _LifecycleContext,
    ) -> _LifecycleContext:
        return _RECONCILE._recovery_lifecycle_context(operation_id, context)

    def _pending_launch_preflight(
        self,
        record: BotRecord,
        operation_id: str,
    ) -> tuple[ReadinessProbe | None, str]:
        return _RECONCILE._pending_launch_preflight(self, record, operation_id)

    def _recover_pending_stop_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return _RECONCILE._recover_pending_stop_intent(
            self, record, context=context, allow_stop=allow_stop
        )

    def _recover_pending_launch(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        probe: ReadinessProbe | None,
        fingerprint: str,
        action: str,
        allow_launch: bool,
    ) -> BotStatusResponse | None:
        return _RECONCILE._recover_pending_launch(
            self,
            record,
            context=context,
            probe=probe,
            fingerprint=fingerprint,
            action=action,
            allow_launch=allow_launch,
        )

    def _recover_pending_stop_intent_locked(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return _RECONCILE._recover_pending_stop_intent_locked(
            self, record, context=context, allow_stop=allow_stop
        )

    def _pending_restart_old_marker(
        self,
        record: BotRecord,
        observed: _MarkerObservation | None = None,
    ) -> _MarkerObservation | None:
        return _RECONCILE._pending_restart_old_marker(self, record, observed)

    def _recover_pending_restart_predecessor(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse | None:
        return _RECONCILE._recover_pending_restart_predecessor(
            self, record, context=context, allow_stop=allow_stop
        )

    def _recover_pending_restart_old_gateway(
        self,
        record: BotRecord,
        marker: _MarkerObservation,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return _RECONCILE._recover_pending_restart_old_gateway(
            self, record, marker, context=context, allow_stop=allow_stop
        )

    def _stop_pending_restart_old_gateway(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        return _RECONCILE._stop_pending_restart_old_gateway(
            self, record, generation, context=context
        )

    def _stop_gateway_generation_locked(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> StopEffect:
        return _RECONCILE._stop_gateway_generation_locked(self, record, generation)

    def _append_recovery_audit_event(self, action: str, **values: object) -> None:
        return _RECONCILE._append_recovery_audit_event(self, action, **values)

    def _restart_delay(self, record: BotRecord) -> float:
        return _RECONCILE._restart_delay(self, record)


def _read_process_cmdline(pid: int) -> list[str] | None:
    return _process_identity.read_process_cmdline(
        pid,
        system=platform.system(),
        run_process=subprocess.run,
    )


def _readiness_probe_marker_payload(probe: ReadinessProbe | None) -> dict[str, object] | None:
    return readiness_probe_to_payload(probe)


def _readiness_probe_from_marker(value: object) -> ReadinessProbe | None:
    return readiness_probe_from_payload(value)


def _read_darwin_cmdline(pid: int) -> list[str] | None:
    return _process_identity.read_darwin_cmdline(pid, run_process=subprocess.run)


def _read_process_start_fingerprint(pid: int) -> str | None:
    return _process_identity.read_process_start_fingerprint(
        pid,
        system=platform.system(),
        run_process=subprocess.run,
    )


def _read_darwin_process_start_fingerprint(pid: int) -> str | None:
    return _process_identity.read_darwin_process_start_fingerprint(
        pid,
        run_process=subprocess.run,
    )
