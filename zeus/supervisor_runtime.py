from __future__ import annotations

import os
import platform
import signal
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.gateway_runtime import (
    OwnershipCheck,
    PopenLike,
)
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
)
from zeus.readiness import ReadinessProbe, ReadinessResult
from zeus.supervisor_core import (
    _READINESS_PROBE_UNSET,
    _GatewayGeneration,
    _LifecycleContext,
    _MarkerObservation,
    _ReadinessProbeUnset,
    _SignalResult,
    _SupervisorCore,
)

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


class _SupervisorRuntime(_SupervisorCore):
    def _read_strict_runtime_marker(
        self, bot_id: str, registered_profile_path: str
    ) -> _MarkerObservation:
        return self._runtime.read_strict_runtime_marker(bot_id, registered_profile_path)

    def _matching_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_fingerprint: str,
        expected_pid: int | None = None,
        require_live_command: bool,
    ) -> _MarkerObservation:
        return self._runtime.matching_runtime_marker(
            record,
            expected_fingerprint=expected_fingerprint,
            expected_pid=expected_pid,
            require_live_command=require_live_command,
            read_marker=self._read_strict_runtime_marker,
        )

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
    ) -> _MarkerObservation:
        return self._runtime.classify_schema3_runtime_marker(
            record,
            payload,
            expected_pid=expected_pid,
            expected_operation_id=expected_operation_id,
            expected_revision=expected_revision,
            expected_fingerprint=expected_fingerprint,
            require_live_command=require_live_command,
        )

    def _process_start_identity_error(self, payload: dict[str, object], pid: int) -> str | None:
        if "_runtime" in self.__dict__:
            return self._runtime.process_start_identity_error(payload, pid)
        return _process_identity.process_start_identity_error(
            payload.get("proc_start_fingerprint"),
            self.proc_start_fingerprint_reader(pid),
            fingerprint_required=self._process_start_fingerprint_required(),
        )

    @staticmethod
    def _valid_marker_start(value: object) -> bool:
        return _process_identity.valid_process_start_fingerprint(value)

    @staticmethod
    def _process_start_fingerprint_required() -> bool:
        return _process_identity.process_start_fingerprint_required(platform.system())

    def _classify_existing_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_pid: int | None = None,
    ) -> _MarkerObservation:
        return self._runtime.classify_existing_runtime_marker(
            record,
            expected_pid=expected_pid,
            read_marker=self._read_strict_runtime_marker,
        )

    def _remove_exact_schema3_marker(
        self,
        record: BotRecord,
        marker: _MarkerObservation,
    ) -> bool:
        return self._runtime.remove_exact_schema3_marker(record, marker)

    def _gateway_generation(
        self,
        marker: _MarkerObservation,
    ) -> _GatewayGeneration | None:
        return self._runtime.gateway_generation(marker)

    def _classify_exact_gateway_generation(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> _MarkerObservation:
        return self._runtime.classify_exact_gateway_generation(
            record,
            generation,
            read_marker=self._read_strict_runtime_marker,
        )

    def _remove_gateway_generation_marker(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> bool:
        return self._runtime.remove_gateway_generation_marker(record, generation)

    def _remove_gateway_generation_marker_locked(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> bool:
        return self._runtime.remove_gateway_generation_marker_locked(record, generation)

    def _pending_action_required(self, record: BotRecord, reason: str) -> BotStatusResponse:
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=BotStatus.failed,
            pid=record.pid,
            profile_path=record.profile_path,
            message=f"action required: {reason}",
        )

    def _status_for_live_record(
        self, record: BotRecord, *, context: _LifecycleContext
    ) -> BotStatusResponse:
        pid = record.pid
        if pid is None:
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )
        if record.status == BotStatus.starting:
            probe, probe_error = self._readiness_probe_for_live_record(record)
            if probe_error is not None:
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.starting,
                    pid=pid,
                    profile_path=record.profile_path,
                    message=probe_error,
                )
            if probe is None:
                self._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.running,
                    pid=pid,
                    ready_at=datetime.now(UTC),
                    last_transition_reason="gateway process is running without readiness probe",
                    reset_restart=True,
                )
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.running,
                    pid=pid,
                    profile_path=record.profile_path,
                    message="running",
                )
            readiness = self._probe_once(probe)
            if readiness.ready:
                self._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.running,
                    pid=pid,
                    ready_at=datetime.now(UTC),
                    last_transition_reason="gateway readiness probe passed",
                    reset_restart=True,
                )
                self.store.append_audit_event(
                    "bot.readiness_ready",
                    bot_id=record.bot_id,
                    pid=pid,
                    url=probe.url,
                )
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.running,
                    pid=pid,
                    profile_path=record.profile_path,
                    message="gateway ready",
                )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.starting,
                pid=pid,
                profile_path=record.profile_path,
                message=readiness.message,
            )
        if record.status in {BotStatus.failed, BotStatus.unknown}:
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=record.status,
                pid=pid,
                profile_path=record.profile_path,
                message=record.last_error or f"gateway process state is {record.status.value}",
            )
        needs_running_projection_update = (
            record.status is not BotStatus.running
            or record.restart_attempts != 0
            or record.next_restart_at is not None
            or record.ready_at is None
            or record.last_error is not None
            or record.last_exit_code is not None
        )
        if needs_running_projection_update:
            self._update_lifecycle(
                context,
                record.bot_id,
                BotStatus.running,
                pid=pid,
                ready_at=datetime.now(UTC),
                last_transition_reason="gateway process is running",
                reset_restart=True,
            )
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=BotStatus.running,
            pid=pid,
            profile_path=record.profile_path,
        )

    def _readiness_probe_for_bot(
        self, bot_id: str, *, timeout_seconds: float | None = None
    ) -> ReadinessProbe | None:
        return self._runtime.readiness_probe_for_bot(
            bot_id,
            timeout_seconds=timeout_seconds,
        )

    def _readiness_probe_for_live_record(
        self, record: BotRecord
    ) -> tuple[ReadinessProbe | None, str | None]:
        return self._runtime.readiness_probe_for_live_record(record)

    def _readiness_probe(
        self, env: dict[str, str], *, timeout_seconds: float | None = None
    ) -> ReadinessProbe | None:
        return self._runtime.readiness_probe(env, timeout_seconds=timeout_seconds)

    def _wait_for_readiness(
        self,
        process: PopenLike,
        probe: ReadinessProbe,
    ) -> ReadinessResult:
        return self._runtime.wait_for_readiness(process, probe)

    def log_path(self, profile_path: str) -> Path:
        return self._runtime.log_path(profile_path)

    def pid_marker_path(self, profile_path: str) -> Path:
        return self._runtime.pid_marker_path(profile_path)

    def _require_bot(self, bot_id: str) -> BotRecord:
        record = self.store.get_bot(bot_id)
        if record is None:
            raise KeyError(f"unknown bot: {bot_id}")
        return record

    def _pid_state(self, pid: int) -> _PidState:
        if "_runtime" in self.__dict__:
            return self._runtime.pid_state(pid)
        if self.pid_alive_fn is not None:
            return _process_identity.pid_state(pid, pid_alive_fn=self.pid_alive_fn)

        def probe_with_current_kill(probe_pid: int) -> bool:
            os.kill(probe_pid, 0)
            return True

        return _process_identity.pid_state(pid, pid_alive_fn=probe_with_current_kill)

    def _unknown_pid_response(
        self,
        record: BotRecord,
        operation: str,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        message = f"gateway PID state is unknown; refusing to {operation}"
        self._update_lifecycle(
            context,
            record.bot_id,
            BotStatus.unknown,
            pid=record.pid,
            last_error=message,
            last_transition_reason="gateway PID state could not be determined",
        )
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=BotStatus.unknown,
            pid=record.pid,
            profile_path=record.profile_path,
            message=message,
        )

    def _send_signal(self, pid: int, sig: signal.Signals) -> _SignalResult:
        return self._runtime.send_signal(pid, sig)

    def _write_pid_marker(
        self,
        profile_path: str,
        pid: int,
        bot_id: str,
        argv: list[str],
        *,
        readiness_probe: ReadinessProbe | _ReadinessProbeUnset | None = _READINESS_PROBE_UNSET,
    ) -> None:
        include_readiness_probe = not isinstance(readiness_probe, _ReadinessProbeUnset)
        runtime_probe = (
            None if isinstance(readiness_probe, _ReadinessProbeUnset) else readiness_probe
        )
        self._runtime.write_pid_marker(
            profile_path,
            pid,
            bot_id,
            argv,
            readiness_probe=runtime_probe,
            include_readiness_probe=include_readiness_probe,
        )

    def _remove_pid_marker(self, profile_path: str) -> None:
        self._runtime.remove_pid_marker(profile_path)

    def _read_pid_marker(self, profile_path: str) -> dict[str, object]:
        return self._runtime.read_pid_marker(profile_path)

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool:
        return self._verify_gateway_pid_ownership(profile_path, pid, bot_id).verified

    def _verify_gateway_pid_ownership(
        self, profile_path: str, pid: int, bot_id: str
    ) -> OwnershipCheck:
        record = self.store.get_bot(bot_id)
        ownership = self._runtime.verify_gateway_pid_ownership(
            profile_path,
            pid,
            bot_id,
            expected_record=record,
        )
        if ownership.classification == "legacy-marker-valid":
            self.store.append_audit_event(
                "bot.pid_marker_legacy_accepted",
                bot_id=bot_id,
                pid=pid,
            )
        return ownership

    def _verify_marker_payload(
        self, payload: dict[str, object], argv: list[str], bot_id: str
    ) -> OwnershipCheck:
        return self._runtime.verify_marker_payload(payload, argv, bot_id)

    def _resolved_hermes_bin(self) -> str | None:
        if "_runtime" in self.__dict__:
            return self._runtime.resolved_hermes_bin()
        return _resolve_executable(self.adapter.hermes_bin)

    def _trusted_hermes_bins(self) -> set[str]:
        if "_runtime" in self.__dict__:
            return self._runtime.trusted_hermes_bins()
        return _trusted_hermes_paths(self.adapter.hermes_bin)

    def _cleanup_failed_start_registration(
        self,
        record: BotRecord,
        process: PopenLike,
        registration_error: BaseException,
        *,
        context: _LifecycleContext,
    ) -> bool:
        cleanup_errors: list[str] = []
        try:
            stopped = self._terminate_spawned_process(process, cleanup_errors)
        except Exception as exc:
            cleanup_errors.append(f"terminate child: {type(exc).__name__}: {exc}")
            stopped = False
        if stopped:
            self._processes.pop(record.bot_id, None)
            try:
                self._remove_pid_marker(record.profile_path)
            except OSError as exc:
                cleanup_errors.append(f"remove marker: {type(exc).__name__}: {exc}")
            try:
                failed_record = replace(
                    record,
                    status=BotStatus.failed,
                    pid=None,
                    ready_at=None,
                    stopped_at=datetime.now(UTC),
                    last_exit_code=None,
                    last_error="gateway start registration failed",
                    last_transition_reason="gateway start registration failed",
                )
                self.store.upsert_bot_with_event(
                    failed_record,
                    event=self._event(
                        context,
                        record.bot_id,
                        action="bot.start.registration_failed",
                        outcome="failure",
                        reason="gateway start registration failed",
                        error_code="registration_failed",
                        error_message=str(registration_error),
                    ),
                )
            except Exception as exc:
                cleanup_errors.append(f"restore state: {type(exc).__name__}: {exc}")
        else:
            try:
                self._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.unknown,
                    pid=process.pid,
                    last_error="gateway start registration failed and cleanup was incomplete",
                    last_transition_reason="gateway start cleanup failed",
                )
            except Exception as exc:
                cleanup_errors.append(f"record incomplete cleanup: {type(exc).__name__}: {exc}")
        self.store.append_audit_event(
            "bot.start_registration_failed",
            bot_id=record.bot_id,
            pid=process.pid,
            error=type(registration_error).__name__,
            message=str(registration_error),
            cleanup_succeeded=stopped and not cleanup_errors,
            cleanup_errors=cleanup_errors,
        )
        return stopped

    def _terminate_spawned_process(
        self,
        process: PopenLike,
        cleanup_errors: list[str],
    ) -> bool:
        return self._runtime.terminate_spawned_process(process, cleanup_errors)

    def _signal_spawned_process(
        self,
        process: PopenLike,
        sig: signal.Signals,
        cleanup_errors: list[str],
    ) -> _SignalResult:
        return self._runtime.signal_spawned_process(process, sig, cleanup_errors)

    def _reap_spawned_process(
        self,
        process: PopenLike,
        cleanup_errors: list[str],
        *,
        timeout: float,
    ) -> bool:
        return self._runtime.reap_spawned_process(
            process,
            cleanup_errors,
            timeout=timeout,
        )

    def _spawned_tree_stopped(self, process: PopenLike, *, timeout: float) -> bool:
        return self._runtime.spawned_tree_stopped(process, timeout=timeout)

    def _wait_for_exit(self, bot_id: str, pid: int) -> bool:
        return self._runtime.wait_for_exit(bot_id, pid)

    def _poll_startup(self, process: PopenLike) -> int | None:
        return self._runtime.poll_startup(process)
