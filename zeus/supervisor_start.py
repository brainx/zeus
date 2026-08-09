from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from zeus import process_identity as _process_identity
from zeus.gateway_runtime import (
    PopenLike,
)
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
    TemplateError,
)
from zeus.readiness import ReadinessProbe
from zeus.supervisor_core import (
    _READINESS_PROBE_UNSET,
    _GatewayGeneration,
    _LifecycleContext,
    _ReadinessProbeUnset,
)
from zeus.supervisor_runtime import _SupervisorRuntime

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


class _SupervisorStart(_SupervisorRuntime):
    def start(
        self,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = self._lifecycle_context(source, request_id)
        with self.bot_lock(bot_id), self._bot_process_lock(bot_id):
            return self._start_locked(
                bot_id,
                wait=wait,
                timeout_seconds=timeout_seconds,
                context=context,
            )

    def _start_locked(
        self,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if record.pending_operation_id is not None:
            return self._pending_action_required(record, "lifecycle intent is already pending")
        pid_state = self._pid_state(record.pid) if record.pid else _PidState.dead
        if record.pid and pid_state == _PidState.unknown:
            return self._unknown_pid_response(record, "start another gateway", context=context)
        if record.pid and pid_state == _PidState.alive:
            if not self._pid_owned(record.profile_path, record.pid, bot_id):
                self._update_lifecycle(
                    context,
                    bot_id,
                    BotStatus.failed,
                    pid=record.pid,
                    last_error="recorded gateway PID ownership could not be verified",
                    last_transition_reason="ownership verification failed",
                )
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.failed,
                    pid=record.pid,
                    profile_path=record.profile_path,
                    message="recorded gateway PID is alive but ownership could not be verified",
                )
            response = self._status_for_live_record(record, context=context)
            return BotStatusResponse(
                bot_id=bot_id,
                status=response.status,
                pid=response.pid,
                profile_path=response.profile_path,
                message=(
                    "already running" if response.status == BotStatus.running else response.message
                ),
            )
        marker = self._classify_existing_runtime_marker(record)
        if marker.kind == "dead":
            if not self._remove_exact_schema3_marker(record, marker):
                return self._pending_action_required(
                    record, "stale gateway marker cleanup could not be verified"
                )
        elif marker.kind != "missing":
            return self._pending_action_required(
                record,
                marker.reason or "existing gateway marker ownership is unresolved",
            )
        try:
            probe = self._preflight_start(record, timeout_seconds=timeout_seconds)
        except (OSError, TemplateError) as exc:
            message = f"failed to start gateway: {exc}"
            self._update_lifecycle(
                context,
                bot_id,
                BotStatus.failed,
                pid=None,
                action="bot.start.preflight",
                last_error=message,
                last_transition_reason="gateway launch preflight failed",
            )
            self.store.append_audit_event(
                "bot.start_failed",
                bot_id=bot_id,
                error=type(exc).__name__,
                message=str(exc),
            )
            return BotStatusResponse(
                bot_id,
                BotStatus.failed,
                None,
                record.profile_path,
                message,
            )
        record = self.store.begin_lifecycle_intent(
            bot_id,
            action="start",
            operation_id=context.operation_id,
            source=context.source,
            request_id=context.request_id,
            reason="gateway start requested",
        )
        return self._start_record(
            record,
            reset_restart=True,
            message="started",
            wait=wait,
            timeout_seconds=timeout_seconds,
            context=context,
            probe=probe,
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
        bot_id = record.bot_id
        action = record.pending_action
        operation_id = record.pending_operation_id
        if action not in {"start", "restart"} or operation_id is None:
            raise RuntimeError("gateway launch requires a pending start or restart intent")
        if isinstance(probe, _ReadinessProbeUnset):
            try:
                probe = self._preflight_start(record, timeout_seconds=timeout_seconds)
            except (OSError, TemplateError) as exc:
                return BotStatusResponse(
                    bot_id,
                    BotStatus.failed,
                    record.pid,
                    record.profile_path,
                    f"restart aborted: launch preflight failed: {exc}",
                )
        effect = self._runtime.launch(
            record,
            probe=probe,
            wait=wait,
            marker_lock=self._marker_publication_lock,
            marker_matcher=self._matching_runtime_marker,
            ack_reader=self._read_launcher_ack,
            pipe_writer=self._write_pipe_payload,
        )
        if effect.outcome == "launch_failed":
            failure_message = f"failed to start gateway: {effect.reason}"
            try:
                self._complete_failed_intent(
                    record,
                    context=context,
                    pid=None,
                    message=failure_message,
                    reason="gateway process launch failed",
                )
            except Exception:
                return self._pending_action_required(
                    record, "launch failure could not be persisted"
                )
            self.store.append_audit_event(
                "bot.start_failed",
                bot_id=bot_id,
                error=effect.error_type,
                message=effect.reason,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=failure_message,
            )
        if effect.outcome == "registration_failed_clean":
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message="gateway start registration failed; spawned process was stopped",
            )
        if effect.outcome == "registration_failed_unknown":
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.unknown,
                pid=effect.pid,
                profile_path=record.profile_path,
                message=(
                    "gateway start registration failed and spawned process cleanup "
                    "could not be confirmed"
                ),
            )
        generation = effect.generation
        if generation is None:
            raise RuntimeError("gateway runtime returned no launch generation")
        pid = effect.pid if effect.pid is not None else generation.pid
        if effect.outcome == "startup_exited":
            returncode = effect.returncode
            failure_message = (
                f"gateway exited during startup grace period with return code {returncode}"
            )
            terminal = replace(record, pid=pid)
            try:
                self._complete_failed_intent(
                    terminal,
                    context=context,
                    pid=None,
                    stopped_at=datetime.now(UTC),
                    last_exit_code=returncode,
                    message=failure_message,
                    reason="gateway exited during startup grace period",
                )
            except Exception:
                return self._launch_completion_failure_response(record, generation)
            self.store.append_audit_event(
                "bot.start_failed",
                bot_id=bot_id,
                pid=pid,
                returncode=returncode,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=failure_message,
            )
        if effect.outcome == "readiness_exited":
            try:
                self._complete_failed_intent(
                    record,
                    context=context,
                    pid=None,
                    stopped_at=datetime.now(UTC),
                    last_exit_code=effect.returncode,
                    message="gateway process exited during readiness check",
                    reason="readiness process exited",
                )
            except Exception:
                return self._launch_completion_failure_response(record, generation)
            self.store.append_audit_event(
                "bot.start_failed",
                bot_id=bot_id,
                pid=pid,
                returncode=effect.returncode,
                reason="readiness_process_exited",
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message="gateway process exited during readiness check",
            )
        if effect.outcome == "ready":
            try:
                self._complete_started_intent(
                    record,
                    context=context,
                    status=BotStatus.running,
                    pid=pid,
                    ready_at=datetime.now(UTC),
                    reset_restart=reset_restart,
                    reason="gateway readiness probe passed",
                )
            except Exception:
                return self._launch_completion_failure_response(record, generation)
            self.store.append_audit_event("bot.start", bot_id=bot_id, pid=pid)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.running,
                pid=pid,
                profile_path=record.profile_path,
                message="gateway ready",
            )
        if effect.outcome == "readiness_timeout":
            try:
                self._complete_started_intent(
                    record,
                    context=context,
                    status=BotStatus.starting,
                    pid=pid,
                    last_error=effect.readiness_message,
                    reason="readiness probe timed out",
                )
            except Exception:
                return self._launch_completion_failure_response(record, generation)
            self.store.append_audit_event(
                "bot.start_readiness_pending",
                bot_id=bot_id,
                pid=pid,
                url=probe.url if probe is not None else None,
                message=effect.readiness_message,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.starting,
                pid=pid,
                profile_path=record.profile_path,
                message="readiness timeout; gateway process still alive",
            )
        if effect.outcome == "readiness_pending":
            try:
                self._complete_started_intent(
                    record,
                    context=context,
                    status=BotStatus.starting,
                    pid=pid,
                    reason="gateway process started; readiness probe pending",
                )
            except Exception:
                return self._launch_completion_failure_response(record, generation)
            self.store.append_audit_event(
                "bot.start_readiness_pending",
                bot_id=bot_id,
                pid=pid,
                url=probe.url if probe is not None else None,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.starting,
                pid=pid,
                profile_path=record.profile_path,
                message="started; readiness probe pending",
            )
        if effect.outcome != "running":
            raise RuntimeError(f"unknown gateway launch outcome: {effect.outcome}")
        try:
            self._complete_started_intent(
                record,
                context=context,
                status=BotStatus.running,
                pid=pid,
                ready_at=datetime.now(UTC),
                reset_restart=reset_restart,
                reason="gateway process started without readiness probe",
            )
        except Exception:
            return self._launch_completion_failure_response(record, generation)
        self.store.append_audit_event("bot.start", bot_id=bot_id, pid=pid)
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.running,
            pid=pid,
            profile_path=record.profile_path,
            message=message,
        )

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None:
        return self._runtime.preflight_start(record, timeout_seconds=timeout_seconds)

    def _write_pipe_payload(self, fd: int, payload: bytes) -> None:
        self._runtime.write_pipe_payload(fd, payload)

    def _read_launcher_ack(self, fd: int) -> bytes:
        return self._runtime.read_launcher_ack(fd)

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
        action = record.pending_action
        operation_id = record.pending_operation_id
        if action not in {"start", "restart"} or operation_id is None:
            raise RuntimeError("pending launch intent is unavailable")
        return self.store.complete_lifecycle_intent(
            record.bot_id,
            action=action,
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            status=status,
            pid=pid,
            source=context.source,
            request_id=context.request_id,
            reason=reason,
            started_at=datetime.now(UTC),
            ready_at=ready_at,
            last_error=last_error,
            last_transition_reason=reason,
            reset_restart=reset_restart,
            clear_ready_at=ready_at is None,
            clear_stopped_at=True,
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
        action = record.pending_action
        operation_id = record.pending_operation_id
        if action not in {"start", "restart"} or operation_id is None:
            raise RuntimeError("pending launch intent is unavailable")
        return self.store.complete_lifecycle_intent(
            record.bot_id,
            action=action,
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            status=BotStatus.failed,
            pid=pid,
            source=context.source,
            outcome="failure",
            request_id=context.request_id,
            reason=reason,
            error_code="gateway_start_failed",
            error_message=message,
            stopped_at=stopped_at,
            last_exit_code=last_exit_code,
            last_error=message,
            last_transition_reason=reason,
            clear_ready_at=True,
        )

    def _cleanup_interrupted_intent_launch(
        self,
        record: BotRecord,
        process: PopenLike,
        *,
        expected_fingerprint: str,
    ) -> bool:
        return self._runtime.cleanup_interrupted_launch(
            record,
            process,
            expected_fingerprint=expected_fingerprint,
        )

    def _launch_completion_failure_response(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> BotStatusResponse:
        cleaned = self._runtime.cleanup_registered_launch(record, generation)
        if cleaned:
            return BotStatusResponse(
                record.bot_id,
                BotStatus.failed,
                None,
                record.profile_path,
                "gateway start completion could not be persisted; spawned process was stopped",
            )
        return BotStatusResponse(
            record.bot_id,
            BotStatus.unknown,
            generation.pid,
            record.profile_path,
            "gateway start completion is unknown and cleanup could not be confirmed",
        )
