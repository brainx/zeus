from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, TypeVar

from zeus.errors import BotDeleteError
from zeus.gateway_marker import GatewayGeneration
from zeus.gateway_runtime import MarkerObservation, StopEffect
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
    TemplateError,
)
from zeus.process_identity import PidState
from zeus.readiness import ReadinessProbe, ReadinessResult

_ContextT = TypeVar("_ContextT")


class _RecoveryHost(Protocol[_ContextT]):
    def _recovery_lifecycle_context(
        self,
        operation_id: str,
        context: _ContextT,
    ) -> _ContextT: ...

    def _pending_action_required(
        self,
        record: BotRecord,
        reason: str,
    ) -> BotStatusResponse: ...

    def _pending_launch_preflight(
        self,
        record: BotRecord,
        operation_id: str,
    ) -> tuple[ReadinessProbe | None, str]: ...

    def _recover_pending_stop_intent(
        self,
        record: BotRecord,
        *,
        context: _ContextT,
        allow_stop: bool,
    ) -> BotStatusResponse: ...

    def _recover_pending_restart_predecessor(
        self,
        record: BotRecord,
        *,
        context: _ContextT,
        allow_stop: bool,
    ) -> BotStatusResponse | None: ...

    def _recover_pending_launch(
        self,
        record: BotRecord,
        *,
        context: _ContextT,
        probe: ReadinessProbe | None,
        fingerprint: str,
        action: str,
        allow_launch: bool,
    ) -> BotStatusResponse | None: ...

    def _matching_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_fingerprint: str,
        require_live_command: bool,
    ) -> MarkerObservation: ...

    def _probe_once(self, probe: ReadinessProbe) -> ReadinessResult: ...

    def _complete_started_intent(
        self,
        record: BotRecord,
        *,
        context: _ContextT,
        status: BotStatus,
        pid: int,
        reason: str,
        ready_at: datetime | None = ...,
        last_error: str | None = ...,
        reset_restart: bool = ...,
    ) -> BotRecord: ...

    def _start_record(
        self,
        record: BotRecord,
        *,
        reset_restart: bool,
        message: str,
        context: _ContextT,
        probe: ReadinessProbe | None,
    ) -> BotStatusResponse: ...

    def _pid_state(self, pid: int) -> PidState: ...

    def _read_strict_runtime_marker(
        self,
        bot_id: str,
        profile_path: str,
    ) -> MarkerObservation: ...

    def _remove_owned_launch_marker_locked(
        self,
        record: BotRecord,
        *,
        observed: MarkerObservation,
    ) -> bool: ...

    def _complete_stopped_intent(
        self,
        record: BotRecord,
        *,
        context: _ContextT,
        reason: str,
    ) -> BotRecord: ...

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool: ...

    def _stop_record_effect_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        context: _ContextT,
        complete_stop: bool,
    ) -> BotStatusResponse: ...

    def _is_compat_runtime_marker(self, payload: dict[str, object]) -> bool: ...

    def _pending_restart_old_marker(
        self,
        record: BotRecord,
        observed: MarkerObservation | None = None,
    ) -> MarkerObservation | None: ...

    def _classify_schema3_runtime_marker(
        self,
        record: BotRecord,
        payload: dict[str, object],
        *,
        expected_pid: int | None,
        expected_revision: int,
        require_live_command: bool,
    ) -> MarkerObservation: ...

    def _recover_pending_restart_old_gateway(
        self,
        record: BotRecord,
        marker: MarkerObservation,
        *,
        context: _ContextT,
        allow_stop: bool,
    ) -> BotStatusResponse: ...

    def _gateway_generation(
        self,
        marker: MarkerObservation,
    ) -> GatewayGeneration | None: ...

    def _stop_pending_restart_old_gateway(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        context: _ContextT,
    ) -> BotStatusResponse: ...

    def _remove_gateway_generation_marker_locked(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool: ...

    def _update_lifecycle(
        self,
        context: _ContextT,
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

    def _stop_gateway_generation_locked(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> StopEffect: ...

    def _append_recovery_audit_event(self, action: str, **values: object) -> None: ...


class PendingIntentRecovery:
    def recover(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        *,
        context: _ContextT,
        allow_launch: bool,
    ) -> BotStatusResponse:
        action = record.pending_action
        operation_id = record.pending_operation_id
        if action is None or operation_id is None:
            return host._pending_action_required(
                record,
                "pending lifecycle correlation is invalid",
            )
        recovery_context = host._recovery_lifecycle_context(operation_id, context)
        if action == "stop":
            return host._recover_pending_stop_intent(
                record,
                context=recovery_context,
                allow_stop=allow_launch,
            )
        if action not in {"start", "restart"}:
            return host._pending_action_required(
                record,
                "pending lifecycle action is invalid",
            )
        try:
            probe, fingerprint = host._pending_launch_preflight(record, operation_id)
        except (OSError, ValueError, TemplateError, BotDeleteError) as exc:
            return host._pending_action_required(record, f"launch preflight failed: {exc}")
        if action == "restart":
            predecessor_result = host._recover_pending_restart_predecessor(
                record,
                context=recovery_context,
                allow_stop=allow_launch,
            )
            if predecessor_result is not None:
                return predecessor_result
        pending_result = host._recover_pending_launch(
            record,
            context=recovery_context,
            probe=probe,
            fingerprint=fingerprint,
            action=action,
            allow_launch=allow_launch,
        )
        if pending_result is not None:
            return pending_result
        return host._start_record(
            record,
            reset_restart=action == "restart",
            message="recovered interrupted gateway launch",
            context=recovery_context,
            probe=probe,
        )

    def recover_pending_launch_locked(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        *,
        context: _ContextT,
        probe: ReadinessProbe | None,
        fingerprint: str,
        action: str,
        allow_launch: bool,
    ) -> BotStatusResponse | None:
        marker = host._matching_runtime_marker(
            record,
            expected_fingerprint=fingerprint,
            require_live_command=True,
        )
        if marker.kind == "live" and marker.payload is not None:
            marker_pid = marker.payload["pid"]
            if isinstance(marker_pid, bool) or not isinstance(marker_pid, int):
                return host._pending_action_required(record, "live marker PID is invalid")
            status = BotStatus.starting if probe is not None else BotStatus.running
            ready_at = None if probe is not None else datetime.now(UTC)
            if probe is not None:
                readiness = host._probe_once(probe)
                if readiness.ready:
                    status = BotStatus.running
                    ready_at = datetime.now(UTC)
            try:
                host._complete_started_intent(
                    record,
                    context=context,
                    status=status,
                    pid=marker_pid,
                    ready_at=ready_at,
                    reset_restart=True,
                    reason="recovery adopted registered gateway",
                )
            except Exception:
                return host._pending_action_required(
                    record,
                    "gateway adoption could not be persisted",
                )
            return BotStatusResponse(
                record.bot_id,
                status,
                marker_pid,
                record.profile_path,
                "recovered registered gateway",
            )
        if marker.kind == "untrusted":
            return host._pending_action_required(record, marker.reason)
        if not allow_launch:
            return host._pending_action_required(
                record,
                "desired running gateway is missing; reconcile is required",
            )
        if marker.kind == "dead":
            generation = host._gateway_generation(marker)
            if generation is None or not host._remove_gateway_generation_marker_locked(
                record,
                generation,
            ):
                return host._pending_action_required(
                    record,
                    "dead gateway marker cleanup failed",
                )
            if action == "restart":
                return BotStatusResponse(
                    record.bot_id,
                    BotStatus.starting,
                    None,
                    record.profile_path,
                    "restart pending: removed dead gateway marker; launch on next reconcile",
                )
        return None

    def recover_pending_stop_intent_locked(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        *,
        context: _ContextT,
        allow_stop: bool,
    ) -> BotStatusResponse:
        pid_state = host._pid_state(record.pid) if record.pid else PidState.dead
        if pid_state is PidState.unknown:
            return host._pending_action_required(record, "gateway PID liveness is unknown")
        if not record.pid or pid_state is PidState.dead:
            observed = host._read_strict_runtime_marker(record.bot_id, record.profile_path)
            if not host._remove_owned_launch_marker_locked(record, observed=observed):
                return host._pending_action_required(
                    record,
                    "stale gateway marker ownership could not be verified",
                )
            try:
                host._complete_stopped_intent(
                    record,
                    context=context,
                    reason="recovery confirmed gateway stopped",
                )
            except Exception:
                return host._pending_action_required(
                    record,
                    "stopped state could not be persisted",
                )
            return BotStatusResponse(
                record.bot_id,
                BotStatus.stopped,
                None,
                record.profile_path,
                "recovered interrupted stop",
            )
        if not allow_stop:
            if not host._pid_owned(record.profile_path, record.pid, record.bot_id):
                return host._pending_action_required(
                    record,
                    "gateway ownership could not be verified",
                )
            return host._pending_action_required(
                record,
                "stop intent is pending reconciliation",
            )
        return host._stop_record_effect_locked(
            record,
            kill_after_timeout=None,
            context=context,
            complete_stop=True,
        )

    def pending_restart_old_marker(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        observed: MarkerObservation | None = None,
    ) -> MarkerObservation | None:
        if observed is None:
            observed = host._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return None
        payload = observed.payload
        marker_operation = payload.get("operation_id")
        marker_revision = payload.get("desired_revision")
        if (
            type(marker_operation) is not str
            or marker_operation == record.pending_operation_id
            or type(marker_revision) is not int
            or marker_revision != record.desired_revision - 1
        ):
            return None
        return host._classify_schema3_runtime_marker(
            record,
            payload,
            expected_pid=record.pid,
            expected_revision=record.desired_revision - 1,
            require_live_command=True,
        )

    def recover_pending_restart_predecessor_locked(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        *,
        context: _ContextT,
        allow_stop: bool,
    ) -> BotStatusResponse | None:
        predecessor = host._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if (
            record.pid is not None
            and predecessor.kind == "present"
            and predecessor.payload is not None
            and host._is_compat_runtime_marker(predecessor.payload)
        ):
            return host._pending_action_required(
                record,
                "schema-v2 or legacy gateway restart requires manual process resolution",
            )
        old_marker = host._pending_restart_old_marker(record, predecessor)
        if old_marker is not None:
            return host._recover_pending_restart_old_gateway(
                record,
                old_marker,
                context=context,
                allow_stop=allow_stop,
            )
        if record.pid is None or predecessor.kind != "missing":
            return None
        pid_state = host._pid_state(record.pid)
        if pid_state is PidState.unknown:
            return host._pending_action_required(
                record,
                "previous gateway PID liveness is unknown",
            )
        if pid_state is PidState.alive:
            return host._pending_action_required(record, "previous gateway marker is missing")
        if not allow_stop:
            return host._pending_action_required(
                record,
                "restart intent is pending reconciliation",
            )
        try:
            host._update_lifecycle(
                context,
                record.bot_id,
                BotStatus.stopped,
                pid=None,
                action="bot.restart.old_process_recovered",
                stopped_at=datetime.now(UTC),
                last_transition_reason="recovery confirmed the previous gateway stopped",
                clear_ready_at=True,
            )
        except Exception:
            return host._pending_action_required(
                record,
                "previous gateway stop could not be persisted",
            )
        return BotStatusResponse(
            record.bot_id,
            BotStatus.starting,
            None,
            record.profile_path,
            "restart pending: recovered stopped gateway; launch on next reconcile",
        )

    def recover_pending_restart_old_gateway(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        marker: MarkerObservation,
        *,
        context: _ContextT,
        allow_stop: bool,
    ) -> BotStatusResponse:
        if marker.kind == "untrusted":
            return host._pending_action_required(
                record,
                marker.reason or "previous gateway ownership could not be verified",
            )
        if not allow_stop:
            return host._pending_action_required(
                record,
                "restart intent is pending reconciliation",
            )
        generation = host._gateway_generation(marker)
        if generation is None:
            return host._pending_action_required(
                record,
                "previous gateway marker correlation is invalid",
            )
        if marker.kind == "live":
            if record.pid is None:
                return host._pending_action_required(
                    record,
                    "previous gateway PID is not recorded",
                )
            stopped = host._stop_pending_restart_old_gateway(
                record,
                generation,
                context=context,
            )
            if stopped.status is not BotStatus.stopped:
                return stopped
            return BotStatusResponse(
                record.bot_id,
                BotStatus.starting,
                None,
                record.profile_path,
                "restart pending: previous gateway stopped; launch on next reconcile",
            )
        if marker.kind != "dead" or marker.payload is None:
            return host._pending_action_required(
                record,
                "previous gateway marker ownership could not be verified",
            )
        if not host._remove_gateway_generation_marker_locked(record, generation):
            return host._pending_action_required(
                record,
                "previous gateway marker cleanup could not be verified",
            )
        try:
            host._update_lifecycle(
                context,
                record.bot_id,
                BotStatus.stopped,
                pid=None,
                action="bot.restart.old_process_recovered",
                stopped_at=datetime.now(UTC),
                last_transition_reason="recovery confirmed the previous gateway stopped",
                clear_ready_at=True,
            )
        except Exception:
            return host._pending_action_required(
                record,
                "previous gateway stop could not be persisted",
            )
        return BotStatusResponse(
            record.bot_id,
            BotStatus.starting,
            None,
            record.profile_path,
            "restart pending: recovered stopped gateway; launch on next reconcile",
        )

    def stop_pending_restart_old_gateway(
        self,
        host: _RecoveryHost[_ContextT],
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        context: _ContextT,
    ) -> BotStatusResponse:
        effect = host._stop_gateway_generation_locked(record, generation)
        if effect.outcome != "stopped":
            if effect.kill_result is not None:
                host._append_recovery_audit_event(
                    "bot.stop_kill",
                    bot_id=record.bot_id,
                    pid=generation.pid,
                    succeeded=bool(effect.kill_succeeded),
                )
            reasons = {
                "term_denied": "could not send SIGTERM to the previous gateway",
                "kill_denied": "could not send SIGKILL to the previous gateway",
                "grace_expired": "previous gateway did not stop before the grace period expired",
                "cleanup_unverified": ("previous gateway marker cleanup could not be verified"),
            }
            return host._pending_action_required(
                record,
                reasons.get(effect.outcome, effect.reason),
            )
        if effect.kill_result is not None:
            host._append_recovery_audit_event(
                "bot.stop_kill",
                bot_id=record.bot_id,
                pid=generation.pid,
                succeeded=bool(effect.kill_succeeded),
            )
        try:
            host._update_lifecycle(
                context,
                record.bot_id,
                BotStatus.stopped,
                pid=None,
                action="bot.restart.old_process_stopped",
                stopped_at=datetime.now(UTC),
                last_transition_reason="restart stopped the previous gateway",
                clear_ready_at=True,
            )
        except Exception:
            return host._pending_action_required(
                record,
                "previous gateway stop could not be persisted",
            )
        host._append_recovery_audit_event(
            "bot.stop",
            bot_id=record.bot_id,
            pid=generation.pid,
        )
        return BotStatusResponse(
            record.bot_id,
            BotStatus.stopped,
            None,
            record.profile_path,
            "gateway shutdown completed",
        )
