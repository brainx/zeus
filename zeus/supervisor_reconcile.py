from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from zeus import process_identity as _process_identity
from zeus.errors import (
    BotDeleteError,
)
from zeus.gateway_launcher import (
    LaunchPayloadError,
)
from zeus.gateway_marker import (
    is_compat_runtime_marker,
)
from zeus.gateway_runtime import (
    StopEffect,
)
from zeus.lifecycle import LifecycleEvent
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
    DesiredState,
    RestartPolicy,
)
from zeus.process_lock import LockTimeoutError
from zeus.readiness import ReadinessProbe
from zeus.reconciliation import (
    BotReconcileResult,
    FleetReconciler,
    ReconcileExecution,
    ReconcileLockTimeoutError,
    ReconcileOutcome,
    ReconcileRunSummary,
    ReconcileSnapshotDriftError,
)
from zeus.supervisor_contracts import (
    _GatewayGeneration,
    _LifecycleContext,
    _MarkerObservation,
    _ReconcileLaunch,
)
from zeus.supervisor_reconcile_host import ReconcileHost

_PidState = _process_identity.PidState


class ReconcileOperations:
    """Stateless reconcile operations; callbacks are resolved from the current host."""

    @staticmethod
    def reconcile(
        host: ReconcileHost,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Sequence[tuple[str, str]] | None = None,
    ) -> list[BotStatusResponse]:
        try:
            execution = host.reconcile_execution(
                bot_id,
                now=now,
                force=force,
                reset_restart=reset_restart,
                source=source,
                request_id=request_id,
                bot_snapshot=bot_snapshot,
            )
        except ReconcileLockTimeoutError as error:
            raise LockTimeoutError(error.lock_path, error.timeout_seconds) from error
        return list(execution.legacy_responses)

    @staticmethod
    def reconcile_summary(
        host: ReconcileHost,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Sequence[tuple[str, str]] | None = None,
    ) -> ReconcileRunSummary:
        return host.reconcile_execution(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        ).summary

    @staticmethod
    def reconcile_execution(
        host: ReconcileHost,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        bot_snapshot: Sequence[tuple[str, str]] | None = None,
    ) -> ReconcileExecution:
        return FleetReconciler(host.store, host).execute(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        )

    @staticmethod
    def validate_reconcile_request(
        host: ReconcileHost, source: str, request_id: str | None
    ) -> None:
        host._lifecycle_context(source, request_id)

    @staticmethod
    def validate_reconcile_target(
        host: ReconcileHost,
        bot_id: str,
        *,
        expected_profile_path: str | None = None,
    ) -> str:
        with host.bot_lock(bot_id), host._bot_process_lock(bot_id):
            record = host.store.get_bot(bot_id)
            if record is None:
                raise KeyError(f"unknown bot: {bot_id}")
            if expected_profile_path is not None and record.profile_path != expected_profile_path:
                raise ReconcileSnapshotDriftError(bot_id)
            return record.profile_path

    @staticmethod
    def reconcile_one(
        host: ReconcileHost,
        bot_id: str,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        expected_profile_path: str | None = None,
    ) -> BotReconcileResult:
        result, _response = host.reconcile_one_execution(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            expected_profile_path=expected_profile_path,
        )
        return result

    @staticmethod
    def reconcile_one_execution(
        host: ReconcileHost,
        bot_id: str,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        expected_profile_path: str | None = None,
    ) -> tuple[BotReconcileResult, BotStatusResponse]:
        context = host._lifecycle_context(source, request_id)
        current_time = now or datetime.now(UTC)
        started_at = datetime.now(UTC)
        with host.bot_lock(bot_id), host._bot_process_lock(bot_id):
            before = host.store.get_bot(bot_id)
            if before is None:
                if expected_profile_path is not None:
                    raise ReconcileSnapshotDriftError(bot_id)
                raise KeyError(f"unknown bot: {bot_id}")
            if expected_profile_path is not None and before.profile_path != expected_profile_path:
                raise ReconcileSnapshotDriftError(bot_id)
            prior_events = host.store.list_lifecycle_events(bot_id, limit=1, before=None)
            prior_event_id = prior_events[0].event_id if prior_events else None
            try:
                response = host._reconcile_record(
                    before,
                    current_time,
                    force=force,
                    reset_restart=reset_restart,
                    context=context,
                )
            except ReconcileSnapshotDriftError:
                raise
            except Exception as error:
                loaded_after_error = host.store.get_bot(bot_id)
                if loaded_after_error is None and expected_profile_path is not None:
                    raise ReconcileSnapshotDriftError(bot_id) from error
                after = loaded_after_error or before
                current_event = host._latest_reconcile_event(bot_id, prior_event_id)
                lock_timeout = isinstance(error, LockTimeoutError)
                message = (
                    "bot reconciliation lock timed out"
                    if lock_timeout
                    else "bot reconciliation failed"
                )
                result = BotReconcileResult(
                    bot_id=bot_id,
                    outcome=ReconcileOutcome.error,
                    desired_state=after.desired_state.value,
                    observed_status=after.status.value,
                    pid=after.pid,
                    action=current_event.action if current_event is not None else "reconcile",
                    message=message,
                    error_code="lock_timeout" if lock_timeout else "reconcile_error",
                    event_id=(current_event.event_id if current_event is not None else None),
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )
                return result, BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.failed,
                    pid=after.pid,
                    profile_path=before.profile_path,
                    message=message,
                )
            loaded_after = host.store.get_bot(bot_id)
            if loaded_after is None:
                if expected_profile_path is not None:
                    raise ReconcileSnapshotDriftError(bot_id)
                raise KeyError(f"unknown bot: {bot_id}")
            current_event = host._latest_reconcile_event(bot_id, prior_event_id)
            return (
                host._reconcile_result_from_response(
                    before,
                    loaded_after,
                    response,
                    current_event=current_event,
                    started_at=started_at,
                ),
                response,
            )

    @staticmethod
    def _latest_reconcile_event(
        host: ReconcileHost,
        bot_id: str,
        prior_event_id: int | None,
    ) -> LifecycleEvent | None:
        current_events = host.store.list_lifecycle_events(bot_id, limit=1, before=None)
        if not current_events or current_events[0].event_id == prior_event_id:
            return None
        return current_events[0]

    @staticmethod
    def _reconcile_result_from_response(
        host: ReconcileHost,
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event: LifecycleEvent | None,
        started_at: datetime,
    ) -> BotReconcileResult:
        outcome = host._reconcile_outcome(
            before,
            after,
            response,
            current_event_action=(current_event.action if current_event is not None else None),
        )
        action = (
            current_event.action
            if current_event is not None
            else {
                ReconcileOutcome.healthy: "none",
                ReconcileOutcome.changed: "reconcile",
                ReconcileOutcome.pending: "wait",
                ReconcileOutcome.action_required: "manual",
                ReconcileOutcome.error: "reconcile",
                ReconcileOutcome.skipped: "skip",
            }[outcome]
        )
        error_code = current_event.error_code if current_event is not None else None
        message = response.message
        if outcome is ReconcileOutcome.action_required and error_code is None:
            error_code = "action_required"
        elif outcome is ReconcileOutcome.error:
            if error_code is None:
                error_code = "reconcile_error"
            message = "bot reconciliation failed"
        return BotReconcileResult(
            bot_id=after.bot_id,
            outcome=outcome,
            desired_state=after.desired_state.value,
            observed_status=response.status.value,
            pid=response.pid,
            action=action,
            message=message,
            error_code=error_code,
            event_id=(current_event.event_id if current_event is not None else None),
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

    @staticmethod
    def _reconcile_outcome(
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event_action: str | None,
    ) -> ReconcileOutcome:
        if response.message.startswith("action required:"):
            return ReconcileOutcome.action_required
        if (
            response.status is BotStatus.starting
            or current_event_action == "bot.restart.schedule"
            or (
                response.status is BotStatus.failed
                and after.desired_state is DesiredState.running
                and after.next_restart_at is not None
            )
        ):
            return ReconcileOutcome.pending
        if response.status in {BotStatus.failed, BotStatus.unknown}:
            return ReconcileOutcome.error
        changed_fields = (
            "status",
            "pid",
            "restart_attempts",
            "next_restart_at",
            "pending_operation_id",
            "pending_action",
            "desired_state",
            "desired_revision",
        )
        if current_event_action is not None or any(
            getattr(before, field) != getattr(after, field) for field in changed_fields
        ):
            return ReconcileOutcome.changed
        return ReconcileOutcome.healthy

    @staticmethod
    def _reconcile_record(
        host: ReconcileHost,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        reset_restart: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        if record.pending_operation_id is not None:
            return host._recover_pending_intent(record, context=context, allow_launch=True)
        if reset_restart:
            host._update_restart(
                context,
                record.bot_id,
                status=record.status,
                pid=record.pid,
                restart_attempts=0,
                next_restart_at=None,
                action="bot.restart.reset",
                reason="restart backoff reset",
            )
            record = replace(record, restart_attempts=0, next_restart_at=None)

        pid_state = host._pid_state(record.pid) if record.pid else _PidState.dead
        if record.pid and pid_state == _PidState.unknown:
            return host._unknown_pid_response(record, "reconcile the gateway", context=context)
        if record.pid and pid_state == _PidState.alive:
            if not host._pid_owned(record.profile_path, record.pid, record.bot_id):
                host._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.failed,
                    pid=record.pid,
                    last_error="recorded gateway PID ownership could not be verified",
                    last_transition_reason="ownership verification failed",
                )
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.failed,
                    pid=record.pid,
                    profile_path=record.profile_path,
                    message="recorded gateway PID is alive but ownership could not be verified",
                )
            response = host._status_for_live_record(record, context=context)
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=response.status,
                pid=response.pid,
                profile_path=response.profile_path,
                message=response.message or "running",
            )

        try:
            with host._marker_publication_lock(record):
                prepared = host._prepare_reconcile_dead_record_locked(
                    record,
                    now,
                    force=force,
                    context=context,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return host._pending_action_required(record, str(exc))
        if isinstance(prepared, BotStatusResponse):
            return prepared
        result = host._start_record(
            prepared.record,
            reset_restart=False,
            message=(
                "restarted by reconcile: "
                f"attempt {prepared.attempt}/{prepared.restart_max_attempts}"
            ),
            context=context,
            probe=prepared.probe,
        )
        if result.status == BotStatus.running:
            host.store.append_audit_event(
                "bot.reconcile.restart_started",
                bot_id=record.bot_id,
                pid=result.pid,
                attempt=prepared.attempt,
            )
        return result

    @staticmethod
    def _prepare_reconcile_dead_record_locked(
        host: ReconcileHost,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse | _ReconcileLaunch:
        marker = host._classify_existing_runtime_marker(record, expected_pid=record.pid)
        if marker.kind == "dead":
            generation = host._gateway_generation(marker)
            if generation is None or not host._remove_gateway_generation_marker_locked(
                record, generation
            ):
                return host._pending_action_required(
                    record, "dead gateway marker cleanup could not be verified"
                )
        elif marker.kind != "missing":
            return host._pending_action_required(
                record,
                marker.reason or "recorded gateway marker ownership is unresolved",
            )

        if record.desired_state is DesiredState.stopped:
            if record.status is not BotStatus.stopped or record.pid is not None:
                host._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.stopped,
                    pid=None,
                    action="bot.reconcile.stopped",
                    last_transition_reason="reconcile confirmed gateway is stopped",
                )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )

        if record.restart_policy != RestartPolicy.on_failure:
            host._update_lifecycle(
                context,
                record.bot_id,
                BotStatus.failed,
                pid=None,
                stopped_at=datetime.now(UTC),
                last_error="gateway process is not running",
                last_transition_reason="manual restart policy did not restart bot",
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message="manual policy: not restarting",
            )

        completed_attempts = record.restart_attempts
        if record.next_restart_at is not None:
            # Scheduling already counted the pending attempt; it must still run.
            completed_attempts = max(0, completed_attempts - 1)
        if completed_attempts >= record.restart_max_attempts:
            host._update_restart(
                context,
                record.bot_id,
                status=BotStatus.failed,
                pid=None,
                restart_attempts=record.restart_attempts,
                next_restart_at=None,
                action="bot.restart.limit_reached",
                reason="restart attempt limit reached",
                outcome="failure",
                error_code="restart_limit_reached",
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=(
                    "restart limit reached: "
                    f"{record.restart_attempts}/{record.restart_max_attempts}"
                ),
            )

        if record.next_restart_at is None and not force:
            delay = host._restart_delay(record)
            next_restart_at = now + timedelta(seconds=delay)
            attempt = record.restart_attempts + 1
            host._update_restart(
                context,
                record.bot_id,
                status=BotStatus.failed,
                pid=None,
                restart_attempts=attempt,
                next_restart_at=next_restart_at,
                action="bot.restart.schedule",
                reason="restart scheduled by reconcile",
            )
            host.store.append_audit_event(
                "bot.reconcile.restart_scheduled",
                bot_id=record.bot_id,
                attempt=attempt,
                next_restart_at=next_restart_at.isoformat(),
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=(
                    "restart scheduled: "
                    f"attempt {attempt}/{record.restart_max_attempts} in {delay:g}s"
                ),
            )

        if record.next_restart_at is not None and record.next_restart_at > now and not force:
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=(
                    "restart pending: "
                    f"attempt {record.restart_attempts}/{record.restart_max_attempts} "
                    f"due at {record.next_restart_at.isoformat()}"
                ),
            )

        attempt = record.restart_attempts
        if record.next_restart_at is None or attempt == 0:
            attempt += 1
        host._update_restart(
            context,
            record.bot_id,
            status=BotStatus.failed,
            pid=None,
            restart_attempts=attempt,
            next_restart_at=None,
            action="bot.restart.attempt",
            reason="restart attempt started by reconcile",
        )
        refreshed = host._require_bot(record.bot_id)
        probe = host._preflight_start(refreshed, timeout_seconds=None)
        refreshed = host.store.begin_lifecycle_intent(
            record.bot_id,
            action="start",
            operation_id=context.operation_id,
            source=context.source,
            request_id=context.request_id,
            reason="restart attempt started by reconcile",
        )
        return _ReconcileLaunch(
            refreshed,
            probe,
            attempt,
            record.restart_max_attempts,
        )

    @staticmethod
    def _is_compat_runtime_marker(payload: dict[str, object]) -> bool:
        return is_compat_runtime_marker(payload)

    @staticmethod
    def _recover_pending_intent(
        host: ReconcileHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_launch: bool,
    ) -> BotStatusResponse:
        return host._intent_recovery.recover(
            host,
            record,
            context=context,
            allow_launch=allow_launch,
        )

    @staticmethod
    def _recovery_lifecycle_context(
        operation_id: str,
        context: _LifecycleContext,
    ) -> _LifecycleContext:
        return _LifecycleContext(operation_id, context.source, context.request_id)

    @staticmethod
    def _pending_launch_preflight(
        host: ReconcileHost,
        record: BotRecord,
        operation_id: str,
    ) -> tuple[ReadinessProbe | None, str]:
        probe = host._preflight_start(record, timeout_seconds=None)
        expected = host.adapter.launcher_payload(
            record.bot_id,
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            readiness_probe=probe,
        )
        marker_template = expected["marker"]
        if type(marker_template) is not dict:
            raise ValueError("invalid expected marker")
        return probe, str(marker_template["command_fingerprint"])

    @staticmethod
    def _recover_pending_stop_intent(
        host: ReconcileHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        try:
            with host._marker_publication_lock(record):
                return host._recover_pending_stop_intent_locked(
                    record,
                    context=context,
                    allow_stop=allow_stop,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return host._pending_action_required(record, str(exc))

    @staticmethod
    def _recover_pending_launch(
        host: ReconcileHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        probe: ReadinessProbe | None,
        fingerprint: str,
        action: str,
        allow_launch: bool,
    ) -> BotStatusResponse | None:
        try:
            with host._marker_publication_lock(record):
                return host._intent_recovery.recover_pending_launch_locked(
                    host,
                    record,
                    context=context,
                    probe=probe,
                    fingerprint=fingerprint,
                    action=action,
                    allow_launch=allow_launch,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return host._pending_action_required(record, str(exc))

    @staticmethod
    def _recover_pending_stop_intent_locked(
        host: ReconcileHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return host._intent_recovery.recover_pending_stop_intent_locked(
            host,
            record,
            context=context,
            allow_stop=allow_stop,
        )

    @staticmethod
    def _pending_restart_old_marker(
        host: ReconcileHost,
        record: BotRecord,
        observed: _MarkerObservation | None = None,
    ) -> _MarkerObservation | None:
        return host._intent_recovery.pending_restart_old_marker(
            host,
            record,
            observed,
        )

    @staticmethod
    def _recover_pending_restart_predecessor(
        host: ReconcileHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse | None:
        try:
            with host._marker_publication_lock(record):
                return host._intent_recovery.recover_pending_restart_predecessor_locked(
                    host,
                    record,
                    context=context,
                    allow_stop=allow_stop,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return host._pending_action_required(record, str(exc))

    @staticmethod
    def _recover_pending_restart_old_gateway(
        host: ReconcileHost,
        record: BotRecord,
        marker: _MarkerObservation,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return host._intent_recovery.recover_pending_restart_old_gateway(
            host,
            record,
            marker,
            context=context,
            allow_stop=allow_stop,
        )

    @staticmethod
    def _stop_pending_restart_old_gateway(
        host: ReconcileHost,
        record: BotRecord,
        generation: _GatewayGeneration,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        return host._intent_recovery.stop_pending_restart_old_gateway(
            host,
            record,
            generation,
            context=context,
        )

    @staticmethod
    def _stop_gateway_generation_locked(
        host: ReconcileHost,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> StopEffect:
        return host._runtime.stop_generation_locked(
            record,
            generation,
            kill_after_timeout=None,
            classify_exact=host._classify_exact_gateway_generation,
            remove_generation=host._remove_gateway_generation_marker_locked,
        )

    @staticmethod
    def _append_recovery_audit_event(host: ReconcileHost, action: str, **values: object) -> None:
        host.store.append_audit_event(action, **values)

    @staticmethod
    def _restart_delay(host: ReconcileHost, record: BotRecord) -> float:
        delay = record.restart_backoff_seconds * (2**record.restart_attempts)
        return float(min(delay, host.restart_backoff_cap_seconds))
