from __future__ import annotations

from datetime import UTC, datetime

from zeus.errors import (
    BotDeleteError,
)
from zeus.gateway_launcher import (
    LaunchPayloadError,
)
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
)
from zeus.supervisor_contracts import (
    _LifecycleContext,
    _MarkerObservation,
)
from zeus.supervisor_stop_host import StopHost


class StopOperations:
    """Stateless stop operations; callbacks are resolved from the current host."""

    @staticmethod
    def stop(
        host: StopHost,
        bot_id: str,
        *,
        kill_after_timeout: bool | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = host._lifecycle_context(source, request_id)
        with host.bot_lock(bot_id), host._bot_process_lock(bot_id):
            return host._stop_locked(
                bot_id,
                kill_after_timeout=kill_after_timeout,
                context=context,
            )

    @staticmethod
    def _stop_locked(
        host: StopHost,
        bot_id: str,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        record = host._require_bot(bot_id)
        if record.pending_operation_id is not None:
            return host._pending_action_required(record, "lifecycle intent is already pending")
        record = host.store.begin_lifecycle_intent(
            bot_id,
            action="stop",
            operation_id=context.operation_id,
            source=context.source,
            request_id=context.request_id,
            reason="gateway stop requested",
        )
        return host._stop_record_effect(
            record,
            kill_after_timeout=kill_after_timeout,
            context=context,
            complete_stop=True,
        )

    @staticmethod
    def _stop_record_effect(
        host: StopHost,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse:
        try:
            with host._marker_publication_lock(record):
                return host._stop_record_effect_locked(
                    record,
                    kill_after_timeout=kill_after_timeout,
                    context=context,
                    complete_stop=complete_stop,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return host._pending_action_required(record, str(exc))

    @staticmethod
    def _stop_record_effect_locked(
        host: StopHost,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse:
        effect = host._runtime.stop_locked(
            record,
            kill_after_timeout=kill_after_timeout,
            read_marker=host._read_strict_runtime_marker,
            classify_existing=host._classify_existing_runtime_marker,
            classify_exact=host._classify_exact_gateway_generation,
            remove_owned=host._remove_owned_launch_marker_locked,
            remove_generation=host._remove_gateway_generation_marker_locked,
        )
        if effect.outcome not in {"not_running", "stopped"}:
            if effect.kill_result is not None:
                host.store.append_audit_event(
                    "bot.stop_kill",
                    bot_id=record.bot_id,
                    pid=effect.pid,
                    succeeded=bool(effect.kill_succeeded),
                )
            if effect.outcome == "grace_expired":
                reason = (
                    "gateway did not stop before grace period expired; "
                    "Hermes async delegations may still be running"
                )
            else:
                reason = effect.reason
            return host._pending_action_required(record, reason)
        if effect.outcome == "not_running":
            if complete_stop:
                try:
                    host._complete_stopped_intent(
                        record,
                        context=context,
                        reason="gateway process was not running",
                    )
                except Exception:
                    return host._pending_action_required(
                        record, "stopped state could not be persisted"
                    )
            host.store.append_audit_event("bot.stop", bot_id=record.bot_id, pid=record.pid)
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )
        if effect.kill_result is not None:
            host.store.append_audit_event(
                "bot.stop_kill",
                bot_id=record.bot_id,
                pid=effect.pid,
                succeeded=bool(effect.kill_succeeded),
            )
        if not complete_stop:
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
                    record, "previous gateway stop could not be persisted"
                )
        if complete_stop:
            try:
                host._complete_stopped_intent(
                    record,
                    context=context,
                    reason="gateway shutdown completed",
                )
            except Exception:
                return host._pending_action_required(record, "stopped state could not be persisted")
        host.store.append_audit_event("bot.stop", bot_id=record.bot_id, pid=record.pid)
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=BotStatus.stopped,
            pid=None,
            profile_path=record.profile_path,
            message="gateway shutdown completed",
        )

    @staticmethod
    def _complete_stopped_intent(
        host: StopHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        reason: str,
    ) -> BotRecord:
        operation_id = record.pending_operation_id
        if record.pending_action != "stop" or operation_id is None:
            raise RuntimeError("pending stop intent is unavailable")
        return host.store.complete_lifecycle_intent(
            record.bot_id,
            action="stop",
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            status=BotStatus.stopped,
            pid=None,
            source=context.source,
            request_id=context.request_id,
            reason=reason,
            stopped_at=datetime.now(UTC),
            last_transition_reason=reason,
            reset_restart=True,
            clear_ready_at=True,
        )

    @staticmethod
    def _remove_owned_launch_marker_locked(
        host: StopHost,
        record: BotRecord,
        *,
        observed: _MarkerObservation | None = None,
    ) -> bool:
        return host._runtime.remove_owned_launch_marker_locked(record, observed=observed)

    @staticmethod
    def restart(
        host: StopHost,
        bot_id: str,
        *,
        wait: bool = False,
        timeout_seconds: float | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = host._lifecycle_context(source, request_id)
        with host.bot_lock(bot_id), host._bot_process_lock(bot_id):
            record = host._require_bot(bot_id)
            if record.pending_operation_id is not None:
                return host._pending_action_required(record, "lifecycle intent is already pending")
            probe = host._preflight_start(record, timeout_seconds=timeout_seconds)
            record = host.store.begin_lifecycle_intent(
                bot_id,
                action="restart",
                operation_id=context.operation_id,
                source=context.source,
                request_id=context.request_id,
                reason="gateway restart requested",
            )
            stopped = host._stop_record_effect(
                record,
                context=context,
                complete_stop=False,
            )
            if stopped.status != BotStatus.stopped:
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=stopped.status,
                    pid=stopped.pid,
                    profile_path=stopped.profile_path,
                    message="restart aborted: " + stopped.message,
                )

            refreshed = host._require_bot(bot_id)
            started = host._start_record(
                refreshed,
                reset_restart=True,
                message="restarted",
                wait=wait,
                timeout_seconds=timeout_seconds,
                context=context,
                probe=probe,
            )
            if started.status == BotStatus.running:
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=started.status,
                    pid=started.pid,
                    profile_path=started.profile_path,
                    message="restarted",
                )
            return started
