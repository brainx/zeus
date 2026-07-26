from __future__ import annotations

from datetime import UTC, datetime

from zeus import process_identity as _process_identity
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
from zeus.supervisor_core import (
    _LifecycleContext,
    _MarkerObservation,
)
from zeus.supervisor_start import _SupervisorStart

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


class _SupervisorStop(_SupervisorStart):
    def stop(
        self,
        bot_id: str,
        *,
        kill_after_timeout: bool | None = None,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = self._lifecycle_context(source, request_id)
        with self.bot_lock(bot_id), self._bot_process_lock(bot_id):
            return self._stop_locked(
                bot_id,
                kill_after_timeout=kill_after_timeout,
                context=context,
            )

    def _stop_locked(
        self,
        bot_id: str,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if record.pending_operation_id is not None:
            return self._pending_action_required(record, "lifecycle intent is already pending")
        record = self.store.begin_lifecycle_intent(
            bot_id,
            action="stop",
            operation_id=context.operation_id,
            source=context.source,
            request_id=context.request_id,
            reason="gateway stop requested",
        )
        return self._stop_record_effect(
            record,
            kill_after_timeout=kill_after_timeout,
            context=context,
            complete_stop=True,
        )

    def _stop_record_effect(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None = None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse:
        try:
            with self._marker_publication_lock(record):
                return self._stop_record_effect_locked(
                    record,
                    kill_after_timeout=kill_after_timeout,
                    context=context,
                    complete_stop=complete_stop,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return self._pending_action_required(record, str(exc))

    def _stop_record_effect_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        context: _LifecycleContext,
        complete_stop: bool,
    ) -> BotStatusResponse:
        effect = self._runtime.stop_locked(
            record,
            kill_after_timeout=kill_after_timeout,
            read_marker=self._read_strict_runtime_marker,
            classify_existing=self._classify_existing_runtime_marker,
            classify_exact=self._classify_exact_gateway_generation,
            remove_owned=self._remove_owned_launch_marker_locked,
            remove_generation=self._remove_gateway_generation_marker_locked,
        )
        if effect.outcome not in {"not_running", "stopped"}:
            if effect.kill_result is not None:
                self.store.append_audit_event(
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
            return self._pending_action_required(record, reason)
        if effect.outcome == "not_running":
            if complete_stop:
                try:
                    self._complete_stopped_intent(
                        record,
                        context=context,
                        reason="gateway process was not running",
                    )
                except Exception:
                    return self._pending_action_required(
                        record, "stopped state could not be persisted"
                    )
            self.store.append_audit_event("bot.stop", bot_id=record.bot_id, pid=record.pid)
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )
        if effect.kill_result is not None:
            self.store.append_audit_event(
                "bot.stop_kill",
                bot_id=record.bot_id,
                pid=effect.pid,
                succeeded=bool(effect.kill_succeeded),
            )
        if not complete_stop:
            try:
                self._update_lifecycle(
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
                return self._pending_action_required(
                    record, "previous gateway stop could not be persisted"
                )
        if complete_stop:
            try:
                self._complete_stopped_intent(
                    record,
                    context=context,
                    reason="gateway shutdown completed",
                )
            except Exception:
                return self._pending_action_required(record, "stopped state could not be persisted")
        self.store.append_audit_event("bot.stop", bot_id=record.bot_id, pid=record.pid)
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=BotStatus.stopped,
            pid=None,
            profile_path=record.profile_path,
            message="gateway shutdown completed",
        )

    def _complete_stopped_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        reason: str,
    ) -> BotRecord:
        operation_id = record.pending_operation_id
        if record.pending_action != "stop" or operation_id is None:
            raise RuntimeError("pending stop intent is unavailable")
        return self.store.complete_lifecycle_intent(
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

    def _remove_owned_launch_marker_locked(
        self,
        record: BotRecord,
        *,
        observed: _MarkerObservation | None = None,
    ) -> bool:
        return self._runtime.remove_owned_launch_marker_locked(record, observed=observed)

    def restart(
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
            record = self._require_bot(bot_id)
            if record.pending_operation_id is not None:
                return self._pending_action_required(record, "lifecycle intent is already pending")
            probe = self._preflight_start(record, timeout_seconds=timeout_seconds)
            record = self.store.begin_lifecycle_intent(
                bot_id,
                action="restart",
                operation_id=context.operation_id,
                source=context.source,
                request_id=context.request_id,
                reason="gateway restart requested",
            )
            stopped = self._stop_record_effect(
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

            refreshed = self._require_bot(bot_id)
            started = self._start_record(
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
