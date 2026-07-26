from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.errors import (
    BotDeleteError,
)
from zeus.gateway_launcher import (
    LaunchPayloadError,
)
from zeus.gateway_runtime import (
    OwnershipCheck,
)
from zeus.logging_utils import tail_file
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
    DesiredState,
)
from zeus.supervisor_core import (
    _LifecycleContext,
)
from zeus.supervisor_reconcile import _SupervisorReconcile

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


class _SupervisorStatus(_SupervisorReconcile):
    def status(
        self,
        bot_id: str,
        *,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = self._lifecycle_context(source, request_id)
        with self.bot_lock(bot_id), self._bot_process_lock(bot_id):
            return self._status_locked(bot_id, context=context)

    def _status_locked(self, bot_id: str, *, context: _LifecycleContext) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if record.pending_operation_id is not None:
            return self._recover_pending_intent(record, context=context, allow_launch=False)
        pid_state = self._pid_state(record.pid) if record.pid else _PidState.dead
        if record.pid and pid_state == _PidState.unknown:
            return self._unknown_pid_response(record, "determine gateway status", context=context)
        alive = bool(record.pid and pid_state == _PidState.alive)
        if alive and record.pid and not self._pid_owned(record.profile_path, record.pid, bot_id):
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
        if alive:
            return self._status_for_live_record(record, context=context)
        try:
            with self._marker_publication_lock(record):
                return self._status_dead_record_locked(record, context=context)
        except (BotDeleteError, LaunchPayloadError) as exc:
            return self._pending_action_required(record, str(exc))

    def _status_dead_record_locked(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind == "present" and observed.payload is not None:
            if record.pid is None:
                return self._pending_action_required(
                    record, "stale gateway marker PID is not recorded"
                )
            marker = self._classify_schema3_runtime_marker(
                record,
                observed.payload,
                expected_pid=record.pid,
                expected_revision=record.desired_revision,
                require_live_command=True,
            )
            generation = self._gateway_generation(marker)
            if (
                marker.kind != "dead"
                or generation is None
                or not self._remove_gateway_generation_marker_locked(record, generation)
            ):
                return self._pending_action_required(
                    record,
                    marker.reason or "stale gateway marker ownership could not be verified",
                )
        elif observed.kind != "missing":
            return self._pending_action_required(
                record,
                observed.reason or "stale gateway marker ownership could not be verified",
            )
        status = record.status
        if record.status in {BotStatus.starting, BotStatus.running}:
            status = BotStatus.failed
        last_error = record.last_error
        if record.status in {BotStatus.starting, BotStatus.running}:
            last_error = "gateway process is not running"
        if record.status in {BotStatus.starting, BotStatus.running}:
            self._update_lifecycle(
                context,
                record.bot_id,
                status,
                pid=None,
                stopped_at=datetime.now(UTC),
                last_error=last_error,
                last_transition_reason="gateway process was not running",
            )
        elif record.pid is not None:
            self._update_lifecycle(
                context,
                record.bot_id,
                status,
                pid=None,
                action="bot.pid_cleared",
                last_exit_code=record.last_exit_code,
                last_error=record.last_error,
            )
        if record.desired_state is DesiredState.running:
            status = BotStatus.failed
            last_error = "desired running gateway is missing; action required: run reconcile"
            self._update_lifecycle(
                context,
                record.bot_id,
                status,
                pid=None,
                stopped_at=datetime.now(UTC),
                last_error=last_error,
                last_transition_reason="desired running gateway was not observed",
            )
        if status == BotStatus.failed:
            message = last_error or "gateway process is not running"
        elif status == BotStatus.unknown:
            message = last_error or "gateway process state is unknown"
        else:
            message = ""
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=status,
            pid=None,
            profile_path=record.profile_path,
            message=message,
        )

    def logs(self, bot_id: str, max_bytes: int = 20_000) -> str:
        with self.bot_lock(bot_id):
            record = self._require_bot(bot_id)
            return tail_file(self.log_path(record.profile_path), max_bytes=max_bytes)

    def inspect(self, bot_id: str, max_log_bytes: int = 20_000) -> dict[str, object]:
        with self.bot_lock(bot_id):
            record = self._require_bot(bot_id)
            profile_path = Path(record.profile_path)
            marker = self._read_pid_marker(record.profile_path)
            ownership = OwnershipCheck(False, "not-running")
            pid_state = self._pid_state(record.pid) if record.pid else _PidState.dead
            if record.pid and pid_state == _PidState.alive:
                ownership = self._verify_gateway_pid_ownership(
                    record.profile_path, record.pid, bot_id
                )
            elif record.pid and pid_state == _PidState.unknown:
                ownership = OwnershipCheck(False, "pid-liveness-unknown")
            bot_payload = record.to_dict()
            return {
                "bot": bot_payload,
                "lifecycle": {
                    "started_at": bot_payload["started_at"],
                    "ready_at": bot_payload["ready_at"],
                    "stopped_at": bot_payload["stopped_at"],
                    "last_exit_code": bot_payload["last_exit_code"],
                    "last_error": bot_payload["last_error"],
                    "last_transition_reason": bot_payload["last_transition_reason"],
                },
                "profile_files": {
                    "config.yaml": (profile_path / "config.yaml").is_file(),
                    "SOUL.md": (profile_path / "SOUL.md").is_file(),
                    ".env": (profile_path / ".env").is_file(),
                    "mcp.json": (profile_path / "mcp.json").is_file(),
                    "cron/jobs.json": (profile_path / "cron" / "jobs.json").is_file(),
                },
                "pid_marker": marker,
                "live_cmdline_verified": ownership.verified,
                "ownership": {
                    "verified": ownership.verified,
                    "reason": ownership.reason,
                    "classification": ownership.classification,
                    "expected": {
                        "bot_id": bot_id,
                        "component": "gateway",
                        "action": "run",
                    },
                },
                "recent_logs": tail_file(
                    self.log_path(record.profile_path), max_bytes=max_log_bytes
                ),
            }
