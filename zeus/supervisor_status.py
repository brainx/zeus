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
    validate_id,
)
from zeus.supervisor_contracts import (
    _LifecycleContext,
)
from zeus.supervisor_status_host import StatusHost

_PidState = _process_identity.PidState


class StatusOperations:
    """Stateless status operations; callbacks are resolved from the current host."""

    @staticmethod
    def status(
        host: StatusHost,
        bot_id: str,
        *,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = host._lifecycle_context(source, request_id)
        # Reject unknown bots before allocating any lock state so that requests
        # for nonexistent ids cannot grow the in-memory lock table or the
        # on-disk lock directory.
        safe_bot_id = validate_id(bot_id, "bot_id")
        host._require_bot(safe_bot_id)
        with host.bot_lock(safe_bot_id), host._bot_process_lock(safe_bot_id):
            return host._status_locked(safe_bot_id, context=context)

    @staticmethod
    def _status_locked(
        host: StatusHost, bot_id: str, *, context: _LifecycleContext
    ) -> BotStatusResponse:
        record = host._require_bot(bot_id)
        if record.pending_operation_id is not None:
            return host._recover_pending_intent(record, context=context, allow_launch=False)
        pid_state = host._pid_state(record.pid) if record.pid else _PidState.dead
        if record.pid and pid_state == _PidState.unknown:
            return host._unknown_pid_response(record, "determine gateway status", context=context)
        alive = bool(record.pid and pid_state == _PidState.alive)
        if alive and record.pid and not host._pid_owned(record.profile_path, record.pid, bot_id):
            host._update_lifecycle(
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
            return host._status_for_live_record(record, context=context)
        try:
            with host._marker_publication_lock(record):
                return host._status_dead_record_locked(record, context=context)
        except (BotDeleteError, LaunchPayloadError) as exc:
            return host._pending_action_required(record, str(exc))

    @staticmethod
    def _status_dead_record_locked(
        host: StatusHost,
        record: BotRecord,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        observed = host._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind == "present" and observed.payload is not None:
            if record.pid is None:
                return host._pending_action_required(
                    record, "stale gateway marker PID is not recorded"
                )
            marker = host._classify_schema3_runtime_marker(
                record,
                observed.payload,
                expected_pid=record.pid,
                expected_revision=record.desired_revision,
                require_live_command=True,
            )
            generation = host._gateway_generation(marker)
            if (
                marker.kind != "dead"
                or generation is None
                or not host._remove_gateway_generation_marker_locked(record, generation)
            ):
                return host._pending_action_required(
                    record,
                    marker.reason or "stale gateway marker ownership could not be verified",
                )
        elif observed.kind != "missing":
            return host._pending_action_required(
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
            host._update_lifecycle(
                context,
                record.bot_id,
                status,
                pid=None,
                stopped_at=datetime.now(UTC),
                last_error=last_error,
                last_transition_reason="gateway process was not running",
            )
        elif record.pid is not None:
            host._update_lifecycle(
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
            host._update_lifecycle(
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

    @staticmethod
    def logs(host: StatusHost, bot_id: str, max_bytes: int = 20_000) -> str:
        host._require_bot(bot_id)
        with host.bot_lock(bot_id):
            record = host._require_bot(bot_id)
            return tail_file(host.log_path(record.profile_path), max_bytes=max_bytes)

    @staticmethod
    def inspect(host: StatusHost, bot_id: str, max_log_bytes: int = 20_000) -> dict[str, object]:
        host._require_bot(bot_id)
        with host.bot_lock(bot_id):
            record = host._require_bot(bot_id)
            profile_path = Path(record.profile_path)
            marker = host._read_pid_marker(record.profile_path)
            ownership = OwnershipCheck(False, "not-running")
            pid_state = host._pid_state(record.pid) if record.pid else _PidState.dead
            if record.pid and pid_state == _PidState.alive:
                ownership = host._verify_gateway_pid_ownership(
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
                    host.log_path(record.profile_path), max_bytes=max_log_bytes
                ),
            }
