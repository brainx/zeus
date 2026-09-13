from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.errors import (
    BotArchiveError,
    BotDeleteError,
    BotExistsError,
    BotReplaceError,
    BotRunningError,
)
from zeus.models import (
    BotCreateRequest,
    BotRecord,
    BotStatus,
    BotStatusResponse,
    HermesTemplate,
    validate_id,
)
from zeus.profile_manager import ProfileArchive, ProfileDeletion
from zeus.supervisor_contracts import (
    _LifecycleContext,
)
from zeus.supervisor_registry_host import RegistryHost

_PidState = _process_identity.PidState


class RegistryOperations:
    """Stateless registry operations; callbacks are resolved from the current host."""

    @staticmethod
    def create_bot(
        host: RegistryHost,
        request: BotCreateRequest,
        template: HermesTemplate,
        *,
        replace_existing: bool = False,
        stop_if_running: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotRecord:
        context = host._lifecycle_context(source, request_id)
        bot_id = validate_id(request.bot_id, "bot_id")
        with (
            host.store.defer_lifecycle_audit(),
            host.bot_lock(bot_id),
            host._bot_process_lock(bot_id),
        ):
            existing = host.store.get_bot(bot_id)
            profile_path = Path(host.adapter.hermes_root) / "profiles" / bot_id
            profile_exists = os.path.lexists(profile_path)
            if existing is not None:
                active = host._record_may_be_active(existing)
                if active and (not replace_existing or not stop_if_running):
                    raise BotRunningError(
                        "bot is running or starting; use --replace --stop to replace it"
                    )
                if not active and not replace_existing:
                    raise BotExistsError("bot already exists; use --replace to replace it")
                try:
                    host._safe_profile_path(bot_id, existing.profile_path)
                except BotDeleteError as exc:
                    raise BotReplaceError(str(exc)) from exc
            elif profile_exists:
                if not replace_existing:
                    raise BotExistsError("bot profile already exists; use --replace to replace it")
                if profile_path.is_symlink() or not profile_path.is_dir():
                    raise BotExistsError(
                        "bot profile path is not a safe directory; resolve it manually"
                    )
                host._assert_unregistered_profile_inactive(bot_id, profile_path)

            host._profile_manager.preflight(request, template)
            stopped_record: BotRecord | None = None
            if existing is not None:
                active = host._record_may_be_active(existing)
                if active:
                    stopped = host._stop_locked(bot_id, context=context)
                    if stopped.status != BotStatus.stopped:
                        raise BotReplaceError(f"could not stop existing bot: {stopped.message}")
                    stopped_record = existing

            try:
                with host._profile_manager.install_transaction(request, template) as record:
                    host._remove_pid_marker(record.profile_path)
                    host.store.upsert_bot_with_event(
                        record,
                        event=host._event(
                            context,
                            record.bot_id,
                            action="bot.replace" if existing else "bot.create",
                            reason="bot profile registered",
                            details={"template_id": record.template_id},
                        ),
                    )
            except BaseException:
                if stopped_record is not None:
                    try:
                        host._recover_previously_active_bot(
                            stopped_record, "replacement", context=context
                        )
                    except Exception as recovery_error:
                        raise BotReplaceError(
                            "bot replacement failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            host.store.append_audit_event(
                "bot.replace" if existing else "bot.create",
                bot_id=record.bot_id,
                template_id=record.template_id,
            )
            return record

    @staticmethod
    def delete_bot(
        host: RegistryHost,
        bot_id: str,
        *,
        stop_if_running: bool = False,
        remove_profile: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = host._lifecycle_context(source, request_id)
        safe_bot_id = validate_id(bot_id, "bot_id")
        with (
            host.store.defer_lifecycle_audit(),
            host.bot_lock(safe_bot_id),
            host._bot_process_lock(safe_bot_id),
        ):
            record = host._require_bot(safe_bot_id)
            if remove_profile:
                host._safe_profile_path(safe_bot_id, record.profile_path)
            was_active = host._record_may_be_active(record)
            if was_active:
                if not stop_if_running:
                    raise BotRunningError("bot is running or starting; use --stop before delete")
                stopped = host._stop_locked(safe_bot_id, context=context)
                if stopped.status != BotStatus.stopped:
                    raise BotDeleteError(f"could not stop bot before delete: {stopped.message}")
            profile_deletion: ProfileDeletion | None = None
            try:
                if remove_profile:
                    profile_deletion = host._profile_manager.stage_delete(
                        safe_bot_id, record.profile_path
                    )
                else:
                    host._remove_pid_marker(record.profile_path)
                deleted = host.store.delete_bot_with_event(
                    safe_bot_id,
                    event=host._event(
                        context,
                        safe_bot_id,
                        action="bot.delete",
                        reason="bot registration deleted",
                        details={"profile_removed": remove_profile},
                    ),
                )
                if not deleted:
                    raise KeyError(f"unknown bot: {safe_bot_id}")
            except BaseException as operation_error:
                if profile_deletion is not None:
                    try:
                        host._profile_manager.rollback_delete(profile_deletion)
                    except BotDeleteError as rollback_error:
                        raise rollback_error from operation_error
                if was_active:
                    try:
                        host._recover_previously_active_bot(record, "deletion", context=context)
                    except Exception as recovery_error:
                        raise BotDeleteError(
                            "bot deletion failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            cleanup_pending = False
            if profile_deletion is not None:
                cleanup_error = host._profile_manager.finish_delete(profile_deletion)
                if cleanup_error is not None:
                    cleanup_pending = True
                    host.store.append_audit_event(
                        "bot.delete_cleanup_pending",
                        bot_id=safe_bot_id,
                        error=type(cleanup_error).__name__,
                    )
            host.store.append_audit_event(
                "bot.delete",
                bot_id=safe_bot_id,
                profile_removed=remove_profile,
                cleanup_pending=cleanup_pending,
            )
            return BotStatusResponse(
                bot_id=safe_bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message=("deleted; profile cleanup is pending" if cleanup_pending else "deleted"),
            )

    @staticmethod
    def archive_bot(
        host: RegistryHost,
        bot_id: str,
        *,
        stop_if_running: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> dict[str, object]:
        context = host._lifecycle_context(source, request_id)
        safe_bot_id = validate_id(bot_id, "bot_id")
        with (
            host.store.defer_lifecycle_audit(),
            host.bot_lock(safe_bot_id),
            host._bot_process_lock(safe_bot_id),
        ):
            record = host._require_bot(safe_bot_id)
            try:
                profile_path = host._safe_profile_path(safe_bot_id, record.profile_path)
            except BotDeleteError as exc:
                raise BotArchiveError(str(exc)) from exc
            was_active = host._record_may_be_active(record)
            if was_active:
                if not stop_if_running:
                    raise BotRunningError("bot is running or starting; use --stop before archive")
                stopped = host._stop_locked(safe_bot_id, context=context)
                if stopped.status != BotStatus.stopped:
                    raise BotArchiveError(f"could not stop bot before archive: {stopped.message}")

            profile_archive: ProfileArchive | None = None
            try:
                profile_archive = host._profile_manager.stage_archive(safe_bot_id, profile_path)
                deleted = host.store.delete_bot_with_event(
                    safe_bot_id,
                    event=host._event(
                        context,
                        safe_bot_id,
                        action="bot.archive",
                        reason="bot registration archived",
                    ),
                )
                if not deleted:
                    raise KeyError(f"unknown bot: {safe_bot_id}")
            except BaseException as operation_error:
                if profile_archive is not None:
                    try:
                        host._profile_manager.rollback_archive(profile_archive)
                    except BotArchiveError as rollback_error:
                        raise rollback_error from operation_error
                if was_active:
                    try:
                        host._recover_previously_active_bot(record, "archive", context=context)
                    except Exception as recovery_error:
                        raise BotArchiveError(
                            "bot archive failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            archive_path = profile_archive.archive_path if profile_archive is not None else None
            host.store.append_audit_event(
                "bot.archive",
                bot_id=safe_bot_id,
                archive_path=str(archive_path) if archive_path else None,
            )
            return {
                "bot_id": safe_bot_id,
                "status": BotStatus.stopped.value,
                "pid": None,
                "profile_path": record.profile_path,
                "archive_path": str(archive_path) if archive_path else None,
                "message": "archived",
            }

    @staticmethod
    def _record_may_be_active(host: RegistryHost, record: BotRecord) -> bool:
        if record.pending_operation_id is not None:
            return True
        if record.pid and host._pid_state(record.pid) != _PidState.dead:
            return True
        return record.status in {BotStatus.starting, BotStatus.running}

    @staticmethod
    def _recover_previously_active_bot(
        host: RegistryHost,
        record: BotRecord,
        operation: str,
        *,
        context: _LifecycleContext,
    ) -> None:
        recovery_context = _LifecycleContext(context.operation_id, "recovery", None)
        recoverable = replace(
            record,
            status=BotStatus.stopped,
            pid=None,
            ready_at=None,
            stopped_at=datetime.now(UTC),
            last_exit_code=None,
            last_error=None,
            last_transition_reason=f"recovering after failed {operation}",
        )
        host.store.upsert_bot_with_event(
            recoverable,
            event=host._event(
                recovery_context,
                record.bot_id,
                action="bot.recovery.prepare",
                reason=f"recovering after failed {operation}",
            ),
        )
        probe = host._preflight_start(recoverable, timeout_seconds=None)
        recoverable = host.store.begin_lifecycle_intent(
            record.bot_id,
            action="start",
            operation_id=context.operation_id,
            source="recovery",
            reason=f"recovering after failed {operation}",
        )
        result = host._start_record(
            recoverable,
            reset_restart=False,
            message=f"restored after failed {operation}",
            context=recovery_context,
            probe=probe,
        )
        if result.status not in {BotStatus.starting, BotStatus.running}:
            raise RuntimeError(f"previous bot restart failed after {operation}: {result.message}")

    @staticmethod
    def _assert_unregistered_profile_inactive(
        host: RegistryHost,
        bot_id: str,
        profile_path: Path,
    ) -> None:
        host._runtime.assert_unregistered_profile_inactive(bot_id, profile_path)

    @staticmethod
    def _safe_profile_path(host: RegistryHost, bot_id: str, profile_path: str) -> Path:
        return host._profile_manager.validate_profile_path(bot_id, profile_path)

    @staticmethod
    def _stage_profile_deletion(host: RegistryHost, bot_id: str, profile_path: str) -> Path | None:
        deletion = host._profile_manager.stage_delete(bot_id, profile_path)
        if deletion is None:
            return None
        return deletion.tombstone_path

    @staticmethod
    def _restore_tombstoned_profile(
        host: RegistryHost,
        bot_id: str,
        profile_path: str,
        tombstone: Path,
    ) -> None:
        profile = host._profile_manager._pin_profile_path(bot_id, profile_path)
        host._profile_manager.rollback_delete(
            ProfileDeletion(
                profile_path=profile,
                tombstone_path=tombstone,
            )
        )

    @staticmethod
    def _restore_archived_profile(
        host: RegistryHost,
        bot_id: str,
        profile_path: str,
        archive_path: Path,
    ) -> None:
        profile = host._profile_manager._pin_profile_path(bot_id, profile_path)
        host._profile_manager.rollback_archive(
            ProfileArchive(
                profile_path=profile,
                archive_path=archive_path,
            )
        )
