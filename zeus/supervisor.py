from __future__ import annotations

import contextlib
import os
import platform
import re
import signal
import subprocess  # nosec B404
import threading
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.errors import (
    BotArchiveError,
    BotDeleteError,
    BotExistsError,
    BotReplaceError,
    BotRunningError,
)
from zeus.gateway_launcher import (
    LaunchPayloadError,
    _read_bounded_file,
    _remove_marker_if_owned_locked,
)
from zeus.gateway_marker import (
    GatewayGeneration,
    is_compat_runtime_marker,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.gateway_runtime import (
    GatewayRuntime,
    KillFn,
    MarkerObservation,
    OwnershipCheck,
    PopenFactory,
    PopenLike,
    RuntimeHooks,
    SignalResult,
    gateway_process_launch_kwargs,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.lifecycle import LifecycleEvent, LifecycleEventInput
from zeus.logging_utils import tail_file
from zeus.models import (
    BotCreateRequest,
    BotRecord,
    BotStatus,
    BotStatusResponse,
    DesiredState,
    HermesTemplate,
    RestartPolicy,
    TemplateError,
    validate_id,
)
from zeus.private_io import nofollow_absolute_path
from zeus.process_lock import BotProcessLock, LockTimeoutError
from zeus.profile_manager import ProfileArchive, ProfileDeletion, ProfileManager
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once
from zeus.reconciliation import (
    BotReconcileResult,
    FleetReconciler,
    ReconcileExecution,
    ReconcileLockTimeoutError,
    ReconcileOutcome,
    ReconcileRunSummary,
    ReconcileSnapshotDriftError,
)
from zeus.state import StateStore

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


class _ReadinessProbeUnset:
    pass


_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_LIFECYCLE_SOURCES = frozenset({"api", "cli", "reconcile", "recovery", "system"})
_READINESS_PROBE_UNSET = _ReadinessProbeUnset()


@dataclass(frozen=True)
class _LifecycleContext:
    operation_id: str
    source: str
    request_id: str | None


_MarkerObservation = MarkerObservation


_GatewayGeneration = GatewayGeneration


@dataclass(frozen=True)
class _ReconcileLaunch:
    record: BotRecord
    probe: ReadinessProbe | None
    attempt: int
    restart_max_attempts: int


def _gateway_process_launch_kwargs() -> dict[str, object]:
    return gateway_process_launch_kwargs()


def _nofollow_absolute_path(path: Path) -> Path:
    return nofollow_absolute_path(path)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _caused_by_missing_path(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, FileNotFoundError):
            return True
        current = current.__cause__
    return False


class Supervisor:
    def __init__(
        self,
        store: StateStore,
        hermes_bin: str,
        hermes_root: Path | str,
        popen_factory: PopenFactory = subprocess.Popen,
        kill_fn: KillFn = os.kill,
        pid_alive_fn: PidAliveFn | None = None,
        cmdline_reader: CmdlineReader | None = None,
        startup_grace_seconds: float = 0.25,
        stop_grace_seconds: float = 15.0,
        kill_after_timeout: bool = False,
        lock_timeout_seconds: float = 30.0,
        readiness_timeout_seconds: float = 30.0,
        readiness_interval_seconds: float = 0.5,
        allow_legacy_pid_markers: bool = True,
        restart_backoff_cap_seconds: float = 3600.0,
        proc_start_fingerprint_reader: ProcStartFingerprintReader | None = None,
    ) -> None:
        self.store = store
        configured_hermes_root = _nofollow_absolute_path(Path(hermes_root))
        self.adapter = HermesAdapter(
            hermes_bin=hermes_bin,
            hermes_root=configured_hermes_root.resolve(),
        )
        self._profile_manager = ProfileManager(
            self.adapter.hermes_root,
            self.store.database_path.parent / "archive",
        )
        self._marker_profiles_root = configured_hermes_root / "profiles"
        self.startup_grace_seconds = startup_grace_seconds
        self.lock_dir = self.store.database_path.parent / "locks" / "bots"
        self.readiness_timeout_seconds = readiness_timeout_seconds
        self.readiness_interval_seconds = readiness_interval_seconds
        self.allow_legacy_pid_markers = allow_legacy_pid_markers
        self.restart_backoff_cap_seconds = restart_backoff_cap_seconds
        self._cleanup_process_group = os.name == "posix" and popen_factory is subprocess.Popen
        self._runtime = GatewayRuntime(
            self.adapter,
            self._profile_manager,
            self._marker_profiles_root,
            popen_factory=popen_factory,
            kill_fn=kill_fn,
            pid_alive_fn=pid_alive_fn,
            cmdline_reader=cmdline_reader or _read_process_cmdline,
            proc_start_fingerprint_reader=(
                proc_start_fingerprint_reader or _read_process_start_fingerprint
            ),
            startup_grace_seconds=startup_grace_seconds,
            stop_grace_seconds=stop_grace_seconds,
            kill_after_timeout=kill_after_timeout,
            lock_timeout_seconds=lock_timeout_seconds,
            readiness_timeout_seconds=readiness_timeout_seconds,
            readiness_interval_seconds=readiness_interval_seconds,
            allow_legacy_pid_markers=allow_legacy_pid_markers,
            cleanup_process_group=self._cleanup_process_group,
            hooks_provider=self._runtime_hooks,
        )
        self._locks_guard = threading.Lock()
        self._bot_locks: dict[str, threading.RLock] = {}

    def _runtime_hooks(self) -> RuntimeHooks:
        return RuntimeHooks(
            pipe=os.pipe,
            close=os.close,
            read_bounded_file=_read_bounded_file,
            remove_marker_if_owned_locked=_remove_marker_if_owned_locked,
            probe_once=probe_once,
        )

    def _get_runtime_proxy(self, name: str) -> object:
        runtime = self.__dict__.get("_runtime")
        if runtime is not None:
            return getattr(runtime, name)
        return self.__dict__.get(f"_runtime_proxy_{name}")

    def _set_runtime_proxy(self, name: str, value: object) -> None:
        runtime = self.__dict__.get("_runtime")
        history = self.__dict__.setdefault(f"_runtime_proxy_history_{name}", [])
        if isinstance(history, list):
            if len(history) >= 32:
                del history[0]
            history.append(
                getattr(runtime, name)
                if runtime is not None
                else self.__dict__.get(f"_runtime_proxy_{name}")
            )
        if runtime is not None:
            setattr(runtime, name, value)
        else:
            self.__dict__[f"_runtime_proxy_{name}"] = value

    def _delete_runtime_proxy(self, name: str) -> None:
        history = self.__dict__.get(f"_runtime_proxy_history_{name}")
        if not isinstance(history, list) or not history:
            self.__dict__.pop(f"_runtime_proxy_{name}", None)
            return
        previous = history.pop()
        runtime = self.__dict__.get("_runtime")
        if runtime is not None:
            setattr(runtime, name, previous)
        else:
            self.__dict__[f"_runtime_proxy_{name}"] = previous

    @property
    def popen_factory(self) -> PopenFactory:
        return self._get_runtime_proxy("popen_factory")  # type: ignore[return-value]

    @popen_factory.setter
    def popen_factory(self, value: PopenFactory) -> None:
        self._set_runtime_proxy("popen_factory", value)

    @popen_factory.deleter
    def popen_factory(self) -> None:
        self._delete_runtime_proxy("popen_factory")

    @property
    def kill_fn(self) -> KillFn:
        return self._get_runtime_proxy("kill_fn")  # type: ignore[return-value]

    @kill_fn.setter
    def kill_fn(self, value: KillFn) -> None:
        self._set_runtime_proxy("kill_fn", value)

    @kill_fn.deleter
    def kill_fn(self) -> None:
        self._delete_runtime_proxy("kill_fn")

    @property
    def pid_alive_fn(self) -> PidAliveFn | None:
        return self._get_runtime_proxy("pid_alive_fn")  # type: ignore[return-value]

    @pid_alive_fn.setter
    def pid_alive_fn(self, value: PidAliveFn | None) -> None:
        self._set_runtime_proxy("pid_alive_fn", value)

    @pid_alive_fn.deleter
    def pid_alive_fn(self) -> None:
        self._delete_runtime_proxy("pid_alive_fn")

    @property
    def cmdline_reader(self) -> CmdlineReader:
        return self._get_runtime_proxy("cmdline_reader")  # type: ignore[return-value]

    @cmdline_reader.setter
    def cmdline_reader(self, value: CmdlineReader) -> None:
        self._set_runtime_proxy("cmdline_reader", value)

    @cmdline_reader.deleter
    def cmdline_reader(self) -> None:
        self._delete_runtime_proxy("cmdline_reader")

    @property
    def proc_start_fingerprint_reader(self) -> ProcStartFingerprintReader:
        return self._get_runtime_proxy("proc_start_fingerprint_reader")  # type: ignore[return-value]

    @proc_start_fingerprint_reader.setter
    def proc_start_fingerprint_reader(self, value: ProcStartFingerprintReader) -> None:
        self._set_runtime_proxy("proc_start_fingerprint_reader", value)

    @proc_start_fingerprint_reader.deleter
    def proc_start_fingerprint_reader(self) -> None:
        self._delete_runtime_proxy("proc_start_fingerprint_reader")

    @property
    def _processes(self) -> dict[str, PopenLike]:
        return self._get_runtime_proxy("_processes")  # type: ignore[return-value]

    @_processes.setter
    def _processes(self, value: dict[str, PopenLike]) -> None:
        self._set_runtime_proxy("_processes", value)

    @_processes.deleter
    def _processes(self) -> None:
        self._delete_runtime_proxy("_processes")

    @property
    def stop_grace_seconds(self) -> float:
        return self._get_runtime_proxy("stop_grace_seconds")  # type: ignore[return-value]

    @stop_grace_seconds.setter
    def stop_grace_seconds(self, value: float) -> None:
        self._set_runtime_proxy("stop_grace_seconds", value)

    @stop_grace_seconds.deleter
    def stop_grace_seconds(self) -> None:
        self._delete_runtime_proxy("stop_grace_seconds")

    @property
    def kill_after_timeout(self) -> bool:
        return self._get_runtime_proxy("kill_after_timeout")  # type: ignore[return-value]

    @kill_after_timeout.setter
    def kill_after_timeout(self, value: bool) -> None:
        self._set_runtime_proxy("kill_after_timeout", value)

    @kill_after_timeout.deleter
    def kill_after_timeout(self) -> None:
        self._delete_runtime_proxy("kill_after_timeout")

    @property
    def lock_timeout_seconds(self) -> float:
        return self._get_runtime_proxy("lock_timeout_seconds")  # type: ignore[return-value]

    @lock_timeout_seconds.setter
    def lock_timeout_seconds(self, value: float) -> None:
        self._set_runtime_proxy("lock_timeout_seconds", value)

    @lock_timeout_seconds.deleter
    def lock_timeout_seconds(self) -> None:
        self._delete_runtime_proxy("lock_timeout_seconds")

    def _lifecycle_context(self, source: str, request_id: str | None) -> _LifecycleContext:
        if source not in _LIFECYCLE_SOURCES:
            raise ValueError("invalid lifecycle event source")
        if source == "api":
            if request_id is None or _REQUEST_ID_RE.fullmatch(request_id) is None:
                raise ValueError("API lifecycle operations require a generated request ID")
        elif request_id is not None:
            raise ValueError("only API lifecycle operations may carry a request ID")
        return _LifecycleContext(uuid.uuid4().hex, source, request_id)

    def _event(
        self,
        context: _LifecycleContext,
        bot_id: str,
        *,
        action: str,
        outcome: str = "success",
        reason: str = "",
        error_code: str | None = None,
        error_message: str | None = None,
        details: dict[str, object] | None = None,
    ) -> LifecycleEventInput:
        return LifecycleEventInput(
            bot_id=bot_id,
            operation_id=context.operation_id,
            request_id=context.request_id,
            source=context.source,
            action=action,
            outcome=outcome,
            reason=reason,
            error_code=error_code,
            error_message=error_message,
            details=details or {},
        )

    def _update_lifecycle(
        self,
        context: _LifecycleContext,
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
    ) -> None:
        reason = last_transition_reason or ""
        failed = status in {BotStatus.failed, BotStatus.unknown}
        self.store.update_lifecycle_with_event(
            bot_id,
            status,
            pid,
            event=self._event(
                context,
                bot_id,
                action=action or f"bot.{status.value}",
                outcome="failure" if failed else "success",
                reason=reason,
                error_code=f"bot_{status.value}" if failed else None,
                error_message=last_error,
                details=details,
            ),
            started_at=started_at,
            ready_at=ready_at,
            stopped_at=stopped_at,
            last_exit_code=last_exit_code,
            last_error=last_error,
            last_transition_reason=last_transition_reason,
            reset_restart=reset_restart,
            clear_ready_at=clear_ready_at,
            clear_stopped_at=clear_stopped_at,
        )

    def _update_restart(
        self,
        context: _LifecycleContext,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
        action: str,
        reason: str,
        outcome: str = "success",
        error_code: str | None = None,
    ) -> None:
        self.store.update_restart_with_event(
            bot_id,
            status=status,
            pid=pid,
            restart_attempts=restart_attempts,
            next_restart_at=next_restart_at,
            event=self._event(
                context,
                bot_id,
                action=action,
                outcome=outcome,
                reason=reason,
                error_code=error_code,
                details={
                    "restart_attempts": restart_attempts,
                    "next_restart_at": (
                        next_restart_at.isoformat() if next_restart_at is not None else None
                    ),
                },
            ),
        )

    def bot_lock(self, bot_id: str) -> threading.RLock:
        with self._locks_guard:
            lock = self._bot_locks.get(bot_id)
            if lock is None:
                lock = threading.RLock()
                self._bot_locks[bot_id] = lock
            return lock

    def _bot_process_lock(self, bot_id: str) -> BotProcessLock:
        safe_bot_id = validate_id(bot_id, "bot_id")
        return BotProcessLock(
            self.lock_dir / f"{safe_bot_id}.lock",
            timeout_seconds=self.lock_timeout_seconds,
        )

    def _marker_publication_lock(
        self,
        record: BotRecord,
    ) -> contextlib.AbstractContextManager[object]:
        return self._runtime.marker_publication_lock(record)

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
        context = self._lifecycle_context(source, request_id)
        bot_id = validate_id(request.bot_id, "bot_id")
        with self.bot_lock(bot_id), self._bot_process_lock(bot_id):
            existing = self.store.get_bot(bot_id)
            profile_path = Path(self.adapter.hermes_root) / "profiles" / bot_id
            profile_exists = os.path.lexists(profile_path)
            if existing is not None:
                active = self._record_may_be_active(existing)
                if active and (not replace_existing or not stop_if_running):
                    raise BotRunningError(
                        "bot is running or starting; use --replace --stop to replace it"
                    )
                if not active and not replace_existing:
                    raise BotExistsError("bot already exists; use --replace to replace it")
                try:
                    self._safe_profile_path(bot_id, existing.profile_path)
                except BotDeleteError as exc:
                    raise BotReplaceError(str(exc)) from exc
            elif profile_exists:
                if not replace_existing:
                    raise BotExistsError("bot profile already exists; use --replace to replace it")
                if profile_path.is_symlink() or not profile_path.is_dir():
                    raise BotExistsError(
                        "bot profile path is not a safe directory; resolve it manually"
                    )
                self._assert_unregistered_profile_inactive(bot_id, profile_path)

            self._profile_manager.preflight(request, template)
            stopped_record: BotRecord | None = None
            if existing is not None:
                active = self._record_may_be_active(existing)
                if active:
                    stopped = self._stop_locked(bot_id, context=context)
                    if stopped.status != BotStatus.stopped:
                        raise BotReplaceError(f"could not stop existing bot: {stopped.message}")
                    stopped_record = existing

            try:
                with self._profile_manager.install_transaction(request, template) as record:
                    self._remove_pid_marker(record.profile_path)
                    self.store.upsert_bot_with_event(
                        record,
                        event=self._event(
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
                        self._recover_previously_active_bot(
                            stopped_record, "replacement", context=context
                        )
                    except Exception as recovery_error:
                        raise BotReplaceError(
                            "bot replacement failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            self.store.append_audit_event(
                "bot.replace" if existing else "bot.create",
                bot_id=record.bot_id,
                template_id=record.template_id,
            )
            return record

    def delete_bot(
        self,
        bot_id: str,
        *,
        stop_if_running: bool = False,
        remove_profile: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> BotStatusResponse:
        context = self._lifecycle_context(source, request_id)
        safe_bot_id = validate_id(bot_id, "bot_id")
        with self.bot_lock(safe_bot_id), self._bot_process_lock(safe_bot_id):
            record = self._require_bot(safe_bot_id)
            if remove_profile:
                self._safe_profile_path(safe_bot_id, record.profile_path)
            was_active = self._record_may_be_active(record)
            if was_active:
                if not stop_if_running:
                    raise BotRunningError("bot is running or starting; use --stop before delete")
                stopped = self._stop_locked(safe_bot_id, context=context)
                if stopped.status != BotStatus.stopped:
                    raise BotDeleteError(f"could not stop bot before delete: {stopped.message}")
            profile_deletion: ProfileDeletion | None = None
            try:
                if remove_profile:
                    profile_deletion = self._profile_manager.stage_delete(
                        safe_bot_id, record.profile_path
                    )
                else:
                    self._remove_pid_marker(record.profile_path)
                deleted = self.store.delete_bot_with_event(
                    safe_bot_id,
                    event=self._event(
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
                        self._profile_manager.rollback_delete(profile_deletion)
                    except BotDeleteError as rollback_error:
                        raise rollback_error from operation_error
                if was_active:
                    try:
                        self._recover_previously_active_bot(record, "deletion", context=context)
                    except Exception as recovery_error:
                        raise BotDeleteError(
                            "bot deletion failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            cleanup_pending = False
            if profile_deletion is not None:
                cleanup_error = self._profile_manager.finish_delete(profile_deletion)
                if cleanup_error is not None:
                    cleanup_pending = True
                    self.store.append_audit_event(
                        "bot.delete_cleanup_pending",
                        bot_id=safe_bot_id,
                        error=type(cleanup_error).__name__,
                    )
            self.store.append_audit_event(
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

    def archive_bot(
        self,
        bot_id: str,
        *,
        stop_if_running: bool = False,
        source: str = "cli",
        request_id: str | None = None,
    ) -> dict[str, object]:
        context = self._lifecycle_context(source, request_id)
        safe_bot_id = validate_id(bot_id, "bot_id")
        with self.bot_lock(safe_bot_id), self._bot_process_lock(safe_bot_id):
            record = self._require_bot(safe_bot_id)
            try:
                profile_path = self._safe_profile_path(safe_bot_id, record.profile_path)
            except BotDeleteError as exc:
                raise BotArchiveError(str(exc)) from exc
            was_active = self._record_may_be_active(record)
            if was_active:
                if not stop_if_running:
                    raise BotRunningError("bot is running or starting; use --stop before archive")
                stopped = self._stop_locked(safe_bot_id, context=context)
                if stopped.status != BotStatus.stopped:
                    raise BotArchiveError(f"could not stop bot before archive: {stopped.message}")

            profile_archive: ProfileArchive | None = None
            try:
                profile_archive = self._profile_manager.stage_archive(safe_bot_id, profile_path)
                deleted = self.store.delete_bot_with_event(
                    safe_bot_id,
                    event=self._event(
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
                        self._profile_manager.rollback_archive(profile_archive)
                    except BotArchiveError as rollback_error:
                        raise rollback_error from operation_error
                if was_active:
                    try:
                        self._recover_previously_active_bot(record, "archive", context=context)
                    except Exception as recovery_error:
                        raise BotArchiveError(
                            "bot archive failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            archive_path = profile_archive.archive_path if profile_archive is not None else None
            self.store.append_audit_event(
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
        except OSError as exc:
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
        probe: ReadinessProbe | None | _ReadinessProbeUnset = _READINESS_PROBE_UNSET,
    ) -> BotStatusResponse:
        bot_id = record.bot_id
        action = record.pending_action
        operation_id = record.pending_operation_id
        if action not in {"start", "restart"} or operation_id is None:
            raise RuntimeError("gateway launch requires a pending start or restart intent")
        if isinstance(probe, _ReadinessProbeUnset):
            try:
                probe = self._preflight_start(record, timeout_seconds=timeout_seconds)
            except OSError as exc:
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
        try:
            execution = self.reconcile_execution(
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
        return self.reconcile_execution(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        ).summary

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
        return FleetReconciler(self.store, self).execute(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            bot_snapshot=bot_snapshot,
        )

    def validate_reconcile_request(self, source: str, request_id: str | None) -> None:
        self._lifecycle_context(source, request_id)

    def validate_reconcile_target(
        self,
        bot_id: str,
        *,
        expected_profile_path: str | None = None,
    ) -> str:
        with self.bot_lock(bot_id), self._bot_process_lock(bot_id):
            record = self.store.get_bot(bot_id)
            if record is None:
                raise KeyError(f"unknown bot: {bot_id}")
            if expected_profile_path is not None and record.profile_path != expected_profile_path:
                raise ReconcileSnapshotDriftError(bot_id)
            return record.profile_path

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
        result, _response = self.reconcile_one_execution(
            bot_id,
            now=now,
            force=force,
            reset_restart=reset_restart,
            source=source,
            request_id=request_id,
            expected_profile_path=expected_profile_path,
        )
        return result

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
        context = self._lifecycle_context(source, request_id)
        current_time = now or datetime.now(UTC)
        started_at = datetime.now(UTC)
        with self.bot_lock(bot_id), self._bot_process_lock(bot_id):
            before = self.store.get_bot(bot_id)
            if before is None:
                if expected_profile_path is not None:
                    raise ReconcileSnapshotDriftError(bot_id)
                raise KeyError(f"unknown bot: {bot_id}")
            if expected_profile_path is not None and before.profile_path != expected_profile_path:
                raise ReconcileSnapshotDriftError(bot_id)
            prior_events = self.store.list_lifecycle_events(bot_id, limit=1, before=None)
            prior_event_id = prior_events[0].event_id if prior_events else None
            try:
                response = self._reconcile_record(
                    before,
                    current_time,
                    force=force,
                    reset_restart=reset_restart,
                    context=context,
                )
            except ReconcileSnapshotDriftError:
                raise
            except Exception as error:
                loaded_after_error = self.store.get_bot(bot_id)
                if loaded_after_error is None and expected_profile_path is not None:
                    raise ReconcileSnapshotDriftError(bot_id) from error
                after = loaded_after_error or before
                current_event = self._latest_reconcile_event(bot_id, prior_event_id)
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
            loaded_after = self.store.get_bot(bot_id)
            if loaded_after is None:
                if expected_profile_path is not None:
                    raise ReconcileSnapshotDriftError(bot_id)
                raise KeyError(f"unknown bot: {bot_id}")
            current_event = self._latest_reconcile_event(bot_id, prior_event_id)
            return (
                self._reconcile_result_from_response(
                    before,
                    loaded_after,
                    response,
                    current_event=current_event,
                    started_at=started_at,
                ),
                response,
            )

    def _latest_reconcile_event(
        self,
        bot_id: str,
        prior_event_id: int | None,
    ) -> LifecycleEvent | None:
        current_events = self.store.list_lifecycle_events(bot_id, limit=1, before=None)
        if not current_events or current_events[0].event_id == prior_event_id:
            return None
        return current_events[0]

    def _reconcile_result_from_response(
        self,
        before: BotRecord,
        after: BotRecord,
        response: BotStatusResponse,
        *,
        current_event: LifecycleEvent | None,
        started_at: datetime,
    ) -> BotReconcileResult:
        outcome = self._reconcile_outcome(
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

    def _reconcile_record(
        self,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        reset_restart: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        if record.pending_operation_id is not None:
            return self._recover_pending_intent(record, context=context, allow_launch=True)
        if reset_restart:
            self._update_restart(
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

        pid_state = self._pid_state(record.pid) if record.pid else _PidState.dead
        if record.pid and pid_state == _PidState.unknown:
            return self._unknown_pid_response(record, "reconcile the gateway", context=context)
        if record.pid and pid_state == _PidState.alive:
            if not self._pid_owned(record.profile_path, record.pid, record.bot_id):
                self._update_lifecycle(
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
            response = self._status_for_live_record(record, context=context)
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=response.status,
                pid=response.pid,
                profile_path=response.profile_path,
                message=response.message or "running",
            )

        try:
            with self._marker_publication_lock(record):
                prepared = self._prepare_reconcile_dead_record_locked(
                    record,
                    now,
                    force=force,
                    context=context,
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return self._pending_action_required(record, str(exc))
        if isinstance(prepared, BotStatusResponse):
            return prepared
        result = self._start_record(
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
            self.store.append_audit_event(
                "bot.reconcile.restart_started",
                bot_id=record.bot_id,
                pid=result.pid,
                attempt=prepared.attempt,
            )
        return result

    def _prepare_reconcile_dead_record_locked(
        self,
        record: BotRecord,
        now: datetime,
        *,
        force: bool,
        context: _LifecycleContext,
    ) -> BotStatusResponse | _ReconcileLaunch:
        marker = self._classify_existing_runtime_marker(record, expected_pid=record.pid)
        if marker.kind == "dead":
            generation = self._gateway_generation(marker)
            if generation is None or not self._remove_gateway_generation_marker_locked(
                record, generation
            ):
                return self._pending_action_required(
                    record, "dead gateway marker cleanup could not be verified"
                )
        elif marker.kind != "missing":
            return self._pending_action_required(
                record,
                marker.reason or "recorded gateway marker ownership is unresolved",
            )

        if record.desired_state is DesiredState.stopped:
            if record.status is not BotStatus.stopped or record.pid is not None:
                self._update_lifecycle(
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
            self._update_lifecycle(
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

        if record.restart_attempts >= record.restart_max_attempts:
            self._update_restart(
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
            delay = self._restart_delay(record)
            next_restart_at = now + timedelta(seconds=delay)
            attempt = record.restart_attempts + 1
            self._update_restart(
                context,
                record.bot_id,
                status=BotStatus.failed,
                pid=None,
                restart_attempts=attempt,
                next_restart_at=next_restart_at,
                action="bot.restart.schedule",
                reason="restart scheduled by reconcile",
            )
            self.store.append_audit_event(
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
        self._update_restart(
            context,
            record.bot_id,
            status=BotStatus.failed,
            pid=None,
            restart_attempts=attempt,
            next_restart_at=None,
            action="bot.restart.attempt",
            reason="restart attempt started by reconcile",
        )
        refreshed = self._require_bot(record.bot_id)
        probe = self._preflight_start(refreshed, timeout_seconds=None)
        refreshed = self.store.begin_lifecycle_intent(
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

    def _recover_pending_intent(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_launch: bool,
    ) -> BotStatusResponse:
        action = record.pending_action
        operation_id = record.pending_operation_id
        if action is None or operation_id is None:
            return self._pending_action_required(record, "pending lifecycle correlation is invalid")
        recovery_context = _LifecycleContext(operation_id, context.source, context.request_id)
        if action == "stop":
            try:
                with self._marker_publication_lock(record):
                    return self._recover_pending_stop_intent_locked(
                        record,
                        context=recovery_context,
                        allow_stop=allow_launch,
                    )
            except (BotDeleteError, LaunchPayloadError) as exc:
                return self._pending_action_required(record, str(exc))

        if action not in {"start", "restart"}:
            return self._pending_action_required(record, "pending lifecycle action is invalid")
        try:
            probe = self._preflight_start(record, timeout_seconds=None)
            expected = self.adapter.launcher_payload(
                record.bot_id,
                operation_id=operation_id,
                desired_revision=record.desired_revision,
                readiness_probe=probe,
            )
            marker_template = expected["marker"]
            if type(marker_template) is not dict:
                raise ValueError("invalid expected marker")
            fingerprint = str(marker_template["command_fingerprint"])
        except (OSError, ValueError, TemplateError, BotDeleteError) as exc:
            return self._pending_action_required(record, f"launch preflight failed: {exc}")
        if action == "restart":
            predecessor_result = self._recover_pending_restart_predecessor(
                record,
                context=recovery_context,
                allow_stop=allow_launch,
            )
            if predecessor_result is not None:
                return predecessor_result
        try:
            with self._marker_publication_lock(record):
                marker = self._matching_runtime_marker(
                    record,
                    expected_fingerprint=fingerprint,
                    require_live_command=True,
                )
                if marker.kind == "live" and marker.payload is not None:
                    marker_pid = marker.payload["pid"]
                    if isinstance(marker_pid, bool) or not isinstance(marker_pid, int):
                        return self._pending_action_required(record, "live marker PID is invalid")
                    pid = marker_pid
                    status = BotStatus.starting if probe is not None else BotStatus.running
                    ready_at = None if probe is not None else datetime.now(UTC)
                    if probe is not None:
                        readiness = probe_once(
                            probe.url,
                            timeout_seconds=min(1.0, max(0.2, probe.interval_seconds)),
                            expected_status=probe.expected_status,
                            expected_platform=probe.expected_platform,
                        )
                        if readiness.ready:
                            status = BotStatus.running
                            ready_at = datetime.now(UTC)
                    try:
                        self._complete_started_intent(
                            record,
                            context=recovery_context,
                            status=status,
                            pid=pid,
                            ready_at=ready_at,
                            reset_restart=True,
                            reason="recovery adopted registered gateway",
                        )
                    except Exception:
                        return self._pending_action_required(
                            record, "gateway adoption could not be persisted"
                        )
                    return BotStatusResponse(
                        record.bot_id,
                        status,
                        pid,
                        record.profile_path,
                        "recovered registered gateway",
                    )
                if marker.kind == "untrusted":
                    return self._pending_action_required(record, marker.reason)
                if not allow_launch:
                    return self._pending_action_required(
                        record, "desired running gateway is missing; reconcile is required"
                    )
                if marker.kind == "dead":
                    generation = self._gateway_generation(marker)
                    if generation is None or not self._remove_gateway_generation_marker_locked(
                        record, generation
                    ):
                        return self._pending_action_required(
                            record, "dead gateway marker cleanup failed"
                        )
                    if action == "restart":
                        return BotStatusResponse(
                            record.bot_id,
                            BotStatus.starting,
                            None,
                            record.profile_path,
                            "restart pending: removed dead gateway marker; "
                            "launch on next reconcile",
                        )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return self._pending_action_required(record, str(exc))
        return self._start_record(
            record,
            reset_restart=action == "restart",
            message="recovered interrupted gateway launch",
            context=recovery_context,
            probe=probe,
        )

    def _recover_pending_stop_intent_locked(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        pid_state = self._pid_state(record.pid) if record.pid else _PidState.dead
        if pid_state is _PidState.unknown:
            return self._pending_action_required(record, "gateway PID liveness is unknown")
        if not record.pid or pid_state is _PidState.dead:
            observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
            if not self._remove_owned_launch_marker_locked(record, observed=observed):
                return self._pending_action_required(
                    record, "stale gateway marker ownership could not be verified"
                )
            try:
                self._complete_stopped_intent(
                    record,
                    context=context,
                    reason="recovery confirmed gateway stopped",
                )
            except Exception:
                return self._pending_action_required(record, "stopped state could not be persisted")
            return BotStatusResponse(
                record.bot_id,
                BotStatus.stopped,
                None,
                record.profile_path,
                "recovered interrupted stop",
            )
        if not allow_stop:
            if not self._pid_owned(record.profile_path, record.pid, record.bot_id):
                return self._pending_action_required(
                    record, "gateway ownership could not be verified"
                )
            return self._pending_action_required(record, "stop intent is pending reconciliation")
        return self._stop_record_effect_locked(
            record,
            kill_after_timeout=None,
            context=context,
            complete_stop=True,
        )

    def _pending_restart_old_marker(
        self,
        record: BotRecord,
        observed: _MarkerObservation | None = None,
    ) -> _MarkerObservation | None:
        """Return a strictly verified marker from the generation before a restart intent."""
        if observed is None:
            observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
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
        return self._classify_schema3_runtime_marker(
            record,
            payload,
            expected_pid=record.pid,
            expected_revision=record.desired_revision - 1,
            require_live_command=True,
        )

    def _recover_pending_restart_predecessor(
        self,
        record: BotRecord,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse | None:
        try:
            with self._marker_publication_lock(record):
                predecessor = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
                if (
                    record.pid is not None
                    and predecessor.kind == "present"
                    and predecessor.payload is not None
                    and self._is_compat_runtime_marker(predecessor.payload)
                ):
                    return self._pending_action_required(
                        record,
                        "schema-v2 or legacy gateway restart requires manual process resolution",
                    )
                old_marker = self._pending_restart_old_marker(record, predecessor)
                if old_marker is not None:
                    return self._recover_pending_restart_old_gateway(
                        record,
                        old_marker,
                        context=context,
                        allow_stop=allow_stop,
                    )
                if record.pid is None or predecessor.kind != "missing":
                    return None
                pid_state = self._pid_state(record.pid)
                if pid_state is _PidState.unknown:
                    return self._pending_action_required(
                        record, "previous gateway PID liveness is unknown"
                    )
                if pid_state is _PidState.alive:
                    return self._pending_action_required(
                        record, "previous gateway marker is missing"
                    )
                if not allow_stop:
                    return self._pending_action_required(
                        record, "restart intent is pending reconciliation"
                    )
                try:
                    self._update_lifecycle(
                        context,
                        record.bot_id,
                        BotStatus.stopped,
                        pid=None,
                        action="bot.restart.old_process_recovered",
                        stopped_at=datetime.now(UTC),
                        last_transition_reason=("recovery confirmed the previous gateway stopped"),
                        clear_ready_at=True,
                    )
                except Exception:
                    return self._pending_action_required(
                        record, "previous gateway stop could not be persisted"
                    )
                return BotStatusResponse(
                    record.bot_id,
                    BotStatus.starting,
                    None,
                    record.profile_path,
                    "restart pending: recovered stopped gateway; launch on next reconcile",
                )
        except (BotDeleteError, LaunchPayloadError) as exc:
            return self._pending_action_required(record, str(exc))

    def _recover_pending_restart_old_gateway(
        self,
        record: BotRecord,
        marker: _MarkerObservation,
        *,
        context: _LifecycleContext,
        allow_stop: bool,
    ) -> BotStatusResponse:
        if marker.kind == "untrusted":
            return self._pending_action_required(
                record,
                marker.reason or "previous gateway ownership could not be verified",
            )
        if not allow_stop:
            return self._pending_action_required(record, "restart intent is pending reconciliation")
        generation = self._gateway_generation(marker)
        if generation is None:
            return self._pending_action_required(
                record, "previous gateway marker correlation is invalid"
            )
        if marker.kind == "live":
            if record.pid is None:
                return self._pending_action_required(record, "previous gateway PID is not recorded")
            stopped = self._stop_pending_restart_old_gateway(
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
            return self._pending_action_required(
                record, "previous gateway marker ownership could not be verified"
            )
        if not self._remove_gateway_generation_marker_locked(record, generation):
            return self._pending_action_required(
                record, "previous gateway marker cleanup could not be verified"
            )
        try:
            self._update_lifecycle(
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
            return self._pending_action_required(
                record, "previous gateway stop could not be persisted"
            )
        return BotStatusResponse(
            record.bot_id,
            BotStatus.starting,
            None,
            record.profile_path,
            "restart pending: recovered stopped gateway; launch on next reconcile",
        )

    def _stop_pending_restart_old_gateway(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
        *,
        context: _LifecycleContext,
    ) -> BotStatusResponse:
        effect = self._runtime.stop_generation_locked(
            record,
            generation,
            kill_after_timeout=None,
            classify_exact=self._classify_exact_gateway_generation,
            remove_generation=self._remove_gateway_generation_marker_locked,
        )
        if effect.outcome != "stopped":
            if effect.kill_result is not None:
                self.store.append_audit_event(
                    "bot.stop_kill",
                    bot_id=record.bot_id,
                    pid=generation.pid,
                    succeeded=bool(effect.kill_succeeded),
                )
            reasons = {
                "term_denied": "could not send SIGTERM to the previous gateway",
                "kill_denied": "could not send SIGKILL to the previous gateway",
                "grace_expired": ("previous gateway did not stop before the grace period expired"),
                "cleanup_unverified": ("previous gateway marker cleanup could not be verified"),
            }
            return self._pending_action_required(
                record,
                reasons.get(effect.outcome, effect.reason),
            )
        if effect.kill_result is not None:
            self.store.append_audit_event(
                "bot.stop_kill",
                bot_id=record.bot_id,
                pid=generation.pid,
                succeeded=bool(effect.kill_succeeded),
            )
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
        self.store.append_audit_event("bot.stop", bot_id=record.bot_id, pid=generation.pid)
        return BotStatusResponse(
            record.bot_id,
            BotStatus.stopped,
            None,
            record.profile_path,
            "gateway shutdown completed",
        )

    def _restart_delay(self, record: BotRecord) -> float:
        delay = record.restart_backoff_seconds * (2**record.restart_attempts)
        return float(min(delay, self.restart_backoff_cap_seconds))

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
            readiness = probe_once(
                probe.url,
                timeout_seconds=min(1.0, max(0.2, probe.interval_seconds)),
                expected_status=probe.expected_status,
                expected_platform=probe.expected_platform,
            )
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

    def _record_may_be_active(self, record: BotRecord) -> bool:
        if record.pending_operation_id is not None:
            return True
        if record.pid and self._pid_state(record.pid) != _PidState.dead:
            return True
        return record.status in {BotStatus.starting, BotStatus.running}

    def _recover_previously_active_bot(
        self,
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
        self.store.upsert_bot_with_event(
            recoverable,
            event=self._event(
                recovery_context,
                record.bot_id,
                action="bot.recovery.prepare",
                reason=f"recovering after failed {operation}",
            ),
        )
        probe = self._preflight_start(recoverable, timeout_seconds=None)
        recoverable = self.store.begin_lifecycle_intent(
            record.bot_id,
            action="start",
            operation_id=context.operation_id,
            source="recovery",
            reason=f"recovering after failed {operation}",
        )
        result = self._start_record(
            recoverable,
            reset_restart=False,
            message=f"restored after failed {operation}",
            context=recovery_context,
            probe=probe,
        )
        if result.status not in {BotStatus.starting, BotStatus.running}:
            raise RuntimeError(f"previous bot restart failed after {operation}: {result.message}")

    def _assert_unregistered_profile_inactive(
        self,
        bot_id: str,
        profile_path: Path,
    ) -> None:
        self._runtime.assert_unregistered_profile_inactive(bot_id, profile_path)

    def _safe_profile_path(self, bot_id: str, profile_path: str) -> Path:
        return self._profile_manager.validate_profile_path(bot_id, profile_path)

    def _stage_profile_deletion(self, bot_id: str, profile_path: str) -> Path | None:
        deletion = self._profile_manager.stage_delete(bot_id, profile_path)
        if deletion is None:
            return None
        return deletion.tombstone_path

    def _restore_tombstoned_profile(
        self,
        bot_id: str,
        profile_path: str,
        tombstone: Path,
    ) -> None:
        profile = self._profile_manager._pin_profile_path(bot_id, profile_path)
        self._profile_manager.rollback_delete(
            ProfileDeletion(
                profile_path=profile,
                tombstone_path=tombstone,
            )
        )

    def _restore_archived_profile(
        self,
        bot_id: str,
        profile_path: str,
        archive_path: Path,
    ) -> None:
        profile = self._profile_manager._pin_profile_path(bot_id, profile_path)
        self._profile_manager.rollback_archive(
            ProfileArchive(
                profile_path=profile,
                archive_path=archive_path,
            )
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
        readiness_probe: ReadinessProbe | None | _ReadinessProbeUnset = _READINESS_PROBE_UNSET,
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
