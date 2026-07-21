from __future__ import annotations

import contextlib
import errno
import json
import math
import os
import platform
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess  # nosec B404
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Protocol, TypeGuard
from urllib.parse import urlparse

from zeus.errors import (
    BotArchiveError,
    BotDeleteError,
    BotExistsError,
    BotReplaceError,
    BotRunningError,
)
from zeus.fs_utils import atomic_write_json
from zeus.gateway_launcher import (
    MAX_PAYLOAD_BYTES,
    LaunchPayloadError,
    _confirm_marker_missing,
    _ConfirmedMissing,
    _is_owned_runtime_marker,
    _open_logs,
    _open_profile_chain,
    _open_regular_marker,
    _read_bounded_file,
    _reject_duplicate_keys,
    _remove_marker_if_owned_locked,
    _validate_marker_bindings,
    marker_publication_lock,
    remove_marker_if_owned,
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
from zeus.private_io import UnsafeFileError, nofollow_absolute_path, open_private_append
from zeus.process_lock import BotProcessLock, LockTimeoutError
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once, readiness_probe_from_env
from zeus.reconciliation import (
    BotReconcileResult,
    FleetReconciler,
    ReconcileExecution,
    ReconcileLockTimeoutError,
    ReconcileOutcome,
    ReconcileRunSummary,
    ReconcileSnapshotDriftError,
)
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore


class PopenLike(Protocol):
    pid: int

    def poll(self) -> int | None: ...


PopenFactory = Callable[..., PopenLike]
KillFn = Callable[[int, signal.Signals], None]
PidAliveFn = Callable[[int], bool]
CmdlineReader = Callable[[int], list[str] | None]
ProcStartFingerprintReader = Callable[[int], str | None]


@dataclass(frozen=True)
class OwnershipCheck:
    verified: bool
    reason: str
    classification: str | None = None


@dataclass(frozen=True)
class _CommandCheck:
    verified: bool
    reason: str
    classification: str | None = None


class _PidState(Enum):
    alive = "alive"
    dead = "dead"
    unknown = "unknown"


class _SignalResult(Enum):
    sent = "sent"
    missing = "missing"
    denied = "denied"


class _ReadinessProbeUnset:
    pass


_PYTHON_INTERPRETER_RE = re.compile(r"^python(?:\d+(?:\.\d+)?)?$")
_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_LIFECYCLE_SOURCES = frozenset({"api", "cli", "reconcile", "recovery", "system"})
_READINESS_PROBE_UNSET = _ReadinessProbeUnset()


@dataclass(frozen=True)
class _LifecycleContext:
    operation_id: str
    source: str
    request_id: str | None


@dataclass(frozen=True)
class _MarkerObservation:
    kind: str
    payload: dict[str, object] | None = None
    reason: str = ""


@dataclass(frozen=True)
class _GatewayGeneration:
    operation_id: str
    desired_revision: int
    pid: int
    command_fingerprint: str
    proc_start_fingerprint: str | None


@dataclass(frozen=True)
class _ReconcileLaunch:
    record: BotRecord
    probe: ReadinessProbe | None
    attempt: int
    restart_max_attempts: int


def _gateway_process_launch_kwargs() -> dict[str, object]:
    if os.name == "posix":
        return {"start_new_session": True}
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return {"creationflags": creationflags} if creationflags else {}


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
        self._marker_profiles_root = configured_hermes_root / "profiles"
        self.popen_factory = popen_factory
        self.kill_fn = kill_fn
        self.pid_alive_fn = pid_alive_fn
        self.cmdline_reader = cmdline_reader or _read_process_cmdline
        self.startup_grace_seconds = startup_grace_seconds
        self.stop_grace_seconds = stop_grace_seconds
        self.kill_after_timeout = kill_after_timeout
        self.lock_dir = self.store.database_path.parent / "locks" / "bots"
        self.lock_timeout_seconds = lock_timeout_seconds
        self.readiness_timeout_seconds = readiness_timeout_seconds
        self.readiness_interval_seconds = readiness_interval_seconds
        self.allow_legacy_pid_markers = allow_legacy_pid_markers
        self.restart_backoff_cap_seconds = restart_backoff_cap_seconds
        self.proc_start_fingerprint_reader = (
            proc_start_fingerprint_reader or _read_process_start_fingerprint
        )
        self._cleanup_process_group = os.name == "posix" and popen_factory is subprocess.Popen
        self._processes: dict[str, PopenLike] = {}
        self._locks_guard = threading.Lock()
        self._bot_locks: dict[str, threading.RLock] = {}

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
        profile_path = self._safe_profile_path(record.bot_id, record.profile_path)
        if not os.path.lexists(profile_path):
            # A schema-v3 launcher cannot publish beneath an absent profile, so
            # marker absence is already stable without creating profile state.
            return contextlib.nullcontext()
        return marker_publication_lock(
            profile_path,
            timeout_seconds=self.lock_timeout_seconds,
        )

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

            renderer = ProfileRenderer(self.adapter.hermes_root)
            renderer.preflight(request, template)
            stopped_record: BotRecord | None = None
            if existing is not None:
                active = self._record_may_be_active(existing)
                if active:
                    stopped = self._stop_locked(bot_id, context=context)
                    if stopped.status != BotStatus.stopped:
                        raise BotReplaceError(f"could not stop existing bot: {stopped.message}")
                    stopped_record = existing

            try:
                with renderer.transaction(request, template) as record:
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
            profile_tombstone: Path | None = None
            try:
                if remove_profile:
                    profile_tombstone = self._stage_profile_deletion(
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
            except BaseException:
                if profile_tombstone is not None:
                    self._restore_tombstoned_profile(
                        safe_bot_id, record.profile_path, profile_tombstone
                    )
                if was_active:
                    try:
                        self._recover_previously_active_bot(record, "deletion", context=context)
                    except Exception as recovery_error:
                        raise BotDeleteError(
                            "bot deletion failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
            cleanup_pending = False
            if profile_tombstone is not None:
                try:
                    shutil.rmtree(profile_tombstone)
                except OSError as exc:
                    cleanup_pending = True
                    self.store.append_audit_event(
                        "bot.delete_cleanup_pending",
                        bot_id=safe_bot_id,
                        error=type(exc).__name__,
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

            archive_path: Path | None = None
            try:
                if profile_path.exists():
                    archive_root = self.store.database_path.parent / "archive"
                    archive_root.mkdir(parents=True, exist_ok=True)
                    candidate = archive_root / (
                        f"{safe_bot_id}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
                    )
                    shutil.move(str(profile_path), str(candidate))
                    archive_path = candidate
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
            except BaseException:
                if archive_path is not None:
                    self._restore_archived_profile(safe_bot_id, record.profile_path, archive_path)
                if was_active:
                    try:
                        self._recover_previously_active_bot(record, "archive", context=context)
                    except Exception as recovery_error:
                        raise BotArchiveError(
                            "bot archive failed and the previous bot could not be restarted"
                        ) from recovery_error
                raise
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
        payload = self.adapter.launcher_payload(
            bot_id,
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            readiness_probe=probe,
        )
        marker_data = payload["marker"]
        if type(marker_data) is not dict:
            raise RuntimeError("launcher produced an invalid marker payload")
        expected_fingerprint = str(marker_data["command_fingerprint"])
        log_path = self.log_path(record.profile_path)
        process: PopenLike | None = None
        payload_read = payload_write = ack_read = ack_write = -1
        try:
            encoded_payload = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            if not encoded_payload or len(encoded_payload) > MAX_PAYLOAD_BYTES:
                raise ValueError("launcher payload is too large")
            with open_private_append(log_path) as log_file:
                payload_read, payload_write = os.pipe()
                ack_read, ack_write = os.pipe()
                launcher_argv = self.adapter.launcher_command(payload_read, ack_write)
                process = self.popen_factory(
                    launcher_argv,
                    env=dict(os.environ),
                    stdout=log_file,
                    stderr=log_file,
                    pass_fds=(payload_read, ack_write),
                    close_fds=True,
                    **_gateway_process_launch_kwargs(),
                )
            os.close(payload_read)
            payload_read = -1
            os.close(ack_write)
            ack_write = -1
            self._write_pipe_payload(payload_write, encoded_payload)
            os.close(payload_write)
            payload_write = -1
            acknowledgment = self._read_launcher_ack(ack_read)
            os.close(ack_read)
            ack_read = -1
            if acknowledgment != b"1":
                raise RuntimeError("gateway launcher did not acknowledge marker publication")
            with self._marker_publication_lock(record):
                marker = self._matching_runtime_marker(
                    record,
                    expected_fingerprint=expected_fingerprint,
                    expected_pid=process.pid,
                    require_live_command=True,
                )
                if marker.kind != "live":
                    raise RuntimeError(
                        "gateway launcher ownership marker could not be verified: " + marker.reason
                    )
            self._processes[bot_id] = process
        except BaseException as exc:
            for fd in (payload_read, payload_write, ack_read, ack_write):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            if process is None:
                if not isinstance(exc, (OSError, ValueError)):
                    raise
                self._processes.pop(bot_id, None)
                failure_message = f"failed to start gateway: {exc}"
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
                    error=type(exc).__name__,
                    message=str(exc),
                )
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.failed,
                    pid=None,
                    profile_path=record.profile_path,
                    message=failure_message,
                )
            cleanup_complete = self._cleanup_interrupted_intent_launch(
                record,
                process,
                expected_fingerprint=expected_fingerprint,
            )
            if not isinstance(exc, Exception):
                raise
            if cleanup_complete:
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.failed,
                    pid=None,
                    profile_path=record.profile_path,
                    message="gateway start registration failed; spawned process was stopped",
                )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.unknown,
                pid=process.pid,
                profile_path=record.profile_path,
                message=(
                    "gateway start registration failed and spawned process cleanup "
                    "could not be confirmed"
                ),
            )
        if process is None:  # Defensive guard for custom process factories.
            raise RuntimeError("gateway process factory returned no process")
        returncode = self._poll_startup(process)
        if returncode is not None:
            remove_marker_if_owned(
                self._safe_profile_path(record.bot_id, record.profile_path),
                operation_id=operation_id,
                desired_revision=record.desired_revision,
                pid=process.pid,
                command_fingerprint=expected_fingerprint,
            )
            self._processes.pop(bot_id, None)
            message = f"gateway exited during startup grace period with return code {returncode}"
            terminal = replace(record, pid=process.pid)
            try:
                self._complete_failed_intent(
                    terminal,
                    context=context,
                    pid=None,
                    stopped_at=datetime.now(UTC),
                    last_exit_code=returncode,
                    message=message,
                    reason="gateway exited during startup grace period",
                )
            except Exception:
                return self._launch_completion_failure_response(
                    record, process, expected_fingerprint=expected_fingerprint
                )
            self.store.append_audit_event(
                "bot.start_failed",
                bot_id=bot_id,
                pid=process.pid,
                returncode=returncode,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=message,
            )
        if probe is not None:
            if wait:
                readiness = self._wait_for_readiness(process, probe)
                if process.poll() is not None:
                    returncode = process.poll()
                    remove_marker_if_owned(
                        self._safe_profile_path(record.bot_id, record.profile_path),
                        operation_id=operation_id,
                        desired_revision=record.desired_revision,
                        pid=process.pid,
                        command_fingerprint=expected_fingerprint,
                    )
                    self._processes.pop(bot_id, None)
                    try:
                        self._complete_failed_intent(
                            record,
                            context=context,
                            pid=None,
                            stopped_at=datetime.now(UTC),
                            last_exit_code=returncode,
                            message="gateway process exited during readiness check",
                            reason="readiness process exited",
                        )
                    except Exception:
                        return self._launch_completion_failure_response(
                            record, process, expected_fingerprint=expected_fingerprint
                        )
                    self.store.append_audit_event(
                        "bot.start_failed",
                        bot_id=bot_id,
                        pid=process.pid,
                        returncode=returncode,
                        reason="readiness_process_exited",
                    )
                    return BotStatusResponse(
                        bot_id=bot_id,
                        status=BotStatus.failed,
                        pid=None,
                        profile_path=record.profile_path,
                        message="gateway process exited during readiness check",
                    )
                if readiness.ready:
                    try:
                        self._complete_started_intent(
                            record,
                            context=context,
                            status=BotStatus.running,
                            pid=process.pid,
                            ready_at=datetime.now(UTC),
                            reset_restart=reset_restart,
                            reason="gateway readiness probe passed",
                        )
                    except Exception:
                        return self._launch_completion_failure_response(
                            record, process, expected_fingerprint=expected_fingerprint
                        )
                    self.store.append_audit_event("bot.start", bot_id=bot_id, pid=process.pid)
                    return BotStatusResponse(
                        bot_id=bot_id,
                        status=BotStatus.running,
                        pid=process.pid,
                        profile_path=record.profile_path,
                        message="gateway ready",
                    )
                try:
                    self._complete_started_intent(
                        record,
                        context=context,
                        status=BotStatus.starting,
                        pid=process.pid,
                        last_error=readiness.message,
                        reason="readiness probe timed out",
                    )
                except Exception:
                    return self._launch_completion_failure_response(
                        record, process, expected_fingerprint=expected_fingerprint
                    )
                self.store.append_audit_event(
                    "bot.start_readiness_pending",
                    bot_id=bot_id,
                    pid=process.pid,
                    url=probe.url,
                    message=readiness.message,
                )
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.starting,
                    pid=process.pid,
                    profile_path=record.profile_path,
                    message="readiness timeout; gateway process still alive",
                )
            try:
                self._complete_started_intent(
                    record,
                    context=context,
                    status=BotStatus.starting,
                    pid=process.pid,
                    reason="gateway process started; readiness probe pending",
                )
            except Exception:
                return self._launch_completion_failure_response(
                    record, process, expected_fingerprint=expected_fingerprint
                )
            self.store.append_audit_event(
                "bot.start_readiness_pending",
                bot_id=bot_id,
                pid=process.pid,
                url=probe.url,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.starting,
                pid=process.pid,
                profile_path=record.profile_path,
                message="started; readiness probe pending",
            )
        try:
            self._complete_started_intent(
                record,
                context=context,
                status=BotStatus.running,
                pid=process.pid,
                ready_at=datetime.now(UTC),
                reset_restart=reset_restart,
                reason="gateway process started without readiness probe",
            )
        except Exception:
            return self._launch_completion_failure_response(
                record, process, expected_fingerprint=expected_fingerprint
            )
        self.store.append_audit_event("bot.start", bot_id=bot_id, pid=process.pid)
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.running,
            pid=process.pid,
            profile_path=record.profile_path,
            message=message,
        )

    def _preflight_start(
        self, record: BotRecord, *, timeout_seconds: float | None
    ) -> ReadinessProbe | None:
        expected_profile = (Path(self.adapter.hermes_root) / "profiles" / record.bot_id).resolve()
        if Path(record.profile_path).resolve() != expected_profile:
            raise TemplateError("registered bot profile does not match the Hermes profile path")
        safe_profile = self._safe_profile_path(record.bot_id, record.profile_path)
        if not safe_profile.is_dir() or safe_profile.is_symlink():
            raise TemplateError("registered bot profile is not a safe directory")
        _argv, env = self.adapter.command(record.bot_id, "gateway", "run")
        probe = self._readiness_probe(env, timeout_seconds=timeout_seconds)
        self.adapter.launcher_payload(
            record.bot_id,
            operation_id="0" * 32,
            desired_revision=max(1, record.desired_revision + 1),
            readiness_probe=probe,
        )
        return probe

    def _write_pipe_payload(self, fd: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("short launcher payload write")
            offset += written

    def _read_launcher_ack(self, fd: int) -> bytes:
        deadline = time.monotonic() + 5.0
        acknowledgment = bytearray()
        while len(acknowledgment) <= 1:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("gateway launcher acknowledgment timed out")
            readable, _writable, _exceptional = select.select([fd], [], [], remaining)
            if not readable:
                raise TimeoutError("gateway launcher acknowledgment timed out")
            chunk = os.read(fd, 2 - len(acknowledgment))
            if not chunk:
                return bytes(acknowledgment)
            acknowledgment.extend(chunk)
        return bytes(acknowledgment)

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
        cleanup_errors: list[str] = []
        stopped = self._terminate_spawned_process(process, cleanup_errors)
        if not stopped:
            return False
        self._processes.pop(record.bot_id, None)
        operation_id = record.pending_operation_id
        if operation_id is None:
            return False
        remove_marker_if_owned(
            self._safe_profile_path(record.bot_id, record.profile_path),
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            pid=process.pid,
            command_fingerprint=expected_fingerprint,
        )
        return (
            self._read_strict_runtime_marker(record.bot_id, record.profile_path).kind == "missing"
        )

    def _launch_completion_failure_response(
        self,
        record: BotRecord,
        process: PopenLike,
        *,
        expected_fingerprint: str,
    ) -> BotStatusResponse:
        cleaned = self._cleanup_interrupted_intent_launch(
            record,
            process,
            expected_fingerprint=expected_fingerprint,
        )
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
            process.pid,
            record.profile_path,
            "gateway start completion is unknown and cleanup could not be confirmed",
        )

    def _read_strict_runtime_marker(
        self, bot_id: str, registered_profile_path: str
    ) -> _MarkerObservation:
        profile_path = _nofollow_absolute_path(Path(registered_profile_path))
        expected_profile = self._marker_profiles_root / bot_id
        if not profile_path.is_absolute() or profile_path != expected_profile:
            return _MarkerObservation(
                "untrusted",
                reason="registered profile path does not match the trusted Hermes profile",
            )
        profile = None
        logs_fd = marker_fd = -1
        try:
            profile = _open_profile_chain(profile_path)
        except _ConfirmedMissing:
            return _MarkerObservation("missing", reason="marker is missing")
        except (OSError, ValueError) as exc:
            return _MarkerObservation(
                "untrusted", reason=f"registered profile cannot be opened safely: {exc}"
            )
        try:
            try:
                logs_fd = _open_logs(profile.fd, create=False)
            except ValueError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    try:
                        profile.confirm_missing("logs")
                    except (OSError, ValueError) as confirm_error:
                        return _MarkerObservation(
                            "untrusted",
                            reason=f"marker directory absence is untrusted: {confirm_error}",
                        )
                    return _MarkerObservation("missing", reason="marker is missing")
                return _MarkerObservation(
                    "untrusted", reason=f"marker directory cannot be opened safely: {exc}"
                )
            try:
                marker_fd, marker_stat = _open_regular_marker(logs_fd)
                raw = _read_bounded_file(marker_fd)
                marker_stat = _validate_marker_bindings(
                    profile,
                    logs_fd,
                    marker_fd,
                    marker_stat,
                )
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
            except FileNotFoundError:
                try:
                    _confirm_marker_missing(profile, logs_fd)
                except (OSError, ValueError) as confirm_error:
                    return _MarkerObservation(
                        "untrusted",
                        reason=f"marker absence is untrusted: {confirm_error}",
                    )
                return _MarkerObservation("missing", reason="marker is missing")
            except ValueError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    try:
                        _confirm_marker_missing(profile, logs_fd)
                    except (OSError, ValueError) as confirm_error:
                        return _MarkerObservation(
                            "untrusted",
                            reason=f"marker absence is untrusted: {confirm_error}",
                        )
                    return _MarkerObservation("missing", reason="marker is missing")
                return _MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return _MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
        except FileNotFoundError as exc:
            return _MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
        finally:
            for fd in (marker_fd, logs_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            if profile is not None:
                profile.close()
        if type(value) is not dict:
            return _MarkerObservation("untrusted", reason="marker is not an object")
        if marker_stat.st_nlink != 1:
            return _MarkerObservation("untrusted", reason="marker has unexpected hard links")
        return _MarkerObservation("present", payload=value)

    def _matching_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_fingerprint: str,
        expected_pid: int | None = None,
        require_live_command: bool,
    ) -> _MarkerObservation:
        observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return observed
        operation_id = record.pending_operation_id
        if operation_id is None:
            return _MarkerObservation("untrusted", reason="pending operation is missing")
        return self._classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=expected_pid,
            expected_operation_id=operation_id,
            expected_revision=record.desired_revision,
            expected_fingerprint=expected_fingerprint,
            require_live_command=require_live_command,
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
        pid_value = payload.get("pid")
        if type(pid_value) is not int or pid_value <= 0:
            return _MarkerObservation("untrusted", reason="marker PID is invalid")
        pid = pid_value
        if expected_pid is not None and pid != expected_pid:
            return _MarkerObservation("untrusted", reason="marker PID does not match")
        operation_id = payload.get("operation_id")
        revision = payload.get("desired_revision")
        fingerprint = payload.get("command_fingerprint")
        if (
            type(operation_id) is not str
            or type(revision) is not int
            or type(fingerprint) is not str
        ):
            return _MarkerObservation("untrusted", reason="marker correlation is invalid")
        if expected_operation_id is not None and operation_id != expected_operation_id:
            return _MarkerObservation("untrusted", reason="marker operation does not match")
        if expected_revision is not None and revision != expected_revision:
            return _MarkerObservation("untrusted", reason="marker revision does not match")
        if expected_fingerprint is not None and fingerprint != expected_fingerprint:
            return _MarkerObservation("untrusted", reason="marker command does not match")
        if not _is_owned_runtime_marker(
            payload,
            bot_id=record.bot_id,
            operation_id=operation_id,
            desired_revision=revision,
            pid=pid,
            expected_fingerprint=fingerprint,
        ):
            return _MarkerObservation("untrusted", reason="marker schema or command does not match")
        expected_hermes = self._resolved_hermes_bin()
        if expected_hermes is None or payload.get("resolved_hermes_bin") != expected_hermes:
            return _MarkerObservation("untrusted", reason="marker executable is not trusted")
        if not require_live_command:
            start_identity_error = self._process_start_identity_error(payload, pid)
            if start_identity_error is not None:
                return _MarkerObservation("untrusted", reason=start_identity_error)
            return _MarkerObservation("live", payload=payload)
        pid_state = self._pid_state(pid)
        if pid_state is _PidState.unknown:
            return _MarkerObservation("untrusted", reason="marker PID liveness is unknown")
        if pid_state is _PidState.dead:
            if self._process_start_fingerprint_required() and not self._valid_marker_start(
                payload.get("proc_start_fingerprint")
            ):
                return _MarkerObservation(
                    "untrusted", reason="process start fingerprint is unavailable"
                )
            return _MarkerObservation("dead", payload=payload, reason="marker PID is dead")
        start_identity_error = self._process_start_identity_error(payload, pid)
        if start_identity_error is not None:
            return _MarkerObservation("untrusted", reason=start_identity_error)
        live_argv = self.cmdline_reader(pid)
        if not live_argv:
            return _MarkerObservation("untrusted", reason="live gateway command is unavailable")
        command_check = _verify_gateway_command(
            live_argv,
            record.bot_id,
            self._trusted_hermes_bins(),
            require_trusted_path=True,
        )
        if not command_check.verified:
            return _MarkerObservation("untrusted", reason="live gateway command does not match")
        return _MarkerObservation("live", payload=payload)

    def _process_start_identity_error(self, payload: dict[str, object], pid: int) -> str | None:
        marker_start = payload.get("proc_start_fingerprint")
        live_start = self.proc_start_fingerprint_reader(pid)
        if self._process_start_fingerprint_required():
            if not self._valid_marker_start(marker_start) or not self._valid_marker_start(
                live_start
            ):
                return "process start fingerprint is unavailable"
            if marker_start != live_start:
                return "process start fingerprint does not match"
        elif live_start and marker_start != live_start:
            return "process start fingerprint does not match"
        elif marker_start and live_start != marker_start:
            return "process start fingerprint is unavailable"
        return None

    @staticmethod
    def _valid_marker_start(value: object) -> bool:
        return type(value) is str and bool(value) and len(value) <= 512

    @staticmethod
    def _process_start_fingerprint_required() -> bool:
        return platform.system() in {"Darwin", "Linux"}

    def _classify_existing_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_pid: int | None = None,
    ) -> _MarkerObservation:
        observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return observed
        return self._classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=expected_pid,
            require_live_command=True,
        )

    def _remove_exact_schema3_marker(
        self,
        record: BotRecord,
        marker: _MarkerObservation,
    ) -> bool:
        if marker.kind != "dead":
            return False
        generation = self._gateway_generation(marker)
        if generation is None:
            return False
        return self._remove_gateway_generation_marker(record, generation)

    def _gateway_generation(
        self,
        marker: _MarkerObservation,
    ) -> _GatewayGeneration | None:
        payload = marker.payload
        if marker.kind not in {"live", "dead"} or payload is None:
            return None
        operation_id = payload.get("operation_id")
        revision = payload.get("desired_revision")
        pid = payload.get("pid")
        fingerprint = payload.get("command_fingerprint")
        process_start = payload.get("proc_start_fingerprint")
        if (
            type(operation_id) is not str
            or type(revision) is not int
            or type(pid) is not int
            or type(fingerprint) is not str
            or (process_start is not None and type(process_start) is not str)
        ):
            return None
        return _GatewayGeneration(
            operation_id=operation_id,
            desired_revision=revision,
            pid=pid,
            command_fingerprint=fingerprint,
            proc_start_fingerprint=process_start,
        )

    def _classify_exact_gateway_generation(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> _MarkerObservation:
        observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return _MarkerObservation("untrusted", reason="previous gateway marker changed")
        if observed.payload.get("proc_start_fingerprint") != generation.proc_start_fingerprint:
            return _MarkerObservation(
                "untrusted", reason="previous gateway process identity changed"
            )
        return self._classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=generation.pid,
            expected_operation_id=generation.operation_id,
            expected_revision=generation.desired_revision,
            expected_fingerprint=generation.command_fingerprint,
            require_live_command=True,
        )

    def _remove_gateway_generation_marker(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> bool:
        return remove_marker_if_owned(
            self._safe_profile_path(record.bot_id, record.profile_path),
            operation_id=generation.operation_id,
            desired_revision=generation.desired_revision,
            pid=generation.pid,
            command_fingerprint=generation.command_fingerprint,
            expected_proc_start_fingerprint=generation.proc_start_fingerprint,
            lock_timeout_seconds=self.lock_timeout_seconds,
        )

    def _remove_gateway_generation_marker_locked(
        self,
        record: BotRecord,
        generation: _GatewayGeneration,
    ) -> bool:
        return _remove_marker_if_owned_locked(
            self._safe_profile_path(record.bot_id, record.profile_path),
            operation_id=generation.operation_id,
            desired_revision=generation.desired_revision,
            pid=generation.pid,
            command_fingerprint=generation.command_fingerprint,
            expected_proc_start_fingerprint=generation.proc_start_fingerprint,
        )

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
        bot_id = record.bot_id
        observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if (
            observed.kind == "present"
            and observed.payload is not None
            and self._is_compat_runtime_marker(observed.payload)
        ):
            return self._pending_action_required(
                record,
                "schema-v2 or legacy gateway stop requires manual process resolution",
            )
        pid_state = self._pid_state(record.pid) if record.pid else _PidState.dead
        if record.pid and pid_state == _PidState.unknown:
            return self._pending_action_required(record, "gateway PID liveness is unknown")
        if not record.pid or pid_state == _PidState.dead:
            if not self._remove_owned_launch_marker_locked(record, observed=observed):
                return self._pending_action_required(
                    record, "stale gateway marker ownership could not be verified"
                )
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
            self.store.append_audit_event("bot.stop", bot_id=bot_id, pid=record.pid)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )

        marker = self._classify_existing_runtime_marker(record, expected_pid=record.pid)
        generation = self._gateway_generation(marker)
        if marker.kind != "live" or generation is None:
            return self._pending_action_required(
                record,
                "refusing to stop process because PID ownership could not be verified",
            )
        term_marker = self._classify_exact_gateway_generation(record, generation)
        if term_marker.kind != "live":
            return self._pending_action_required(
                record,
                term_marker.reason or "gateway ownership changed before SIGTERM",
            )

        term_result = self._send_signal(record.pid, signal.SIGTERM)
        if term_result == _SignalResult.denied:
            return self._pending_action_required(record, "could not send SIGTERM to the gateway")
        stopped = term_result == _SignalResult.missing
        if not stopped:
            stopped = self._wait_for_exit(bot_id, record.pid)
        should_kill = self.kill_after_timeout if kill_after_timeout is None else kill_after_timeout
        if not stopped and should_kill:
            kill_marker = self._classify_exact_gateway_generation(record, generation)
            if kill_marker.kind != "live":
                return self._pending_action_required(
                    record,
                    kill_marker.reason or "gateway ownership changed before SIGKILL",
                )
            kill_result = self._send_signal(record.pid, signal.SIGKILL)
            if kill_result == _SignalResult.denied:
                self.store.append_audit_event(
                    "bot.stop_kill",
                    bot_id=bot_id,
                    pid=record.pid,
                    succeeded=False,
                )
                return self._pending_action_required(
                    record, "could not send SIGKILL to the gateway"
                )
            stopped = kill_result == _SignalResult.missing
            if not stopped:
                stopped = self._wait_for_exit(bot_id, record.pid)
            self.store.append_audit_event(
                "bot.stop_kill",
                bot_id=bot_id,
                pid=record.pid,
                succeeded=stopped,
            )
        if not stopped:
            message = (
                "gateway did not stop before grace period expired; "
                "Hermes async delegations may still be running"
            )
            return self._pending_action_required(record, message)

        if not self._remove_gateway_generation_marker_locked(record, generation):
            return self._pending_action_required(
                record, "stopped gateway marker cleanup could not be verified"
            )
        self._processes.pop(bot_id, None)
        if not complete_stop:
            try:
                self._update_lifecycle(
                    context,
                    bot_id,
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
        self.store.append_audit_event("bot.stop", bot_id=bot_id, pid=record.pid)
        return BotStatusResponse(
            bot_id=bot_id,
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
        if observed is None:
            observed = self._read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind == "missing":
            return True
        if observed.kind != "present" or observed.payload is None or record.pid is None:
            return False
        if record.pending_action not in {"stop", "restart"}:
            return False
        marker = self._classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=record.pid,
            expected_revision=record.desired_revision - 1,
            require_live_command=True,
        )
        generation = self._gateway_generation(marker)
        return (
            marker.kind == "dead"
            and generation is not None
            and self._remove_gateway_generation_marker_locked(record, generation)
        )

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
        schema = payload.get("schema")
        return (type(schema) is int and schema == 2) or schema is None

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
        current = self._classify_exact_gateway_generation(record, generation)
        if current.kind == "dead":
            stopped = True
        elif current.kind == "live":
            term_result = self._send_signal(generation.pid, signal.SIGTERM)
            if term_result == _SignalResult.denied:
                return self._pending_action_required(
                    record, "could not send SIGTERM to the previous gateway"
                )
            stopped = term_result == _SignalResult.missing
            if not stopped:
                stopped = self._wait_for_exit(record.bot_id, generation.pid)
        else:
            return self._pending_action_required(
                record, current.reason or "previous gateway marker changed"
            )

        if not stopped and self.kill_after_timeout:
            current = self._classify_exact_gateway_generation(record, generation)
            if current.kind == "dead":
                stopped = True
            elif current.kind != "live":
                return self._pending_action_required(
                    record,
                    current.reason or "previous gateway ownership changed before SIGKILL",
                )
            else:
                kill_result = self._send_signal(generation.pid, signal.SIGKILL)
                if kill_result == _SignalResult.denied:
                    self.store.append_audit_event(
                        "bot.stop_kill",
                        bot_id=record.bot_id,
                        pid=generation.pid,
                        succeeded=False,
                    )
                    return self._pending_action_required(
                        record, "could not send SIGKILL to the previous gateway"
                    )
                stopped = kill_result == _SignalResult.missing
                if not stopped:
                    stopped = self._wait_for_exit(record.bot_id, generation.pid)
                self.store.append_audit_event(
                    "bot.stop_kill",
                    bot_id=record.bot_id,
                    pid=generation.pid,
                    succeeded=stopped,
                )

        if not stopped:
            return self._pending_action_required(
                record,
                "previous gateway did not stop before the grace period expired",
            )
        if not self._remove_gateway_generation_marker_locked(record, generation):
            return self._pending_action_required(
                record, "previous gateway marker cleanup could not be verified"
            )
        self._processes.pop(record.bot_id, None)
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

    def _assert_unregistered_profile_inactive(self, bot_id: str, profile_path: Path) -> None:
        marker_path = self.pid_marker_path(str(profile_path))
        if not marker_path.exists():
            return
        try:
            payload = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BotRunningError(
                "unregistered bot profile has an unreadable PID marker; refusing replacement"
            ) from exc
        pid = payload.get("pid") if isinstance(payload, dict) else None
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise BotRunningError(
                "unregistered bot profile has an invalid PID marker; refusing replacement"
            )
        if self._pid_state(pid) != _PidState.dead:
            raise BotRunningError(
                f"unregistered bot profile may still own gateway PID {pid}; refusing replacement"
            )

    def _safe_profile_path(self, bot_id: str, profile_path: str) -> Path:
        safe_bot_id = validate_id(bot_id, "bot_id")
        profile = Path(profile_path).resolve()
        profiles_root = (Path(self.adapter.hermes_root) / "profiles").resolve()
        try:
            relative = profile.relative_to(profiles_root)
        except ValueError as exc:
            raise BotDeleteError("bot profile path is outside the Hermes profiles root") from exc
        if len(relative.parts) != 1 or relative.parts[0] != safe_bot_id:
            raise BotDeleteError("bot profile path does not match bot id")
        return profile

    def _stage_profile_deletion(self, bot_id: str, profile_path: str) -> Path | None:
        profile = self._safe_profile_path(bot_id, profile_path)
        if not profile.exists():
            return None
        tombstone = profile.with_name(f".{profile.name}.deleting-{os.getpid()}-{time.time_ns()}")
        try:
            os.replace(profile, tombstone)
        except OSError as exc:
            raise BotDeleteError("could not stage the bot profile for deletion") from exc
        return tombstone

    def _restore_tombstoned_profile(
        self,
        bot_id: str,
        profile_path: str,
        tombstone: Path,
    ) -> None:
        profile = self._safe_profile_path(bot_id, profile_path)
        if profile.exists() or profile.is_symlink():
            raise BotDeleteError(
                "bot state deletion failed and the profile could not be restored because "
                "its original path is occupied"
            )
        try:
            os.replace(tombstone, profile)
        except OSError as exc:
            raise BotDeleteError(
                "bot state deletion failed and the profile could not be restored"
            ) from exc

    def _restore_archived_profile(
        self,
        bot_id: str,
        profile_path: str,
        archive_path: Path,
    ) -> None:
        profile = self._safe_profile_path(bot_id, profile_path)
        if profile.exists() or profile.is_symlink():
            raise BotArchiveError(
                "bot state deletion failed and the archived profile could not be restored "
                "because its original path is occupied"
            )
        try:
            shutil.move(str(archive_path), str(profile))
        except OSError as exc:
            raise BotArchiveError(
                "bot state deletion failed and the archived profile could not be restored"
            ) from exc

    def _readiness_probe_for_bot(
        self, bot_id: str, *, timeout_seconds: float | None = None
    ) -> ReadinessProbe | None:
        _argv, env = self.adapter.command(bot_id, "gateway", "run")
        return self._readiness_probe(env, timeout_seconds=timeout_seconds)

    def _readiness_probe_for_live_record(
        self, record: BotRecord
    ) -> tuple[ReadinessProbe | None, str | None]:
        try:
            payload = json.loads(
                self.pid_marker_path(record.profile_path).read_text(encoding="utf-8")
            )
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None, "readiness provenance is unavailable from the PID marker"
        if not isinstance(payload, dict):
            return None, "readiness provenance in the PID marker is invalid"
        if payload.get("schema") not in {2, 3} or "readiness_probe" not in payload:
            # Markers written before readiness provenance was added remain supported.
            return self._readiness_probe_for_bot(record.bot_id), None
        try:
            return _readiness_probe_from_marker(payload["readiness_probe"]), None
        except ValueError as exc:
            return None, f"readiness provenance in the PID marker is invalid: {exc}"

    def _readiness_probe(
        self, env: dict[str, str], *, timeout_seconds: float | None = None
    ) -> ReadinessProbe | None:
        resolved_timeout = (
            self.readiness_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        if (
            isinstance(resolved_timeout, bool)
            or not isinstance(resolved_timeout, (int, float))
            or not math.isfinite(float(resolved_timeout))
            or not 0.1 <= float(resolved_timeout) <= 300
        ):
            raise TemplateError("readiness timeout must be a finite number between 0.1 and 300")
        return readiness_probe_from_env(
            env,
            timeout_seconds=float(resolved_timeout),
            interval_seconds=self.readiness_interval_seconds,
        )

    def _wait_for_readiness(self, process: PopenLike, probe: ReadinessProbe) -> ReadinessResult:
        deadline = time.monotonic() + probe.timeout_seconds
        last = ReadinessResult(False, "not probed yet")
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return ReadinessResult(False, "gateway process exited during readiness check")
            last = probe_once(
                probe.url,
                timeout_seconds=min(5.0, max(0.2, probe.interval_seconds)),
                expected_status=probe.expected_status,
                expected_platform=probe.expected_platform,
            )
            if last.ready:
                return last
            time.sleep(probe.interval_seconds)
        return ReadinessResult(False, f"readiness timeout: {last.message}", last.payload)

    def log_path(self, profile_path: str) -> Path:
        return _nofollow_absolute_path(Path(profile_path) / "logs" / "zeus-gateway.log")

    def pid_marker_path(self, profile_path: str) -> Path:
        return Path(profile_path) / "logs" / "zeus-gateway.pid.json"

    def _require_bot(self, bot_id: str) -> BotRecord:
        record = self.store.get_bot(bot_id)
        if record is None:
            raise KeyError(f"unknown bot: {bot_id}")
        return record

    def _pid_state(self, pid: int) -> _PidState:
        try:
            if self.pid_alive_fn is not None:
                return _PidState.alive if self.pid_alive_fn(pid) else _PidState.dead
            os.kill(pid, 0)
        except ProcessLookupError:
            return _PidState.dead
        except PermissionError:
            return _PidState.unknown
        except OSError as exc:
            return _PidState.dead if exc.errno == errno.ESRCH else _PidState.unknown
        return _PidState.alive

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
        try:
            self.kill_fn(pid, sig)
        except ProcessLookupError:
            return _SignalResult.missing
        except PermissionError:
            return _SignalResult.denied
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return _SignalResult.missing
            if exc.errno == errno.EPERM:
                return _SignalResult.denied
            raise
        return _SignalResult.sent

    def _write_pid_marker(
        self,
        profile_path: str,
        pid: int,
        bot_id: str,
        argv: list[str],
        *,
        readiness_probe: ReadinessProbe | None | _ReadinessProbeUnset = _READINESS_PROBE_UNSET,
    ) -> None:
        path = self.pid_marker_path(profile_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        resolved_hermes_bin = self._resolved_hermes_bin()
        marker_argv = list(argv)
        if resolved_hermes_bin:
            marker_argv[0] = resolved_hermes_bin
        fingerprint = self.proc_start_fingerprint_reader(pid)
        payload = {
            "schema": 2,
            "pid": pid,
            "bot_id": bot_id,
            "component": "gateway",
            "action": "run",
            "argv": marker_argv,
            "resolved_hermes_bin": resolved_hermes_bin,
            "started_at": time.time(),
        }
        if not isinstance(readiness_probe, _ReadinessProbeUnset):
            payload["readiness_probe"] = _readiness_probe_marker_payload(readiness_probe)
        if fingerprint:
            payload["proc_start_fingerprint"] = fingerprint
        atomic_write_json(path, payload, mode=0o600)

    def _remove_pid_marker(self, profile_path: str) -> None:
        try:
            self.pid_marker_path(profile_path).unlink()
        except FileNotFoundError:
            return

    def _read_pid_marker(self, profile_path: str) -> dict[str, object]:
        safe_profile_path = _nofollow_absolute_path(Path(profile_path))
        profile = None
        logs_fd = marker_fd = -1
        try:
            try:
                profile = _open_profile_chain(safe_profile_path)
                logs_fd = _open_logs(profile.fd, create=False)
                marker_fd, marker_stat = _open_regular_marker(logs_fd)
            except _ConfirmedMissing:
                return {"exists": False}
            except (LaunchPayloadError, OSError, ValueError) as exc:
                if _caused_by_missing_path(exc):
                    try:
                        if profile is not None and logs_fd >= 0:
                            _confirm_marker_missing(profile, logs_fd)
                        elif profile is not None:
                            profile.confirm_missing("logs")
                        else:
                            raise UnsafeFileError(
                                "PID marker absence cannot be confirmed safely"
                            ) from exc
                    except (LaunchPayloadError, OSError, ValueError) as confirm_error:
                        raise UnsafeFileError(
                            "PID marker absence cannot be confirmed safely"
                        ) from confirm_error
                    return {"exists": False}
                raise UnsafeFileError("PID marker cannot be opened safely") from exc
            if marker_stat.st_uid != os.geteuid() or marker_stat.st_nlink != 1:
                raise UnsafeFileError("PID marker is not a private regular file")
            marker_mode = f"{stat.S_IMODE(marker_stat.st_mode):04o}"
            try:
                raw = _read_bounded_file(marker_fd)
            except (LaunchPayloadError, OSError, TypeError, ValueError) as exc:
                try:
                    _validate_marker_bindings(
                        profile,
                        logs_fd,
                        marker_fd,
                        marker_stat,
                    )
                except (LaunchPayloadError, OSError, TypeError, ValueError) as binding_error:
                    raise UnsafeFileError(
                        "PID marker changed while it was inspected"
                    ) from binding_error
                return {
                    "exists": True,
                    "valid": False,
                    "mode": marker_mode,
                    "error": str(exc),
                }
            try:
                current_marker = _validate_marker_bindings(
                    profile,
                    logs_fd,
                    marker_fd,
                    marker_stat,
                )
            except (LaunchPayloadError, OSError, TypeError, ValueError) as exc:
                raise UnsafeFileError("PID marker changed while it was inspected") from exc
            if (
                not stat.S_ISREG(current_marker.st_mode)
                or current_marker.st_uid != os.geteuid()
                or current_marker.st_nlink != 1
                or not _same_identity(marker_stat, current_marker)
            ):
                raise UnsafeFileError("PID marker changed while it was inspected")
        finally:
            for descriptor in (marker_fd, logs_fd):
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)
            if profile is not None:
                profile.close()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {"exists": True, "valid": False, "mode": marker_mode, "error": str(exc)}
        if not isinstance(payload, dict):
            return {
                "exists": True,
                "valid": False,
                "mode": marker_mode,
                "error": "pid marker must be a JSON object",
            }
        deprecated = payload.get("schema") is None
        safe_payload: dict[str, object] = {
            "exists": True,
            "valid": True,
            "mode": marker_mode,
            "deprecated": deprecated,
        }
        for key in (
            "schema",
            "pid",
            "bot_id",
            "component",
            "action",
            "started_at",
            "proc_start_fingerprint",
        ):
            if key in payload:
                safe_payload[key] = payload[key]
        if "readiness_probe" in payload:
            try:
                probe = _readiness_probe_from_marker(payload["readiness_probe"])
            except ValueError:
                safe_payload["readiness_probe"] = "invalid"
            else:
                safe_payload["readiness_probe"] = _readiness_probe_marker_payload(probe)
        argv_value = payload.get("argv")
        if isinstance(argv_value, list) and all(isinstance(part, str) for part in argv_value):
            safe_payload["argv_shape"] = _safe_command_shape(argv_value)
        return safe_payload

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool:
        return self._verify_gateway_pid_ownership(profile_path, pid, bot_id).verified

    def _verify_gateway_pid_ownership(
        self, profile_path: str, pid: int, bot_id: str
    ) -> OwnershipCheck:
        record = self.store.get_bot(bot_id)
        if record is not None and record.profile_path != profile_path:
            return OwnershipCheck(False, "marker-mismatch")
        observed = self._read_strict_runtime_marker(bot_id, profile_path)
        if observed.kind == "missing":
            return OwnershipCheck(False, "marker-missing")
        if observed.kind != "present" or observed.payload is None:
            return OwnershipCheck(False, "marker-mismatch")
        payload = observed.payload
        if payload.get("schema") == 3:
            if record is None:
                return OwnershipCheck(False, "marker-mismatch")
            marker = self._classify_schema3_runtime_marker(
                record,
                payload,
                expected_pid=pid,
                require_live_command=True,
            )
            if marker.kind != "live":
                return OwnershipCheck(False, marker.reason or "marker-mismatch")
            live_argv = self.cmdline_reader(pid)
            if not live_argv:
                return OwnershipCheck(False, "live-cmdline-missing")
            live_check = _verify_gateway_command(
                live_argv,
                bot_id,
                self._trusted_hermes_bins(),
                require_trusted_path=True,
            )
            return OwnershipCheck(
                live_check.verified,
                live_check.reason,
                live_check.classification,
            )
        if payload.get("pid") != pid:
            return OwnershipCheck(False, "marker-mismatch")
        argv_value = payload.get("argv")
        if not isinstance(argv_value, list) or not all(
            isinstance(part, str) for part in argv_value
        ):
            return OwnershipCheck(False, "marker-mismatch")
        trusted_hermes = self._resolved_hermes_bin()
        if trusted_hermes is None:
            return OwnershipCheck(False, "untrusted-executable")
        marker_check = self._verify_marker_payload(payload, list(argv_value), bot_id)
        if not marker_check.verified:
            return OwnershipCheck(False, marker_check.reason, marker_check.classification)
        live_argv = self.cmdline_reader(pid)
        if not live_argv:
            return OwnershipCheck(False, "live-cmdline-missing")
        live_check = _verify_gateway_command(
            live_argv, bot_id, self._trusted_hermes_bins(), require_trusted_path=True
        )
        if not live_check.verified:
            return OwnershipCheck(False, live_check.reason, live_check.classification)
        marker_schema = payload.get("schema")
        fingerprint = payload.get("proc_start_fingerprint")
        if marker_schema == 2:
            live_fingerprint = self.proc_start_fingerprint_reader(pid)
            if live_fingerprint and not (isinstance(fingerprint, str) and fingerprint):
                return OwnershipCheck(
                    False,
                    "pid-start-time-missing",
                    live_check.classification,
                )
            if isinstance(fingerprint, str) and fingerprint and live_fingerprint != fingerprint:
                return OwnershipCheck(
                    False,
                    "pid-start-time-mismatch",
                    live_check.classification,
                )
        elif isinstance(fingerprint, str) and fingerprint:
            live_fingerprint = self.proc_start_fingerprint_reader(pid)
            if live_fingerprint != fingerprint:
                return OwnershipCheck(
                    False,
                    "pid-start-time-mismatch",
                    live_check.classification,
                )
        classification = (
            "legacy-marker-valid"
            if marker_check.classification == "legacy-marker-valid"
            else live_check.classification
        )
        if classification == "legacy-marker-valid":
            self.store.append_audit_event(
                "bot.pid_marker_legacy_accepted",
                bot_id=bot_id,
                pid=pid,
            )
        return OwnershipCheck(True, "ok", classification)

    def _verify_marker_payload(
        self, payload: dict[str, object], argv: list[str], bot_id: str
    ) -> OwnershipCheck:
        schema = payload.get("schema")
        if schema == 3:
            pid = payload.get("pid")
            operation_id = payload.get("operation_id")
            revision = payload.get("desired_revision")
            fingerprint = payload.get("command_fingerprint")
            if (
                type(pid) is not int
                or pid <= 0
                or type(operation_id) is not str
                or _REQUEST_ID_RE.fullmatch(operation_id) is None
                or type(revision) is not int
                or revision <= 0
                or type(fingerprint) is not str
            ):
                return OwnershipCheck(False, "marker-mismatch")
            if not _is_owned_runtime_marker(
                payload,
                bot_id=bot_id,
                operation_id=operation_id,
                desired_revision=revision,
                pid=pid,
                expected_fingerprint=fingerprint,
            ):
                return OwnershipCheck(False, "marker-mismatch")
            resolved_hermes_bin = self._resolved_hermes_bin()
            marker_hermes = payload.get("resolved_hermes_bin")
            if (
                resolved_hermes_bin is None
                or type(marker_hermes) is not str
                or _resolve_executable(marker_hermes) != resolved_hermes_bin
            ):
                return OwnershipCheck(False, "untrusted-executable")
            marker_check = _verify_gateway_command(
                argv,
                bot_id,
                resolved_hermes_bin,
                require_trusted_path=True,
            )
            return OwnershipCheck(
                marker_check.verified,
                marker_check.reason,
                marker_check.classification,
            )
        if schema == 2:
            if payload.get("bot_id") != bot_id:
                return OwnershipCheck(False, "wrong-bot-id")
            if payload.get("component") != "gateway" or payload.get("action") != "run":
                return OwnershipCheck(False, "wrong-command-intent")
            resolved_hermes_bin = self._resolved_hermes_bin()
            if not isinstance(payload.get("resolved_hermes_bin"), str):
                return OwnershipCheck(False, "untrusted-executable")
            marker_hermes = _resolve_executable(str(payload["resolved_hermes_bin"]))
            if marker_hermes != resolved_hermes_bin:
                return OwnershipCheck(False, "untrusted-executable")
            marker_check = _verify_gateway_command(
                argv, bot_id, resolved_hermes_bin, require_trusted_path=True
            )
            return OwnershipCheck(
                marker_check.verified,
                marker_check.reason,
                marker_check.classification,
            )
        if schema is not None:
            return OwnershipCheck(False, "marker-mismatch")
        if not self.allow_legacy_pid_markers:
            return OwnershipCheck(False, "legacy-marker-disabled")
        marker_check = _verify_gateway_command(argv, bot_id, None, require_trusted_path=False)
        if not marker_check.verified:
            return OwnershipCheck(False, marker_check.reason, marker_check.classification)
        return OwnershipCheck(True, "ok", "legacy-marker-valid")

    def _resolved_hermes_bin(self) -> str | None:
        return _resolve_executable(self.adapter.hermes_bin)

    def _trusted_hermes_bins(self) -> set[str]:
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

    def _terminate_spawned_process(self, process: PopenLike, cleanup_errors: list[str]) -> bool:
        if process.poll() is not None:
            self._reap_spawned_process(process, cleanup_errors, timeout=0)
            if self._spawned_tree_stopped(process, timeout=0):
                return True
        term_result = self._signal_spawned_process(process, signal.SIGTERM, cleanup_errors)
        if term_result == _SignalResult.missing:
            self._reap_spawned_process(process, cleanup_errors, timeout=0)
            return self._spawned_tree_stopped(process, timeout=0)
        if term_result == _SignalResult.denied:
            return False
        self._reap_spawned_process(
            process,
            cleanup_errors,
            timeout=self.stop_grace_seconds,
        )
        if self._spawned_tree_stopped(process, timeout=0):
            return True
        kill_result = self._signal_spawned_process(process, signal.SIGKILL, cleanup_errors)
        if kill_result == _SignalResult.missing:
            self._reap_spawned_process(process, cleanup_errors, timeout=0)
            return self._spawned_tree_stopped(process, timeout=0)
        if kill_result == _SignalResult.denied:
            return False
        self._reap_spawned_process(
            process,
            cleanup_errors,
            timeout=self.stop_grace_seconds,
        )
        return self._spawned_tree_stopped(process, timeout=self.stop_grace_seconds)

    def _signal_spawned_process(
        self,
        process: PopenLike,
        sig: signal.Signals,
        cleanup_errors: list[str],
    ) -> _SignalResult:
        if self._cleanup_process_group:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                return _SignalResult.missing
            except PermissionError as exc:
                cleanup_errors.append(f"killpg: {type(exc).__name__}: {exc}")
                return _SignalResult.denied
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    return _SignalResult.missing
                if exc.errno == errno.EPERM:
                    cleanup_errors.append(f"killpg: {type(exc).__name__}: {exc}")
                    return _SignalResult.denied
                raise
            return _SignalResult.sent
        method_name = "terminate" if sig == signal.SIGTERM else "kill"
        method = getattr(process, method_name, None)
        if not callable(method):
            return self._send_signal(process.pid, sig)
        try:
            method()
        except ProcessLookupError:
            return _SignalResult.missing
        except PermissionError as exc:
            cleanup_errors.append(f"{method_name}: {type(exc).__name__}: {exc}")
            return _SignalResult.denied
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return _SignalResult.missing
            if exc.errno == errno.EPERM:
                cleanup_errors.append(f"{method_name}: {type(exc).__name__}: {exc}")
                return _SignalResult.denied
            raise
        return _SignalResult.sent

    def _reap_spawned_process(
        self,
        process: PopenLike,
        cleanup_errors: list[str],
        *,
        timeout: float,
    ) -> bool:
        wait = getattr(process, "wait", None)
        if callable(wait):
            try:
                wait(timeout=timeout)
                return True
            except subprocess.TimeoutExpired:
                return False
            except Exception as exc:
                cleanup_errors.append(f"wait: {type(exc).__name__}: {exc}")
        return process.poll() is not None or self._pid_state(process.pid) == _PidState.dead

    def _spawned_tree_stopped(self, process: PopenLike, *, timeout: float) -> bool:
        if not self._cleanup_process_group:
            return process.poll() is not None or self._pid_state(process.pid) == _PidState.dead
        deadline = time.monotonic() + timeout
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return True
            except PermissionError:
                return False
            except OSError as exc:
                return exc.errno == errno.ESRCH
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def _wait_for_exit(self, bot_id: str, pid: int) -> bool:
        process = self._processes.get(bot_id)
        if process is not None and hasattr(process, "wait"):
            try:
                process.wait(timeout=self.stop_grace_seconds)
                return True
            except subprocess.TimeoutExpired:
                return False
            except Exception:
                return False

        deadline = time.monotonic() + self.stop_grace_seconds
        while self._pid_state(pid) != _PidState.dead and time.monotonic() < deadline:
            time.sleep(0.1)
        return self._pid_state(pid) == _PidState.dead

    def _poll_startup(self, process: PopenLike) -> int | None:
        returncode = process.poll()
        if returncode is not None or self.startup_grace_seconds <= 0:
            return returncode

        deadline = time.monotonic() + self.startup_grace_seconds
        while time.monotonic() < deadline:
            time.sleep(min(0.01, max(deadline - time.monotonic(), 0)))
            returncode = process.poll()
            if returncode is not None:
                return returncode
        return process.poll()


def _read_process_cmdline(pid: int) -> list[str] | None:
    system = platform.system()
    if system == "Linux":
        return _read_linux_cmdline(pid)
    if system == "Darwin":
        return _read_darwin_cmdline(pid)
    return None


def _readiness_probe_marker_payload(probe: ReadinessProbe | None) -> dict[str, object] | None:
    if probe is None:
        return None
    return {
        "url": probe.url,
        "expected_status": probe.expected_status,
        "expected_platform": probe.expected_platform,
        "timeout_seconds": probe.timeout_seconds,
        "interval_seconds": probe.interval_seconds,
    }


def _readiness_probe_from_marker(value: object) -> ReadinessProbe | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("readiness_probe must be an object or null")
    url = value.get("url")
    expected_status = value.get("expected_status")
    expected_platform = value.get("expected_platform")
    timeout_seconds = value.get("timeout_seconds")
    interval_seconds = value.get("interval_seconds")
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    parsed = urlparse(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("url must be loopback HTTP without credentials or query data")
    if not isinstance(expected_status, str) or not expected_status:
        raise ValueError("expected_status must be a non-empty string")
    if not isinstance(expected_platform, str) or not expected_platform:
        raise ValueError("expected_platform must be a non-empty string")
    if not _valid_probe_number(timeout_seconds) or not _valid_probe_number(interval_seconds):
        raise ValueError("probe timing values must be finite positive numbers")
    return ReadinessProbe(
        url=url,
        expected_status=expected_status,
        expected_platform=expected_platform,
        timeout_seconds=float(timeout_seconds),
        interval_seconds=float(interval_seconds),
    )


def _valid_probe_number(value: object) -> TypeGuard[int | float]:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 < float(value) <= 3600
    )


def _read_linux_cmdline(pid: int, proc_root: Path = Path("/proc")) -> list[str]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def _read_darwin_cmdline(pid: int) -> list[str] | None:
    try:
        completed = subprocess.run(  # nosec B603
            ["/bin/ps", "-p", str(pid), "-o", "command="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return []
    command = completed.stdout.strip()
    if not command:
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return None


def _read_process_start_fingerprint(pid: int) -> str | None:
    system = platform.system()
    if system == "Darwin":
        return _read_darwin_process_start_fingerprint(pid)
    if system != "Linux":
        return None
    return _read_linux_process_start_fingerprint(pid)


def _read_darwin_process_start_fingerprint(pid: int) -> str | None:
    try:
        completed = subprocess.run(  # nosec B603
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    started = " ".join(completed.stdout.split())
    return f"darwin:ps-lstart:{started}" if started else None


def _read_linux_process_start_fingerprint(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    try:
        stat = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    try:
        fields = stat.rsplit(") ", 1)[1].split()
    except IndexError:
        return None
    if len(fields) < 20:
        return None
    return f"linux:/proc-starttime:{fields[19]}"


def _verify_gateway_command(
    argv: list[str],
    bot_id: str,
    trusted_hermes_bin: str | set[str] | None,
    *,
    require_trusted_path: bool,
) -> _CommandCheck:
    if not argv:
        return _CommandCheck(False, "live-cmdline-missing")
    classification = "direct-hermes"
    hermes_command = argv[0]
    args = argv[1:]
    if len(argv) >= 2 and _looks_like_python_interpreter(argv[0]):
        classification = "python-script-wrapper"
        hermes_command = argv[1]
        args = argv[2:]
    if len(args) != 4 or args.count("-p") != 1 or args[0] != "-p":
        return _CommandCheck(False, "wrong-command-intent", classification)
    if args[1] != bot_id:
        return _CommandCheck(False, "wrong-bot-id", classification)
    if args[2:] != ["gateway", "run"]:
        return _CommandCheck(False, "wrong-command-intent", classification)
    if require_trusted_path:
        resolved_command = _resolve_executable(hermes_command)
        if isinstance(trusted_hermes_bin, str):
            trusted_hermes_bins = {trusted_hermes_bin}
        else:
            trusted_hermes_bins = trusted_hermes_bin or set()
        if not trusted_hermes_bins or resolved_command not in trusted_hermes_bins:
            return _CommandCheck(False, "untrusted-executable", classification)
    return _CommandCheck(True, "ok", classification)


def _looks_like_python_interpreter(command: str) -> bool:
    return bool(_PYTHON_INTERPRETER_RE.fullmatch(Path(command).name.lower()))


def _resolve_executable(command: str, path: str | None = None) -> str | None:
    if not command:
        return None
    candidate = command if "/" in command else shutil.which(command, path=path)
    if candidate is None:
        return None
    try:
        return str(Path(candidate).expanduser().resolve())
    except (OSError, RuntimeError):
        return str(Path(candidate).expanduser().absolute())


def _trusted_hermes_paths(command: str) -> set[str]:
    resolved = _resolve_executable(command)
    if resolved is None:
        return set()
    paths = {resolved}
    delegated = _resolve_launcher_exec_target(resolved)
    if delegated is not None:
        paths.add(delegated)
    return paths


def _resolve_launcher_exec_target(command: str) -> str | None:
    path = Path(command)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None
    if not text.startswith("#!"):
        return None
    for line in text.splitlines()[1:20]:
        stripped = line.strip()
        if not stripped.startswith("exec "):
            continue
        try:
            parts = shlex.split(stripped)
        except ValueError:
            continue
        if len(parts) < 2 or parts[0] != "exec":
            continue
        target = parts[1]
        if "/" not in target:
            continue
        resolved = _resolve_executable(target)
        if resolved and Path(resolved).name == "hermes":
            return resolved
    return None


def _safe_command_shape(argv: list[str]) -> str:
    if not argv:
        return "empty"
    classification = "direct-hermes"
    args = argv[1:]
    if len(argv) >= 2 and _looks_like_python_interpreter(argv[0]):
        classification = "python-script-wrapper"
        args = argv[2:]
    if len(args) == 4 and args[0] == "-p" and args[2:] == ["gateway", "run"]:
        return f"{classification} hermes -p <bot> gateway run"
    return f"{classification} unrecognized"
