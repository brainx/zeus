from __future__ import annotations

import contextlib
import os
import platform
import re
import signal
import subprocess  # nosec B404
import threading
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.gateway_launcher import (
    _read_bounded_file,
    _remove_marker_if_owned_locked,
)
from zeus.gateway_marker import (
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.gateway_runtime import (
    GatewayRuntime,
    KillFn,
    OwnershipCheck,
    PopenFactory,
    PopenLike,
    RuntimeHooks,
    gateway_process_launch_kwargs,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.intent_recovery import PendingIntentRecovery
from zeus.lifecycle import LifecycleEventInput
from zeus.models import (
    BotRecord,
    BotStatus,
    BotStatusResponse,
    validate_id,
)
from zeus.private_io import nofollow_absolute_path
from zeus.process_lock import BotProcessLock
from zeus.profile_manager import ProfileManager
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once
from zeus.state import StateStore
from zeus.supervisor_contracts import (
    _READINESS_PROBE_UNSET,
    _GatewayGeneration,
    _LifecycleContext,
    _MarkerObservation,
    _ReadinessProbeUnset,
    _SignalResult,
)

PidAliveFn = _process_identity.PidAliveFn
CmdlineReader = _process_identity.CmdlineReader
ProcStartFingerprintReader = _process_identity.ProcStartFingerprintReader

_PidState = _process_identity.PidState
_resolve_executable = _process_identity.resolve_executable
_trusted_hermes_paths = _process_identity.trusted_hermes_paths


_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_LIFECYCLE_SOURCES = frozenset({"api", "cli", "reconcile", "recovery", "system"})


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


class _SupervisorCore:
    """Own shared state, locks, persistence coordination and live runtime hooks."""

    @staticmethod
    def _default_cmdline_reader(pid: int) -> list[str] | None:
        return _read_process_cmdline(pid)

    @staticmethod
    def _default_process_start_fingerprint_reader(pid: int) -> str | None:
        return _read_process_start_fingerprint(pid)

    @staticmethod
    def _probe_once(probe: ReadinessProbe) -> ReadinessResult:
        return probe_once(
            probe.url,
            timeout_seconds=min(1.0, max(0.2, probe.interval_seconds)),
            expected_status=probe.expected_status,
            expected_platform=probe.expected_platform,
        )

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
        stop_grace_seconds: float = 60.0,
        kill_after_timeout: bool = False,
        lock_timeout_seconds: float = 30.0,
        readiness_timeout_seconds: float = 30.0,
        readiness_interval_seconds: float = 0.5,
        allow_legacy_pid_markers: bool = True,
        restart_backoff_cap_seconds: float = 3600.0,
        proc_start_fingerprint_reader: ProcStartFingerprintReader | None = None,
        restart_stability_seconds: float = 30.0,
    ) -> None:
        if not 0.0 <= restart_stability_seconds <= 86_400.0:
            raise ValueError("restart_stability_seconds must be between 0 and 86400")
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
        self.restart_stability_seconds = restart_stability_seconds
        self._cleanup_process_group = os.name == "posix" and popen_factory is subprocess.Popen
        self._runtime = GatewayRuntime(
            self.adapter,
            self._profile_manager,
            self._marker_profiles_root,
            popen_factory=popen_factory,
            kill_fn=kill_fn,
            pid_alive_fn=pid_alive_fn,
            cmdline_reader=cmdline_reader or self._default_cmdline_reader,
            proc_start_fingerprint_reader=(
                proc_start_fingerprint_reader or self._default_process_start_fingerprint_reader
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
        self._intent_recovery = PendingIntentRecovery()
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
                    reset_restart=self.restart_stability_seconds == 0,
                )
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.running,
                    pid=pid,
                    profile_path=record.profile_path,
                    message="running",
                )
            readiness = self._probe_once(probe)
            if readiness.ready:
                self._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.running,
                    pid=pid,
                    ready_at=datetime.now(UTC),
                    last_transition_reason="gateway readiness probe passed",
                    reset_restart=self.restart_stability_seconds == 0,
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
        now = datetime.now(UTC)
        # Only the current running generation's first healthy observation counts.
        # Reusing it across polls also keeps the window intact across supervisors.
        ready_at = record.ready_at if record.status is BotStatus.running else None
        ready_at = ready_at or now
        reset_restart = (
            record.restart_attempts != 0
            and (now - ready_at).total_seconds() >= self.restart_stability_seconds
        )
        if record.next_restart_at is not None and not reset_restart:
            self._update_restart(
                context,
                record.bot_id,
                status=record.status,
                pid=pid,
                restart_attempts=record.restart_attempts,
                next_restart_at=None,
                action="bot.restart.cancel",
                reason="gateway is running; pending restart canceled",
            )
        needs_running_projection_update = (
            record.status is not BotStatus.running
            or reset_restart
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
                ready_at=ready_at,
                last_transition_reason=(
                    "gateway remained healthy for restart stability window"
                    if reset_restart
                    else "gateway process is running"
                ),
                reset_restart=reset_restart,
            )
        return BotStatusResponse(
            bot_id=record.bot_id,
            status=BotStatus.running,
            pid=pid,
            profile_path=record.profile_path,
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
        return _process_identity.pid_state(pid, pid_alive_fn=self.pid_alive_fn)

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
        readiness_probe: ReadinessProbe | _ReadinessProbeUnset | None = _READINESS_PROBE_UNSET,
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


# Historical internal import; this is the same concrete class, not another layer.
_SupervisorRuntime = _SupervisorCore
