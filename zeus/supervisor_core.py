from __future__ import annotations

import contextlib
import os
import platform
import re
import subprocess  # nosec B404
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from zeus import process_identity as _process_identity
from zeus.gateway_launcher import (
    _read_bounded_file,
    _remove_marker_if_owned_locked,
)
from zeus.gateway_marker import (
    GatewayGeneration,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.gateway_runtime import (
    GatewayRuntime,
    KillFn,
    MarkerObservation,
    PopenFactory,
    PopenLike,
    RuntimeHooks,
    SignalResult,
    gateway_process_launch_kwargs,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.intent_recovery import PendingIntentRecovery
from zeus.lifecycle import LifecycleEventInput
from zeus.models import (
    BotRecord,
    BotStatus,
    validate_id,
)
from zeus.private_io import nofollow_absolute_path
from zeus.process_lock import BotProcessLock
from zeus.profile_manager import ProfileManager
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once
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


class _SupervisorCore:
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
