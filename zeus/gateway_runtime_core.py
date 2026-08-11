from __future__ import annotations

import contextlib
import errno
import json
import math
import os
import select
import signal
import subprocess  # nosec B404
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

from zeus import process_identity
from zeus.gateway_launcher import (
    MAX_PAYLOAD_BYTES,
    _read_bounded_file,
    _remove_marker_if_owned_locked,
    marker_publication_lock,
)
from zeus.gateway_marker import (
    GatewayGeneration,
    readiness_probe_from_payload,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.models import BotRecord, TemplateError
from zeus.private_io import nofollow_absolute_path
from zeus.profile_manager import ProfileManager
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once, readiness_probe_from_env


class PopenLike(Protocol):
    pid: int

    def poll(self) -> int | None: ...


PopenFactory = Callable[..., PopenLike]
KillFn = Callable[[int, signal.Signals], None]
PidAliveFn = process_identity.PidAliveFn
CmdlineReader = process_identity.CmdlineReader
ProcStartFingerprintReader = process_identity.ProcStartFingerprintReader


class SignalResult(Enum):
    sent = "sent"
    missing = "missing"
    denied = "denied"


_MAX_EFFECT_TEXT = 512
_TRANSIENT_POST_EXEC_MARKER_REASONS = frozenset(
    {
        "live gateway command is unavailable",
        "process start fingerprint is unavailable",
    }
)


def _bounded_text(value: str) -> str:
    return value[:_MAX_EFFECT_TEXT]


@dataclass(frozen=True)
class OwnershipCheck:
    verified: bool
    reason: str
    classification: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _bounded_text(self.reason))
        if self.classification is not None:
            object.__setattr__(
                self,
                "classification",
                _bounded_text(self.classification),
            )


@dataclass(frozen=True, init=False)
class MarkerObservation:
    kind: str
    reason: str
    _payload_json: bytes | None = field(repr=False)

    def __init__(
        self,
        kind: str,
        payload: dict[str, object] | None = None,
        reason: str = "",
    ) -> None:
        snapshot: bytes | None = None
        if payload is not None:
            try:
                snapshot = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                ).encode("utf-8")
            except (TypeError, ValueError, UnicodeEncodeError):
                kind = "untrusted"
                reason = "marker payload could not be snapshotted safely"
            else:
                if len(snapshot) > MAX_PAYLOAD_BYTES:
                    kind = "untrusted"
                    reason = "marker payload snapshot is too large"
                    snapshot = None
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "reason", _bounded_text(reason))
        object.__setattr__(self, "_payload_json", snapshot)

    @property
    def payload(self) -> dict[str, object] | None:
        if self._payload_json is None:
            return None
        value = json.loads(self._payload_json)
        if type(value) is not dict:
            return None
        return value


@dataclass(frozen=True)
class LaunchEffect:
    outcome: str
    pid: int | None = None
    generation: GatewayGeneration | None = None
    reason: str = ""
    returncode: int | None = None
    error_type: str | None = None
    readiness_message: str | None = None
    cleanup_complete: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _bounded_text(self.reason))
        if self.error_type is not None:
            object.__setattr__(self, "error_type", _bounded_text(self.error_type))
        if self.readiness_message is not None:
            object.__setattr__(
                self,
                "readiness_message",
                _bounded_text(self.readiness_message),
            )


@dataclass(frozen=True)
class StopEffect:
    outcome: str
    pid: int | None = None
    generation: GatewayGeneration | None = None
    reason: str = ""
    term_result: SignalResult | None = None
    kill_result: SignalResult | None = None
    marker_removed: bool = False
    kill_attempted: bool = False
    kill_succeeded: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason", _bounded_text(self.reason))


PipeFn = Callable[[], tuple[int, int]]
CloseFn = Callable[[int], None]
ReadBoundedFileFn = Callable[[int], bytes]
RemoveMarkerLockedFn = Callable[..., bool]
ProbeOnceFn = Callable[..., ReadinessResult]


@dataclass(frozen=True)
class RuntimeHooks:
    pipe: PipeFn
    close: CloseFn
    read_bounded_file: ReadBoundedFileFn
    remove_marker_if_owned_locked: RemoveMarkerLockedFn
    probe_once: ProbeOnceFn


def default_runtime_hooks() -> RuntimeHooks:
    return RuntimeHooks(
        pipe=os.pipe,
        close=os.close,
        read_bounded_file=_read_bounded_file,
        remove_marker_if_owned_locked=_remove_marker_if_owned_locked,
        probe_once=probe_once,
    )


def gateway_process_launch_kwargs() -> dict[str, object]:
    if os.name == "posix":
        return {"start_new_session": True}
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return {"creationflags": creationflags} if creationflags else {}


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _caused_by_missing_path(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, FileNotFoundError):
            return True
        current = current.__cause__
    return False


class _GatewayRuntimeCore:
    def __init__(
        self,
        adapter: HermesAdapter,
        profile_manager: ProfileManager,
        marker_profiles_root: Path,
        *,
        popen_factory: PopenFactory = subprocess.Popen,
        kill_fn: KillFn = os.kill,
        pid_alive_fn: PidAliveFn | None = None,
        cmdline_reader: CmdlineReader,
        proc_start_fingerprint_reader: ProcStartFingerprintReader,
        startup_grace_seconds: float = 0.25,
        stop_grace_seconds: float = 15.0,
        kill_after_timeout: bool = False,
        lock_timeout_seconds: float = 30.0,
        readiness_timeout_seconds: float = 30.0,
        readiness_interval_seconds: float = 0.5,
        allow_legacy_pid_markers: bool = True,
        cleanup_process_group: bool = False,
        hooks_provider: Callable[[], RuntimeHooks] = default_runtime_hooks,
    ) -> None:
        self.adapter = adapter
        self.profile_manager = profile_manager
        self.marker_profiles_root = marker_profiles_root
        self.popen_factory = popen_factory
        self.kill_fn = kill_fn
        self.pid_alive_fn = pid_alive_fn
        self.cmdline_reader = cmdline_reader
        self.proc_start_fingerprint_reader = proc_start_fingerprint_reader
        self.startup_grace_seconds = startup_grace_seconds
        self.stop_grace_seconds = stop_grace_seconds
        self.kill_after_timeout = kill_after_timeout
        self.lock_timeout_seconds = lock_timeout_seconds
        self.readiness_timeout_seconds = readiness_timeout_seconds
        self.readiness_interval_seconds = readiness_interval_seconds
        self.allow_legacy_pid_markers = allow_legacy_pid_markers
        self.cleanup_process_group = cleanup_process_group
        self._hooks_provider = hooks_provider
        self._processes: dict[str, PopenLike] = {}

    def _hooks(self) -> RuntimeHooks:
        return self._hooks_provider()

    def safe_profile_path(self, bot_id: str, profile_path: str) -> Path:
        return self.profile_manager.validate_profile_path(bot_id, profile_path)

    def marker_publication_lock(
        self,
        record: BotRecord,
    ) -> contextlib.AbstractContextManager[object]:
        profile_path = self.safe_profile_path(record.bot_id, record.profile_path)
        if not os.path.lexists(profile_path):
            return contextlib.nullcontext()
        return marker_publication_lock(
            profile_path,
            timeout_seconds=self.lock_timeout_seconds,
        )

    def log_path(self, profile_path: str) -> Path:
        return nofollow_absolute_path(Path(profile_path) / "logs" / "zeus-gateway.log")

    def pid_marker_path(self, profile_path: str) -> Path:
        return Path(profile_path) / "logs" / "zeus-gateway.pid.json"

    @staticmethod
    def write_pipe_payload(fd: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("short launcher payload write")
            offset += written

    @staticmethod
    def read_launcher_ack(fd: int) -> bytes:
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

    def readiness_probe_for_bot(
        self,
        bot_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> ReadinessProbe | None:
        _argv, env = self.adapter.command(bot_id, "gateway", "run")
        return self.readiness_probe(env, timeout_seconds=timeout_seconds)

    def readiness_probe_for_live_record(
        self,
        record: BotRecord,
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
            return self.readiness_probe_for_bot(record.bot_id), None
        try:
            return readiness_probe_from_payload(payload["readiness_probe"]), None
        except ValueError as exc:
            return None, f"readiness provenance in the PID marker is invalid: {exc}"

    def readiness_probe(
        self,
        env: dict[str, str],
        *,
        timeout_seconds: float | None = None,
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

    def wait_for_readiness(
        self,
        process: PopenLike,
        readiness: ReadinessProbe,
    ) -> ReadinessResult:
        deadline = time.monotonic() + readiness.timeout_seconds
        last = ReadinessResult(False, "not probed yet")
        probe = self._hooks().probe_once
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return ReadinessResult(False, "gateway process exited during readiness check")
            last = probe(
                readiness.url,
                timeout_seconds=min(5.0, max(0.2, readiness.interval_seconds)),
                expected_status=readiness.expected_status,
                expected_platform=readiness.expected_platform,
            )
            if last.ready:
                return last
            time.sleep(readiness.interval_seconds)
        return ReadinessResult(False, f"readiness timeout: {last.message}", last.payload)

    def pid_state(self, pid: int) -> process_identity.PidState:
        if self.pid_alive_fn is not None:
            return process_identity.pid_state(pid, pid_alive_fn=self.pid_alive_fn)

        def probe_with_current_kill(probe_pid: int) -> bool:
            os.kill(probe_pid, 0)
            return True

        return process_identity.pid_state(pid, pid_alive_fn=probe_with_current_kill)

    def send_signal(self, pid: int, sig: signal.Signals) -> SignalResult:
        try:
            self.kill_fn(pid, sig)
        except ProcessLookupError:
            return SignalResult.missing
        except PermissionError:
            return SignalResult.denied
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return SignalResult.missing
            if exc.errno == errno.EPERM:
                return SignalResult.denied
            raise
        return SignalResult.sent

    def resolved_hermes_bin(self) -> str | None:
        return process_identity.resolve_executable(self.adapter.hermes_bin)

    def trusted_hermes_bins(self) -> set[str]:
        return process_identity.trusted_hermes_paths(self.adapter.hermes_bin)

    def terminate_spawned_process(
        self,
        process: PopenLike,
        cleanup_errors: list[str],
    ) -> bool:
        if process.poll() is not None:
            self.reap_spawned_process(process, cleanup_errors, timeout=0)
            if self.spawned_tree_stopped(process, timeout=0):
                return True
        term_result = self.signal_spawned_process(process, signal.SIGTERM, cleanup_errors)
        if term_result is SignalResult.missing:
            self.reap_spawned_process(process, cleanup_errors, timeout=0)
            return self.spawned_tree_stopped(process, timeout=0)
        if term_result is SignalResult.denied:
            return False
        self.reap_spawned_process(process, cleanup_errors, timeout=self.stop_grace_seconds)
        if self.spawned_tree_stopped(process, timeout=0):
            return True
        kill_result = self.signal_spawned_process(process, signal.SIGKILL, cleanup_errors)
        if kill_result is SignalResult.missing:
            self.reap_spawned_process(process, cleanup_errors, timeout=0)
            return self.spawned_tree_stopped(process, timeout=0)
        if kill_result is SignalResult.denied:
            return False
        self.reap_spawned_process(process, cleanup_errors, timeout=self.stop_grace_seconds)
        return self.spawned_tree_stopped(process, timeout=self.stop_grace_seconds)

    def signal_spawned_process(
        self,
        process: PopenLike,
        sig: signal.Signals,
        cleanup_errors: list[str],
    ) -> SignalResult:
        if self.cleanup_process_group:
            # Once the Popen leader has exited, its numeric pid can be reused by
            # an unrelated session leader.  A same-valued pgid is therefore no
            # longer sufficient authorization to signal the group.
            if process.poll() is not None:
                cleanup_errors.append(
                    "killpg: spawned process already exited; process group ownership "
                    "cannot be verified"
                )
                return SignalResult.denied
            if self._spawned_group_reissued(process, "killpg", cleanup_errors):
                return SignalResult.denied
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                return SignalResult.missing
            except PermissionError as exc:
                cleanup_errors.append(f"killpg: {type(exc).__name__}: {exc}")
                return SignalResult.denied
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    return SignalResult.missing
                if exc.errno == errno.EPERM:
                    cleanup_errors.append(f"killpg: {type(exc).__name__}: {exc}")
                    return SignalResult.denied
                raise
            return SignalResult.sent
        method_name = "terminate" if sig == signal.SIGTERM else "kill"
        method = getattr(process, method_name, None)
        if not callable(method):
            return self.send_signal(process.pid, sig)
        try:
            method()
        except ProcessLookupError:
            return SignalResult.missing
        except PermissionError as exc:
            cleanup_errors.append(f"{method_name}: {type(exc).__name__}: {exc}")
            return SignalResult.denied
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return SignalResult.missing
            if exc.errno == errno.EPERM:
                cleanup_errors.append(f"{method_name}: {type(exc).__name__}: {exc}")
                return SignalResult.denied
            raise
        return SignalResult.sent

    def reap_spawned_process(
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
        return (
            process.poll() is not None
            or self.pid_state(process.pid) is process_identity.PidState.dead
        )

    @staticmethod
    def _spawned_group_reissued(
        process: PopenLike,
        operation: str,
        cleanup_errors: list[str],
    ) -> bool:
        """The child starts a new session, so while it lives pgid == pid. After
        the pid is reaped the OS can reissue it to an unrelated process; only a
        *mismatch* proves reissue (a gone pid says nothing about the group)."""
        try:
            pgid = os.getpgid(process.pid)
        except OSError:
            return False
        if pgid == process.pid:
            return False
        cleanup_errors.append(f"{operation}: process group id no longer belongs to pid")
        return True

    def spawned_tree_stopped(self, process: PopenLike, *, timeout: float) -> bool:
        if not self.cleanup_process_group:
            return (
                process.poll() is not None
                or self.pid_state(process.pid) is process_identity.PidState.dead
            )
        if self._spawned_group_reissued(process, "killpg probe", []):
            # The new pid owner says nothing about descendants that may remain
            # in the original process group, so cleanup cannot be proven.
            return False
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

    def wait_for_exit(self, bot_id: str, pid: int) -> bool:
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
        while (
            self.pid_state(pid) is not process_identity.PidState.dead
            and time.monotonic() < deadline
        ):
            time.sleep(0.1)
        return self.pid_state(pid) is process_identity.PidState.dead

    def poll_startup(self, process: PopenLike) -> int | None:
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
