from __future__ import annotations

import contextlib
import errno
import json
import math
import os
import platform
import select
import signal
import stat
import subprocess  # nosec B404
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

from zeus import process_identity
from zeus.errors import BotRunningError
from zeus.fs_utils import atomic_write_json
from zeus.gateway_launcher import (
    MAX_PAYLOAD_BYTES,
    LaunchPayloadError,
    _confirm_marker_missing,
    _ConfirmedMissing,
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
from zeus.gateway_marker import (
    GatewayGeneration,
    is_compat_runtime_marker,
    is_owned_runtime_marker,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.hermes_adapter import HermesAdapter
from zeus.models import BotRecord, TemplateError
from zeus.private_io import UnsafeFileError, nofollow_absolute_path, open_private_append
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


class GatewayRuntime:
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

    def preflight_start(
        self,
        record: BotRecord,
        *,
        timeout_seconds: float | None,
    ) -> ReadinessProbe | None:
        expected_profile = (Path(self.adapter.hermes_root) / "profiles" / record.bot_id).resolve()
        if Path(record.profile_path).resolve() != expected_profile:
            raise TemplateError("registered bot profile does not match the Hermes profile path")
        safe_profile = self.safe_profile_path(record.bot_id, record.profile_path)
        if not safe_profile.is_dir() or safe_profile.is_symlink():
            raise TemplateError("registered bot profile is not a safe directory")
        _argv, env = self.adapter.command(record.bot_id, "gateway", "run")
        readiness = self.readiness_probe(env, timeout_seconds=timeout_seconds)
        self.adapter.launcher_payload(
            record.bot_id,
            operation_id="0" * 32,
            desired_revision=max(1, record.desired_revision + 1),
            readiness_probe=readiness,
        )
        return readiness

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

    def launch(
        self,
        record: BotRecord,
        *,
        probe: ReadinessProbe | None,
        wait: bool,
        marker_lock: Callable[[BotRecord], contextlib.AbstractContextManager[object]] | None = None,
        marker_matcher: Callable[..., MarkerObservation] | None = None,
        ack_reader: Callable[[int], bytes] | None = None,
        pipe_writer: Callable[[int, bytes], None] | None = None,
    ) -> LaunchEffect:
        operation_id = record.pending_operation_id
        if record.pending_action not in {"start", "restart"} or operation_id is None:
            raise RuntimeError("gateway launch requires a pending start or restart intent")
        payload = self.adapter.launcher_payload(
            record.bot_id,
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            readiness_probe=probe,
        )
        marker_data = payload["marker"]
        if type(marker_data) is not dict:
            raise RuntimeError("launcher produced an invalid marker payload")
        expected_fingerprint = str(marker_data["command_fingerprint"])
        process: PopenLike | None = None
        generation: GatewayGeneration | None = None
        payload_read = payload_write = ack_read = ack_write = -1
        hooks = self._hooks()
        marker_lock = marker_lock or self.marker_publication_lock
        marker_matcher = marker_matcher or self.matching_runtime_marker
        ack_reader = ack_reader or self.read_launcher_ack
        pipe_writer = pipe_writer or self.write_pipe_payload
        try:
            encoded_payload = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            if not encoded_payload or len(encoded_payload) > MAX_PAYLOAD_BYTES:
                raise ValueError("launcher payload is too large")
            with open_private_append(self.log_path(record.profile_path)) as log_file:
                payload_read, payload_write = hooks.pipe()
                ack_read, ack_write = hooks.pipe()
                launcher_argv = self.adapter.launcher_command(payload_read, ack_write)
                process = self.popen_factory(
                    launcher_argv,
                    env=dict(os.environ),
                    stdout=log_file,
                    stderr=log_file,
                    pass_fds=(payload_read, ack_write),
                    close_fds=True,
                    **gateway_process_launch_kwargs(),
                )
            hooks.close(payload_read)
            payload_read = -1
            hooks.close(ack_write)
            ack_write = -1
            pipe_writer(payload_write, encoded_payload)
            hooks.close(payload_write)
            payload_write = -1
            acknowledgment = ack_reader(ack_read)
            hooks.close(ack_read)
            ack_read = -1
            if acknowledgment != b"1":
                raise RuntimeError("gateway launcher did not acknowledge marker publication")
            with marker_lock(record):
                marker = marker_matcher(
                    record,
                    expected_fingerprint=expected_fingerprint,
                    expected_pid=process.pid,
                    require_live_command=True,
                )
                generation = self.gateway_generation(marker)
                if marker.kind != "live" or generation is None:
                    raise RuntimeError(
                        "gateway launcher ownership marker could not be verified: " + marker.reason
                    )
            self._processes[record.bot_id] = process
        except BaseException as exc:
            for fd in (payload_read, payload_write, ack_read, ack_write):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        hooks.close(fd)
            if process is None:
                if not isinstance(exc, (OSError, ValueError)):
                    raise
                self._processes.pop(record.bot_id, None)
                return LaunchEffect(
                    "launch_failed",
                    reason=str(exc),
                    error_type=type(exc).__name__,
                )
            cleanup_complete = self.cleanup_interrupted_launch(
                record,
                process,
                expected_fingerprint=expected_fingerprint,
            )
            if not isinstance(exc, Exception):
                raise
            return LaunchEffect(
                "registration_failed_clean" if cleanup_complete else "registration_failed_unknown",
                pid=None if cleanup_complete else process.pid,
                reason=str(exc),
                error_type=type(exc).__name__,
                cleanup_complete=cleanup_complete,
            )
        if process is None or generation is None:
            raise RuntimeError("gateway process factory returned no process")
        returncode = self.poll_startup(process)
        if returncode is not None:
            self.remove_gateway_generation_marker(record, generation)
            self._processes.pop(record.bot_id, None)
            return LaunchEffect(
                "startup_exited",
                generation=generation,
                reason="gateway exited during startup grace period",
                returncode=returncode,
            )
        if probe is not None:
            if wait:
                readiness = self.wait_for_readiness(process, probe)
                if process.poll() is not None:
                    returncode = process.poll()
                    self.remove_gateway_generation_marker(record, generation)
                    self._processes.pop(record.bot_id, None)
                    return LaunchEffect(
                        "readiness_exited",
                        generation=generation,
                        reason="gateway process exited during readiness check",
                        returncode=returncode,
                    )
                if readiness.ready:
                    return LaunchEffect("ready", process.pid, generation)
                return LaunchEffect(
                    "readiness_timeout",
                    process.pid,
                    generation,
                    reason="readiness probe timed out",
                    readiness_message=readiness.message,
                )
            return LaunchEffect("readiness_pending", process.pid, generation)
        return LaunchEffect("running", process.pid, generation)

    def cleanup_interrupted_launch(
        self,
        record: BotRecord,
        process: PopenLike,
        *,
        expected_fingerprint: str,
    ) -> bool:
        cleanup_errors: list[str] = []
        if not self.terminate_spawned_process(process, cleanup_errors):
            return False
        self._processes.pop(record.bot_id, None)
        operation_id = record.pending_operation_id
        if operation_id is None:
            return False
        remove_marker_if_owned(
            self.safe_profile_path(record.bot_id, record.profile_path),
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            pid=process.pid,
            command_fingerprint=expected_fingerprint,
        )
        return self.read_strict_runtime_marker(record.bot_id, record.profile_path).kind == "missing"

    def cleanup_registered_launch(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool:
        process = self._processes.get(record.bot_id)
        if process is None or process.pid != generation.pid:
            return False
        cleanup_errors: list[str] = []
        if not self.terminate_spawned_process(process, cleanup_errors):
            return False
        self._processes.pop(record.bot_id, None)
        self.remove_gateway_generation_marker(record, generation)
        return self.read_strict_runtime_marker(record.bot_id, record.profile_path).kind == "missing"

    def read_strict_runtime_marker(
        self,
        bot_id: str,
        registered_profile_path: str,
    ) -> MarkerObservation:
        profile_path = nofollow_absolute_path(Path(registered_profile_path))
        expected_profile = self.marker_profiles_root / bot_id
        if not profile_path.is_absolute() or profile_path != expected_profile:
            return MarkerObservation(
                "untrusted",
                reason="registered profile path does not match the trusted Hermes profile",
            )
        profile = None
        logs_fd = marker_fd = -1
        hooks = self._hooks()
        try:
            profile = _open_profile_chain(profile_path)
        except _ConfirmedMissing:
            return MarkerObservation("missing", reason="marker is missing")
        except (OSError, ValueError) as exc:
            return MarkerObservation(
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
                        return MarkerObservation(
                            "untrusted",
                            reason=f"marker directory absence is untrusted: {confirm_error}",
                        )
                    return MarkerObservation("missing", reason="marker is missing")
                return MarkerObservation(
                    "untrusted", reason=f"marker directory cannot be opened safely: {exc}"
                )
            try:
                marker_fd, marker_stat = _open_regular_marker(logs_fd)
                raw = hooks.read_bounded_file(marker_fd)
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
                    return MarkerObservation(
                        "untrusted", reason=f"marker absence is untrusted: {confirm_error}"
                    )
                return MarkerObservation("missing", reason="marker is missing")
            except ValueError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    try:
                        _confirm_marker_missing(profile, logs_fd)
                    except (OSError, ValueError) as confirm_error:
                        return MarkerObservation(
                            "untrusted", reason=f"marker absence is untrusted: {confirm_error}"
                        )
                    return MarkerObservation("missing", reason="marker is missing")
                return MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
        except FileNotFoundError as exc:
            return MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
        finally:
            for fd in (marker_fd, logs_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        hooks.close(fd)
            if profile is not None:
                profile.close()
        if type(value) is not dict:
            return MarkerObservation("untrusted", reason="marker is not an object")
        if marker_stat.st_nlink != 1:
            return MarkerObservation("untrusted", reason="marker has unexpected hard links")
        return MarkerObservation("present", payload=value)

    def matching_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_fingerprint: str,
        expected_pid: int | None = None,
        require_live_command: bool,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
    ) -> MarkerObservation:
        read_marker = read_marker or self.read_strict_runtime_marker
        observed = read_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return observed
        operation_id = record.pending_operation_id
        if operation_id is None:
            return MarkerObservation("untrusted", reason="pending operation is missing")
        return self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=expected_pid,
            expected_operation_id=operation_id,
            expected_revision=record.desired_revision,
            expected_fingerprint=expected_fingerprint,
            require_live_command=require_live_command,
        )

    def classify_schema3_runtime_marker(
        self,
        record: BotRecord,
        payload: dict[str, object],
        *,
        expected_pid: int | None = None,
        expected_operation_id: str | None = None,
        expected_revision: int | None = None,
        expected_fingerprint: str | None = None,
        require_live_command: bool,
    ) -> MarkerObservation:
        pid_value = payload.get("pid")
        if type(pid_value) is not int or pid_value <= 0:
            return MarkerObservation("untrusted", reason="marker PID is invalid")
        pid = pid_value
        if expected_pid is not None and pid != expected_pid:
            return MarkerObservation("untrusted", reason="marker PID does not match")
        operation_id = payload.get("operation_id")
        revision = payload.get("desired_revision")
        fingerprint = payload.get("command_fingerprint")
        if (
            type(operation_id) is not str
            or type(revision) is not int
            or type(fingerprint) is not str
        ):
            return MarkerObservation("untrusted", reason="marker correlation is invalid")
        if expected_operation_id is not None and operation_id != expected_operation_id:
            return MarkerObservation("untrusted", reason="marker operation does not match")
        if expected_revision is not None and revision != expected_revision:
            return MarkerObservation("untrusted", reason="marker revision does not match")
        if expected_fingerprint is not None and fingerprint != expected_fingerprint:
            return MarkerObservation("untrusted", reason="marker command does not match")
        if not is_owned_runtime_marker(
            payload,
            bot_id=record.bot_id,
            operation_id=operation_id,
            desired_revision=revision,
            pid=pid,
            expected_fingerprint=fingerprint,
        ):
            return MarkerObservation("untrusted", reason="marker schema or command does not match")
        expected_hermes = self.resolved_hermes_bin()
        if expected_hermes is None or payload.get("resolved_hermes_bin") != expected_hermes:
            return MarkerObservation("untrusted", reason="marker executable is not trusted")
        if not require_live_command:
            start_identity_error = self.process_start_identity_error(payload, pid)
            if start_identity_error is not None:
                return MarkerObservation("untrusted", reason=start_identity_error)
            return MarkerObservation("live", payload=payload)
        pid_state = self.pid_state(pid)
        if pid_state is process_identity.PidState.unknown:
            return MarkerObservation("untrusted", reason="marker PID liveness is unknown")
        if pid_state is process_identity.PidState.dead:
            if self.process_start_fingerprint_required() and not self.valid_marker_start(
                payload.get("proc_start_fingerprint")
            ):
                return MarkerObservation(
                    "untrusted", reason="process start fingerprint is unavailable"
                )
            return MarkerObservation("dead", payload=payload, reason="marker PID is dead")
        start_identity_error = self.process_start_identity_error(payload, pid)
        if start_identity_error is not None:
            return MarkerObservation("untrusted", reason=start_identity_error)
        live_argv = self.cmdline_reader(pid)
        if not live_argv:
            return MarkerObservation("untrusted", reason="live gateway command is unavailable")
        command_check = process_identity.verify_gateway_command(
            live_argv,
            record.bot_id,
            self.trusted_hermes_bins(),
            require_trusted_path=True,
        )
        if not command_check.verified:
            return MarkerObservation("untrusted", reason="live gateway command does not match")
        return MarkerObservation("live", payload=payload)

    def process_start_identity_error(self, payload: dict[str, object], pid: int) -> str | None:
        return process_identity.process_start_identity_error(
            payload.get("proc_start_fingerprint"),
            self.proc_start_fingerprint_reader(pid),
            fingerprint_required=self.process_start_fingerprint_required(),
        )

    @staticmethod
    def valid_marker_start(value: object) -> bool:
        return process_identity.valid_process_start_fingerprint(value)

    @staticmethod
    def process_start_fingerprint_required() -> bool:
        return process_identity.process_start_fingerprint_required(platform.system())

    def classify_existing_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_pid: int | None = None,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
    ) -> MarkerObservation:
        read_marker = read_marker or self.read_strict_runtime_marker
        observed = read_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return observed
        return self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=expected_pid,
            require_live_command=True,
        )

    @staticmethod
    def gateway_generation(marker: MarkerObservation) -> GatewayGeneration | None:
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
        return GatewayGeneration(
            operation_id=operation_id,
            desired_revision=revision,
            pid=pid,
            command_fingerprint=fingerprint,
            proc_start_fingerprint=process_start,
        )

    def classify_exact_gateway_generation(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
    ) -> MarkerObservation:
        read_marker = read_marker or self.read_strict_runtime_marker
        observed = read_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return MarkerObservation("untrusted", reason="previous gateway marker changed")
        if observed.payload.get("proc_start_fingerprint") != generation.proc_start_fingerprint:
            return MarkerObservation(
                "untrusted", reason="previous gateway process identity changed"
            )
        return self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=generation.pid,
            expected_operation_id=generation.operation_id,
            expected_revision=generation.desired_revision,
            expected_fingerprint=generation.command_fingerprint,
            require_live_command=True,
        )

    def remove_exact_schema3_marker(
        self,
        record: BotRecord,
        marker: MarkerObservation,
    ) -> bool:
        generation = self.gateway_generation(marker)
        return bool(
            marker.kind == "dead"
            and generation is not None
            and self.remove_gateway_generation_marker(record, generation)
        )

    def remove_gateway_generation_marker(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool:
        return remove_marker_if_owned(
            self.safe_profile_path(record.bot_id, record.profile_path),
            operation_id=generation.operation_id,
            desired_revision=generation.desired_revision,
            pid=generation.pid,
            command_fingerprint=generation.command_fingerprint,
            expected_proc_start_fingerprint=generation.proc_start_fingerprint,
            lock_timeout_seconds=self.lock_timeout_seconds,
        )

    def remove_gateway_generation_marker_locked(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool:
        return self._hooks().remove_marker_if_owned_locked(
            self.safe_profile_path(record.bot_id, record.profile_path),
            operation_id=generation.operation_id,
            desired_revision=generation.desired_revision,
            pid=generation.pid,
            command_fingerprint=generation.command_fingerprint,
            expected_proc_start_fingerprint=generation.proc_start_fingerprint,
        )

    def remove_owned_launch_marker_locked(
        self,
        record: BotRecord,
        *,
        observed: MarkerObservation | None = None,
    ) -> bool:
        if observed is None:
            observed = self.read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind == "missing":
            return True
        if observed.kind != "present" or observed.payload is None or record.pid is None:
            return False
        if record.pending_action not in {"stop", "restart"}:
            return False
        marker = self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=record.pid,
            expected_revision=record.desired_revision - 1,
            require_live_command=True,
        )
        generation = self.gateway_generation(marker)
        return bool(
            marker.kind == "dead"
            and generation is not None
            and self.remove_gateway_generation_marker_locked(record, generation)
        )

    def reauthorize_and_signal(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        sig: signal.Signals,
        *,
        classify_exact: Callable[[BotRecord, GatewayGeneration], MarkerObservation] | None = None,
    ) -> tuple[MarkerObservation, SignalResult | None]:
        classify_exact = classify_exact or self.classify_exact_gateway_generation
        current = classify_exact(record, generation)
        if current.kind != "live":
            return current, None
        return current, self.send_signal(generation.pid, sig)

    def stop_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
        classify_existing: Callable[..., MarkerObservation] | None = None,
        classify_exact: Callable[[BotRecord, GatewayGeneration], MarkerObservation] | None = None,
        remove_owned: Callable[..., bool] | None = None,
        remove_generation: Callable[[BotRecord, GatewayGeneration], bool] | None = None,
    ) -> StopEffect:
        read_marker = read_marker or self.read_strict_runtime_marker
        classify_existing = classify_existing or self.classify_existing_runtime_marker
        classify_exact = classify_exact or self.classify_exact_gateway_generation
        remove_owned = remove_owned or self.remove_owned_launch_marker_locked
        remove_generation = remove_generation or self.remove_gateway_generation_marker_locked
        observed = read_marker(record.bot_id, record.profile_path)
        if (
            observed.kind == "present"
            and observed.payload is not None
            and is_compat_runtime_marker(observed.payload)
        ):
            return StopEffect(
                "compat_untrusted",
                record.pid,
                reason="schema-v2 or legacy gateway stop requires manual process resolution",
            )
        if not record.pid:
            if not remove_owned(record, observed=observed):
                return StopEffect(
                    "cleanup_unverified",
                    record.pid,
                    reason="stale gateway marker ownership could not be verified",
                )
            return StopEffect("not_running", record.pid, marker_removed=True)
        marker = classify_existing(record, expected_pid=record.pid)
        generation = self.gateway_generation(marker)
        if marker.kind == "live" and generation is not None:
            return self.stop_generation_locked(
                record,
                generation,
                kill_after_timeout=kill_after_timeout,
                classify_exact=classify_exact,
                remove_generation=remove_generation,
            )
        if marker.kind == "dead":
            if not remove_owned(record, observed=observed):
                return StopEffect(
                    "cleanup_unverified",
                    record.pid,
                    reason="stale gateway marker ownership could not be verified",
                )
            return StopEffect("not_running", record.pid, marker_removed=True)
        pid_state = self.pid_state(record.pid)
        if pid_state is process_identity.PidState.unknown:
            return StopEffect("pid_unknown", record.pid, reason="gateway PID liveness is unknown")
        if pid_state is process_identity.PidState.dead:
            if not remove_owned(record, observed=observed):
                return StopEffect(
                    "cleanup_unverified",
                    record.pid,
                    reason="stale gateway marker ownership could not be verified",
                )
            return StopEffect("not_running", record.pid, marker_removed=True)
        if marker.kind != "live" or generation is None:
            return StopEffect(
                "ownership_unverified",
                record.pid,
                reason="refusing to stop process because PID ownership could not be verified",
            )
        raise AssertionError("unreachable gateway marker state")

    def stop_generation_locked(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        kill_after_timeout: bool | None,
        classify_exact: Callable[[BotRecord, GatewayGeneration], MarkerObservation] | None = None,
        remove_generation: Callable[[BotRecord, GatewayGeneration], bool] | None = None,
    ) -> StopEffect:
        classify_exact = classify_exact or self.classify_exact_gateway_generation
        remove_generation = remove_generation or self.remove_gateway_generation_marker_locked
        current = classify_exact(record, generation)
        term_result: SignalResult | None = None
        kill_result: SignalResult | None = None
        if current.kind == "dead":
            stopped = True
        elif current.kind == "live":
            current, term_result = self.reauthorize_and_signal(
                record,
                generation,
                signal.SIGTERM,
                classify_exact=classify_exact,
            )
            if current.kind != "live" or term_result is None:
                return StopEffect(
                    "term_reauthorization_failed",
                    generation.pid,
                    generation,
                    current.reason or "gateway ownership changed before SIGTERM",
                )
            if term_result is SignalResult.denied:
                return StopEffect(
                    "term_denied",
                    generation.pid,
                    generation,
                    "could not send SIGTERM to the gateway",
                    term_result=term_result,
                )
            stopped = term_result is SignalResult.missing
            if not stopped:
                stopped = self.wait_for_exit(record.bot_id, generation.pid)
        else:
            return StopEffect(
                "term_reauthorization_failed",
                generation.pid,
                generation,
                current.reason or "gateway ownership changed before SIGTERM",
            )
        should_kill = self.kill_after_timeout if kill_after_timeout is None else kill_after_timeout
        kill_attempted = False
        kill_succeeded: bool | None = None
        if not stopped and should_kill:
            kill_attempted = True
            current, kill_result = self.reauthorize_and_signal(
                record,
                generation,
                signal.SIGKILL,
                classify_exact=classify_exact,
            )
            if current.kind == "dead":
                stopped = True
                kill_succeeded = True
            elif current.kind != "live" or kill_result is None:
                return StopEffect(
                    "kill_reauthorization_failed",
                    generation.pid,
                    generation,
                    current.reason or "gateway ownership changed before SIGKILL",
                    term_result=term_result,
                    kill_attempted=True,
                )
            elif kill_result is SignalResult.denied:
                return StopEffect(
                    "kill_denied",
                    generation.pid,
                    generation,
                    "could not send SIGKILL to the gateway",
                    term_result=term_result,
                    kill_result=kill_result,
                    kill_attempted=True,
                    kill_succeeded=False,
                )
            else:
                stopped = kill_result is SignalResult.missing
                if not stopped:
                    stopped = self.wait_for_exit(record.bot_id, generation.pid)
                kill_succeeded = stopped
        if not stopped:
            return StopEffect(
                "grace_expired",
                generation.pid,
                generation,
                "gateway did not stop before grace period expired",
                term_result=term_result,
                kill_result=kill_result,
                kill_attempted=kill_attempted,
                kill_succeeded=kill_succeeded,
            )
        if not remove_generation(record, generation):
            return StopEffect(
                "cleanup_unverified",
                generation.pid,
                generation,
                "stopped gateway marker cleanup could not be verified",
                term_result=term_result,
                kill_result=kill_result,
                kill_attempted=kill_attempted,
                kill_succeeded=kill_succeeded,
            )
        self._processes.pop(record.bot_id, None)
        return StopEffect(
            "stopped",
            generation.pid,
            generation,
            term_result=term_result,
            kill_result=kill_result,
            marker_removed=True,
            kill_attempted=kill_attempted,
            kill_succeeded=kill_succeeded,
        )

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

    def assert_unregistered_profile_inactive(self, bot_id: str, profile_path: Path) -> None:
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
        if self.pid_state(pid) is not process_identity.PidState.dead:
            raise BotRunningError(
                f"unregistered bot profile may still own gateway PID {pid}; refusing replacement"
            )

    def write_pid_marker(
        self,
        profile_path: str,
        pid: int,
        bot_id: str,
        argv: list[str],
        *,
        readiness_probe: ReadinessProbe | None,
        include_readiness_probe: bool,
    ) -> None:
        path = self.pid_marker_path(profile_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        resolved_hermes_bin = self.resolved_hermes_bin()
        marker_argv = list(argv)
        if resolved_hermes_bin:
            marker_argv[0] = resolved_hermes_bin
        fingerprint = self.proc_start_fingerprint_reader(pid)
        payload: dict[str, object] = {
            "schema": 2,
            "pid": pid,
            "bot_id": bot_id,
            "component": "gateway",
            "action": "run",
            "argv": marker_argv,
            "resolved_hermes_bin": resolved_hermes_bin,
            "started_at": time.time(),
        }
        if include_readiness_probe:
            payload["readiness_probe"] = readiness_probe_to_payload(readiness_probe)
        if fingerprint:
            payload["proc_start_fingerprint"] = fingerprint
        atomic_write_json(path, payload, mode=0o600)

    def remove_pid_marker(self, profile_path: str) -> None:
        try:
            self.pid_marker_path(profile_path).unlink()
        except FileNotFoundError:
            return

    def read_pid_marker(self, profile_path: str) -> dict[str, object]:
        safe_profile_path = nofollow_absolute_path(Path(profile_path))
        profile = None
        logs_fd = marker_fd = -1
        hooks = self._hooks()
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
                raw = hooks.read_bounded_file(marker_fd)
            except (LaunchPayloadError, OSError, TypeError, ValueError) as exc:
                try:
                    _validate_marker_bindings(profile, logs_fd, marker_fd, marker_stat)
                except (LaunchPayloadError, OSError, TypeError, ValueError) as binding_error:
                    raise UnsafeFileError(
                        "PID marker changed while it was inspected"
                    ) from binding_error
                return {"exists": True, "valid": False, "mode": marker_mode, "error": str(exc)}
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
                        hooks.close(descriptor)
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
                readiness = readiness_probe_from_payload(payload["readiness_probe"])
            except ValueError:
                safe_payload["readiness_probe"] = "invalid"
            else:
                safe_payload["readiness_probe"] = readiness_probe_to_payload(readiness)
        argv_value = payload.get("argv")
        if isinstance(argv_value, list) and all(isinstance(part, str) for part in argv_value):
            safe_payload["argv_shape"] = process_identity.safe_command_shape(argv_value)
        return safe_payload

    def verify_gateway_pid_ownership(
        self,
        profile_path: str,
        pid: int,
        bot_id: str,
        *,
        expected_record: BotRecord | None,
    ) -> OwnershipCheck:
        if expected_record is not None and expected_record.profile_path != profile_path:
            return OwnershipCheck(False, "marker-mismatch")
        observed = self.read_strict_runtime_marker(bot_id, profile_path)
        if observed.kind == "missing":
            return OwnershipCheck(False, "marker-missing")
        if observed.kind != "present" or observed.payload is None:
            return OwnershipCheck(False, "marker-mismatch")
        payload = observed.payload
        if payload.get("schema") == 3:
            if expected_record is None:
                return OwnershipCheck(False, "marker-mismatch")
            marker = self.classify_schema3_runtime_marker(
                expected_record,
                payload,
                expected_pid=pid,
                require_live_command=True,
            )
            if marker.kind != "live":
                return OwnershipCheck(False, marker.reason or "marker-mismatch")
            live_argv = self.cmdline_reader(pid)
            if not live_argv:
                return OwnershipCheck(False, "live-cmdline-missing")
            live_check = process_identity.verify_gateway_command(
                live_argv,
                bot_id,
                self.trusted_hermes_bins(),
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
        trusted_hermes = self.resolved_hermes_bin()
        if trusted_hermes is None:
            return OwnershipCheck(False, "untrusted-executable")
        marker_check = self.verify_marker_payload(payload, list(argv_value), bot_id)
        if not marker_check.verified:
            return OwnershipCheck(False, marker_check.reason, marker_check.classification)
        live_argv = self.cmdline_reader(pid)
        if not live_argv:
            return OwnershipCheck(False, "live-cmdline-missing")
        live_check = process_identity.verify_gateway_command(
            live_argv,
            bot_id,
            self.trusted_hermes_bins(),
            require_trusted_path=True,
        )
        if not live_check.verified:
            return OwnershipCheck(False, live_check.reason, live_check.classification)
        marker_schema = payload.get("schema")
        fingerprint = payload.get("proc_start_fingerprint")
        if marker_schema == 2:
            live_fingerprint = self.proc_start_fingerprint_reader(pid)
            if live_fingerprint and not (isinstance(fingerprint, str) and fingerprint):
                return OwnershipCheck(False, "pid-start-time-missing", live_check.classification)
            if isinstance(fingerprint, str) and fingerprint and live_fingerprint != fingerprint:
                return OwnershipCheck(False, "pid-start-time-mismatch", live_check.classification)
        elif isinstance(fingerprint, str) and fingerprint:
            live_fingerprint = self.proc_start_fingerprint_reader(pid)
            if live_fingerprint != fingerprint:
                return OwnershipCheck(False, "pid-start-time-mismatch", live_check.classification)
        classification = (
            "legacy-marker-valid"
            if marker_check.classification == "legacy-marker-valid"
            else live_check.classification
        )
        return OwnershipCheck(True, "ok", classification)

    def verify_marker_payload(
        self,
        payload: dict[str, object],
        argv: list[str],
        bot_id: str,
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
                or len(operation_id) != 32
                or any(character not in "0123456789abcdef" for character in operation_id)
                or type(revision) is not int
                or revision <= 0
                or type(fingerprint) is not str
            ):
                return OwnershipCheck(False, "marker-mismatch")
            if not is_owned_runtime_marker(
                payload,
                bot_id=bot_id,
                operation_id=operation_id,
                desired_revision=revision,
                pid=pid,
                expected_fingerprint=fingerprint,
            ):
                return OwnershipCheck(False, "marker-mismatch")
            resolved_hermes_bin = self.resolved_hermes_bin()
            marker_hermes = payload.get("resolved_hermes_bin")
            if (
                resolved_hermes_bin is None
                or type(marker_hermes) is not str
                or process_identity.resolve_executable(marker_hermes) != resolved_hermes_bin
            ):
                return OwnershipCheck(False, "untrusted-executable")
            marker_check = process_identity.verify_gateway_command(
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
            resolved_hermes_bin = self.resolved_hermes_bin()
            if not isinstance(payload.get("resolved_hermes_bin"), str):
                return OwnershipCheck(False, "untrusted-executable")
            marker_hermes = process_identity.resolve_executable(str(payload["resolved_hermes_bin"]))
            if marker_hermes != resolved_hermes_bin:
                return OwnershipCheck(False, "untrusted-executable")
            marker_check = process_identity.verify_gateway_command(
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
        if schema is not None:
            return OwnershipCheck(False, "marker-mismatch")
        if not self.allow_legacy_pid_markers:
            return OwnershipCheck(False, "legacy-marker-disabled")
        marker_check = process_identity.verify_gateway_command(
            argv,
            bot_id,
            None,
            require_trusted_path=False,
        )
        if not marker_check.verified:
            return OwnershipCheck(False, marker_check.reason, marker_check.classification)
        return OwnershipCheck(True, "ok", "legacy-marker-valid")

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

    def spawned_tree_stopped(self, process: PopenLike, *, timeout: float) -> bool:
        if not self.cleanup_process_group:
            return (
                process.poll() is not None
                or self.pid_state(process.pid) is process_identity.PidState.dead
            )
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
