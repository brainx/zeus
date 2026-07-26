"""Stateful Docker compatibility broker for the pinned audit terminal backend."""

from __future__ import annotations

import errno
import fcntl
import json
import math
import os
import re
import secrets
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import NoReturn, Protocol, TypeGuard

from zeus.audit_container import PreparedAuditContainer
from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.private_io import (
    UnsafeFileError,
    pin_private_directory,
    validate_private_directory,
)

HERMES_VERSION = "0.19.0"

_STATE_SCHEMA_VERSION = 1
_STATE_FILE_NAME = "state.json"
_LOCK_FILE_NAME = "state.lock"
_BROKER_FILE_NAME = "docker"
_STATE_LIMIT = 64 * 1024
_CONTROL_OUTPUT_LIMIT = 64 * 1024
_MAX_ARGV_ITEMS = 16
_MAX_ARGV_BYTES = 256 * 1024
_LOCK_WAIT_SECONDS = 1.0
_PROCESS_CHUNK = 64 * 1024
_MINIMAL_DOCKER_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
_CONTAINER_TEMP = "/t" + "mp"

_RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IMAGE_REF_RE = re.compile(r"[^\s\0]+@sha256:[0-9a-f]{64}\Z")
_SESSION_ID_RE = re.compile(r"[0-9a-f]{12}\Z")
_CLEANUP_OWNER_RE = re.compile(r"[0-9a-f]{32}\Z")
_PROFILE_RE = re.compile(r"audit-([0-9a-f]{32})\Z")
_CONTAINER_NAME_RE = re.compile(r"zeus-audit-([0-9a-f]{32})\Z")

_PHASES = frozenset(
    {
        "expect_version",
        "expect_cgroup_probe",
        "expect_image_or_info",
        "expect_image",
        "image_inflight",
        "expect_reuse",
        "expect_network",
        "network_inflight",
        "expect_bootstrap",
        "bootstrap_inflight",
        "terminal",
        "remove_inflight",
        "closed",
        "breached",
    }
)
_CLEANUP_STATES = frozenset({"not_requested", "requested", "running", "complete", "failed"})
_STATE_KEYS = frozenset(
    {
        "schema_version",
        "hermes_version",
        "docker_executable",
        "container_id",
        "container_name",
        "profile_name",
        "image_ref",
        "image_id",
        "container_labels",
        "hermes_labels",
        "phase",
        "deadline",
        "docker_control_seconds",
        "terminal_command_seconds",
        "terminal_call_limit",
        "per_call_reserved_output_bytes",
        "total_output_limit_bytes",
        "terminal_calls",
        "terminal_output_bytes",
        "aggregate_reserved_output_bytes",
        "active_terminal_calls",
        "bootstrap_complete",
        "session_id",
        "limit_breach",
        "breach_reason",
        "cleanup_state",
        "cleanup_owner",
        "cleanup_lease_deadline",
    }
)


class AuditDockerBrokerError(RuntimeError):
    """Raised when broker state or execution cannot be proven safe."""


class _DockerExecutionError(AuditDockerBrokerError):
    pass


@dataclass(frozen=True)
class BrokerCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class AuditDockerBrokerState:
    schema_version: int
    hermes_version: str
    docker_executable: str
    container_id: str
    container_name: str
    profile_name: str
    image_ref: str
    image_id: str
    container_labels: dict[str, str]
    hermes_labels: dict[str, str]
    phase: str
    deadline: float
    docker_control_seconds: int
    terminal_command_seconds: int
    terminal_call_limit: int
    per_call_reserved_output_bytes: int
    total_output_limit_bytes: int
    terminal_calls: int
    terminal_output_bytes: int
    aggregate_reserved_output_bytes: int
    active_terminal_calls: int
    bootstrap_complete: bool
    session_id: str | None
    limit_breach: bool
    breach_reason: str | None
    cleanup_state: str
    cleanup_owner: str | None
    cleanup_lease_deadline: float | None


class DockerExecutionRunner(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult: ...


@dataclass(frozen=True)
class _Decision:
    kind: str
    state: AuditDockerBrokerState
    stdout: bytes = b""
    session_id: str | None = None


@dataclass(frozen=True)
class _LockedStateDirectory:
    fd: int
    state_path: Path


def _error(message: str) -> NoReturn:
    raise AuditDockerBrokerError(message)


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _validate_private_control_file(
    result: os.stat_result,
    *,
    expected_mode: int,
    expected_size: int | None = None,
) -> None:
    if (
        not stat.S_ISREG(result.st_mode)
        or stat.S_IMODE(result.st_mode) != expected_mode
        or result.st_uid != os.geteuid()
        or result.st_nlink != 1
        or (expected_size is not None and result.st_size != expected_size)
    ):
        _error("audit Docker broker file metadata is unsafe")


def _validate_executable(path: Path, description: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _error(f"{description} must be an absolute pathlib.Path")
    try:
        result = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AuditDockerBrokerError(f"{description} is unavailable") from exc
    if (
        not stat.S_ISREG(result.st_mode)
        or resolved != path
        or result.st_uid not in {0, os.geteuid()}
        or result.st_mode & stat.S_IXUSR == 0
        or result.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _error(f"{description} is not a resolved regular executable")
    return path


def _validate_limits(limits: AuditLimits) -> None:
    bounded_fields = (
        "overall_seconds",
        "docker_control_seconds",
        "terminal_command_seconds",
        "terminal_calls",
        "terminal_output_per_call_bytes",
        "terminal_output_total_bytes",
    )
    for field in bounded_fields:
        value = getattr(limits, field)
        maximum = getattr(HARD_LIMITS, field)
        if not _is_int(value) or not 1 <= value <= maximum:
            _error(f"audit Docker broker {field} is outside its hard limit")
    if limits.terminal_output_per_call_bytes > limits.terminal_output_total_bytes:
        _error("audit Docker broker per-call output exceeds its aggregate output limit")


def _validate_prepared(prepared: PreparedAuditContainer) -> str:
    if _CONTAINER_ID_RE.fullmatch(prepared.container_id) is None:
        _error("audit Docker broker container ID is invalid")
    if _IMAGE_ID_RE.fullmatch(prepared.image_id) is None:
        _error("audit Docker broker image ID is invalid")
    if _IMAGE_REF_RE.fullmatch(prepared.image_ref) is None:
        _error("audit Docker broker image reference is invalid")
    name_match = _CONTAINER_NAME_RE.fullmatch(prepared.container_name)
    profile_match = _PROFILE_RE.fullmatch(prepared.profile_name)
    if name_match is None or profile_match is None:
        _error("audit Docker broker run identity is invalid")
    run_id = name_match.group(1)
    if profile_match.group(1) != run_id:
        _error("audit Docker broker run identity is inconsistent")
    if not isinstance(prepared.broker_dir, Path) or not prepared.broker_dir.is_absolute():
        _error("audit Docker broker directory must be absolute")
    if (
        not isinstance(prepared.state_path, Path)
        or not prepared.state_path.is_absolute()
        or prepared.state_path.parent != prepared.broker_dir
        or prepared.state_path.name != _STATE_FILE_NAME
    ):
        _error("audit Docker broker state path is invalid")
    try:
        directory_result = prepared.broker_dir.lstat()
        if (
            not stat.S_ISDIR(directory_result.st_mode)
            or stat.S_IMODE(directory_result.st_mode) != 0o700
            or directory_result.st_uid != os.geteuid()
        ):
            _error("audit Docker broker directory is unsafe")
        validate_private_directory(prepared.broker_dir)
    except AuditDockerBrokerError:
        raise
    except (OSError, TypeError, ValueError, UnsafeFileError) as exc:
        raise AuditDockerBrokerError("audit Docker broker directory is unsafe") from exc
    return run_id


def _validate_deadline(deadline: float, limits: AuditLimits, now: float) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        _error("audit Docker broker deadline must be finite")
    value = float(deadline)
    if value <= now or value - now > limits.overall_seconds:
        _error("audit Docker broker deadline is outside its hard limit")
    return value


def _state_bytes(state: AuditDockerBrokerState) -> bytes:
    data = (
        json.dumps(
            asdict(state),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if len(data) > _STATE_LIMIT:
        _error("audit Docker broker state exceeds its byte limit")
    return data


def _strict_dict(value: object, description: str) -> dict[str, str]:
    if not isinstance(value, dict):
        _error(f"audit Docker broker {description} is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            _error(f"audit Docker broker {description} is invalid")
        result[key] = item
    return result


def _strict_positive_int(value: object, description: str, maximum: int) -> int:
    if not _is_int(value) or not 1 <= value <= maximum:
        _error(f"audit Docker broker {description} is invalid")
    return value


def _strict_nonnegative_int(value: object, description: str, maximum: int) -> int:
    if not _is_int(value) or not 0 <= value <= maximum:
        _error(f"audit Docker broker {description} is invalid")
    return value


def _decode_state(data: bytes) -> AuditDockerBrokerState:
    try:
        value = json.loads(data.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditDockerBrokerError("audit Docker broker state is invalid") from exc
    if not isinstance(value, dict) or frozenset(value) != _STATE_KEYS:
        _error("audit Docker broker state schema is invalid")

    schema_version = value["schema_version"]
    hermes_version = value["hermes_version"]
    docker_executable = value["docker_executable"]
    container_id = value["container_id"]
    container_name = value["container_name"]
    profile_name = value["profile_name"]
    image_ref = value["image_ref"]
    image_id = value["image_id"]
    phase = value["phase"]
    deadline = value["deadline"]
    bootstrap_complete = value["bootstrap_complete"]
    session_id = value["session_id"]
    limit_breach = value["limit_breach"]
    breach_reason = value["breach_reason"]
    cleanup_state = value["cleanup_state"]
    cleanup_owner = value["cleanup_owner"]
    cleanup_lease_deadline = value["cleanup_lease_deadline"]

    if schema_version != _STATE_SCHEMA_VERSION or hermes_version != HERMES_VERSION:
        _error("audit Docker broker state version is unsupported")
    if (
        not isinstance(docker_executable, str)
        or not Path(docker_executable).is_absolute()
        or _CONTAINER_ID_RE.fullmatch(container_id if isinstance(container_id, str) else "") is None
        or _CONTAINER_NAME_RE.fullmatch(container_name if isinstance(container_name, str) else "")
        is None
        or _PROFILE_RE.fullmatch(profile_name if isinstance(profile_name, str) else "") is None
        or _IMAGE_REF_RE.fullmatch(image_ref if isinstance(image_ref, str) else "") is None
        or _IMAGE_ID_RE.fullmatch(image_id if isinstance(image_id, str) else "") is None
    ):
        _error("audit Docker broker sealed identity is invalid")
    name_match = _CONTAINER_NAME_RE.fullmatch(container_name)
    profile_match = _PROFILE_RE.fullmatch(profile_name)
    if name_match is None or profile_match is None or name_match.group(1) != profile_match.group(1):
        _error("audit Docker broker sealed run identity is inconsistent")
    run_id = name_match.group(1)
    expected_container_labels = {
        "com.zeus.audit": "true",
        "com.zeus.audit.run-id": run_id,
        "com.zeus.audit.profile": profile_name,
    }
    expected_hermes_labels = {
        "hermes-agent": "1",
        "hermes-task-id": "default",
        "hermes-profile": profile_name,
    }
    container_labels = _strict_dict(value["container_labels"], "container labels")
    hermes_labels = _strict_dict(value["hermes_labels"], "terminal labels")
    if container_labels != expected_container_labels or hermes_labels != expected_hermes_labels:
        _error("audit Docker broker sealed labels are invalid")
    if not isinstance(phase, str) or phase not in _PHASES:
        _error("audit Docker broker protocol phase is invalid")
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        _error("audit Docker broker deadline is invalid")

    docker_control_seconds = _strict_positive_int(
        value["docker_control_seconds"],
        "Docker control limit",
        HARD_LIMITS.docker_control_seconds,
    )
    terminal_command_seconds = _strict_positive_int(
        value["terminal_command_seconds"],
        "terminal command limit",
        HARD_LIMITS.terminal_command_seconds,
    )
    terminal_call_limit = _strict_positive_int(
        value["terminal_call_limit"],
        "terminal call limit",
        HARD_LIMITS.terminal_calls,
    )
    per_call = _strict_positive_int(
        value["per_call_reserved_output_bytes"],
        "per-call output reservation",
        HARD_LIMITS.terminal_output_per_call_bytes,
    )
    total_limit = _strict_positive_int(
        value["total_output_limit_bytes"],
        "aggregate output limit",
        HARD_LIMITS.terminal_output_total_bytes,
    )
    if per_call > total_limit:
        _error("audit Docker broker output reservations are inconsistent")
    terminal_calls = _strict_nonnegative_int(
        value["terminal_calls"], "terminal call count", terminal_call_limit
    )
    terminal_output = _strict_nonnegative_int(
        value["terminal_output_bytes"], "terminal output ledger", total_limit
    )
    reserved = _strict_nonnegative_int(
        value["aggregate_reserved_output_bytes"],
        "aggregate output reservation",
        total_limit,
    )
    active = _strict_nonnegative_int(
        value["active_terminal_calls"], "active terminal count", terminal_call_limit
    )
    if active * per_call != reserved or terminal_output + reserved > total_limit:
        _error("audit Docker broker output ledger is inconsistent")
    if not isinstance(bootstrap_complete, bool) or not isinstance(limit_breach, bool):
        _error("audit Docker broker state flags are invalid")
    if session_id is not None and (
        not isinstance(session_id, str) or _SESSION_ID_RE.fullmatch(session_id) is None
    ):
        _error("audit Docker broker session seal is invalid")
    if bootstrap_complete != (session_id is not None):
        _error("audit Docker broker bootstrap state is inconsistent")
    if breach_reason is not None and (
        not isinstance(breach_reason, str) or not 1 <= len(breach_reason) <= 64
    ):
        _error("audit Docker broker breach record is invalid")
    if limit_breach != (phase == "breached") or limit_breach != (breach_reason is not None):
        _error("audit Docker broker breach state is inconsistent")
    if not isinstance(cleanup_state, str) or cleanup_state not in _CLEANUP_STATES:
        _error("audit Docker broker cleanup state is invalid")
    if cleanup_state == "running":
        if (
            not isinstance(cleanup_owner, str)
            or _CLEANUP_OWNER_RE.fullmatch(cleanup_owner) is None
            or isinstance(cleanup_lease_deadline, bool)
            or not isinstance(cleanup_lease_deadline, (int, float))
            or not math.isfinite(cleanup_lease_deadline)
            or cleanup_lease_deadline <= 0
        ):
            _error("audit Docker broker cleanup lease is invalid")
    elif cleanup_owner is not None or cleanup_lease_deadline is not None:
        _error("audit Docker broker cleanup lease is inconsistent")
    if phase == "remove_inflight" and cleanup_state != "running":
        _error("audit Docker broker removal state is inconsistent")
    if phase == "closed" and cleanup_state != "complete":
        _error("audit Docker broker closed state is inconsistent")

    return AuditDockerBrokerState(
        schema_version=_STATE_SCHEMA_VERSION,
        hermes_version=HERMES_VERSION,
        docker_executable=docker_executable,
        container_id=container_id,
        container_name=container_name,
        profile_name=profile_name,
        image_ref=image_ref,
        image_id=image_id,
        container_labels=container_labels,
        hermes_labels=hermes_labels,
        phase=phase,
        deadline=float(deadline),
        docker_control_seconds=docker_control_seconds,
        terminal_command_seconds=terminal_command_seconds,
        terminal_call_limit=terminal_call_limit,
        per_call_reserved_output_bytes=per_call,
        total_output_limit_bytes=total_limit,
        terminal_calls=terminal_calls,
        terminal_output_bytes=terminal_output,
        aggregate_reserved_output_bytes=reserved,
        active_terminal_calls=active,
        bootstrap_complete=bootstrap_complete,
        session_id=session_id,
        limit_breach=limit_breach,
        breach_reason=breach_reason,
        cleanup_state=cleanup_state,
        cleanup_owner=cleanup_owner,
        cleanup_lease_deadline=(
            float(cleanup_lease_deadline) if cleanup_lease_deadline is not None else None
        ),
    )


def _lstat_at(directory_fd: int, name: str) -> os.stat_result:
    try:
        return os.lstat(name, dir_fd=directory_fd)
    except OSError as exc:
        raise AuditDockerBrokerError("audit Docker broker file is unavailable") from exc


def _open_lock_at(directory_fd: int) -> int:
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(_LOCK_FILE_NAME, flags, 0o600, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        installed = _lstat_at(directory_fd, _LOCK_FILE_NAME)
        _validate_private_control_file(opened, expected_mode=0o600)
        if not _same_file(opened, installed):
            _error("audit Docker broker lock binding changed")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            with suppress(OSError):
                os.close(descriptor)
        raise


def _acquire_lock(descriptor: int, deadline: float) -> None:
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                raise AuditDockerBrokerError(
                    "audit Docker broker lock could not be acquired"
                ) from exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _error("audit Docker broker lock acquisition timed out")
            time.sleep(min(0.01, remaining))


@contextmanager
def _locked_state(state_path: Path) -> Iterator[_LockedStateDirectory]:
    if (
        not isinstance(state_path, Path)
        or not state_path.is_absolute()
        or state_path.name != _STATE_FILE_NAME
    ):
        _error("audit Docker broker state path is invalid")
    broker_dir = state_path.parent
    try:
        with pin_private_directory(broker_dir) as pinned:
            lock_descriptor = -1
            lock_deadline = time.monotonic() + _LOCK_WAIT_SECONDS
            try:
                _acquire_lock(pinned.fd, lock_deadline)
                lock_descriptor = _open_lock_at(pinned.fd)
                _acquire_lock(lock_descriptor, lock_deadline)
                pinned.validate_at(broker_dir)
                lock_identity = os.fstat(lock_descriptor)
                if not _same_file(
                    lock_identity,
                    _lstat_at(pinned.fd, _LOCK_FILE_NAME),
                ):
                    _error("audit Docker broker lock binding changed")
                yield _LockedStateDirectory(fd=pinned.fd, state_path=state_path)
                if not _same_file(
                    lock_identity,
                    _lstat_at(pinned.fd, _LOCK_FILE_NAME),
                ):
                    _error("audit Docker broker lock binding changed")
                pinned.validate_at(broker_dir)
            finally:
                if lock_descriptor >= 0:
                    with suppress(OSError):
                        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
                    with suppress(OSError):
                        os.close(lock_descriptor)
                with suppress(OSError):
                    fcntl.flock(pinned.fd, fcntl.LOCK_UN)
    except AuditDockerBrokerError:
        raise
    except (OSError, TypeError, ValueError, UnsafeFileError) as exc:
        raise AuditDockerBrokerError("audit Docker broker lock is unavailable") from exc


def _read_control_file_at(
    locked: _LockedStateDirectory,
    name: str,
    *,
    missing_ok: bool = False,
) -> bytes | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=locked.fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        _error("audit Docker broker state is unavailable")
    except OSError as exc:
        raise AuditDockerBrokerError("audit Docker broker state is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        _validate_private_control_file(before, expected_mode=0o600)
        if before.st_size > _STATE_LIMIT:
            _error("audit Docker broker state exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(_PROCESS_CHUNK, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        installed = _lstat_at(locked.fd, name)
        if (
            not _same_file(before, after)
            or not _same_file(after, installed)
            or after.st_size != before.st_size
            or remaining != 0
        ):
            _error("audit Docker broker state binding changed")
        return b"".join(chunks)
    except AuditDockerBrokerError:
        raise
    except OSError as exc:
        raise AuditDockerBrokerError("audit Docker broker state could not be read") from exc
    finally:
        with suppress(OSError):
            os.close(descriptor)


def _write_control_file_at(
    locked: _LockedStateDirectory,
    name: str,
    data: bytes,
    *,
    mode: int,
    replace_existing: bool,
) -> None:
    if len(data) > _STATE_LIMIT:
        _error("audit Docker broker file exceeds its byte limit")
    temporary = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    temporary_exists = False
    try:
        descriptor = os.open(temporary, flags, mode, dir_fd=locked.fd)
        temporary_exists = True
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                _error("audit Docker broker file write made no progress")
            written += count
        os.fsync(descriptor)
        created = os.fstat(descriptor)
        _validate_private_control_file(
            created,
            expected_mode=mode,
            expected_size=len(data),
        )
        os.close(descriptor)
        descriptor = -1
        if replace_existing:
            os.replace(
                temporary,
                name,
                src_dir_fd=locked.fd,
                dst_dir_fd=locked.fd,
            )
            temporary_exists = False
        else:
            os.link(
                temporary,
                name,
                src_dir_fd=locked.fd,
                dst_dir_fd=locked.fd,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=locked.fd)
            temporary_exists = False
        os.fsync(locked.fd)
        installed = _lstat_at(locked.fd, name)
        _validate_private_control_file(
            installed,
            expected_mode=mode,
            expected_size=len(data),
        )
    except AuditDockerBrokerError:
        raise
    except OSError as exc:
        raise AuditDockerBrokerError("audit Docker broker file could not be updated") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_exists:
            with suppress(OSError):
                os.unlink(temporary, dir_fd=locked.fd)


def _read_state_unlocked(locked: _LockedStateDirectory) -> AuditDockerBrokerState:
    data = _read_control_file_at(locked, _STATE_FILE_NAME)
    if data is None:
        _error("audit Docker broker state is unavailable")
    return _decode_state(data)


def _write_state_unlocked(
    locked: _LockedStateDirectory,
    state: AuditDockerBrokerState,
) -> None:
    _write_control_file_at(
        locked,
        _STATE_FILE_NAME,
        _state_bytes(state),
        mode=0o600,
        replace_existing=True,
    )


def read_audit_docker_broker_state(state_path: Path) -> AuditDockerBrokerState:
    with _locked_state(state_path) as locked:
        return _read_state_unlocked(locked)


def _wrapper_bytes(python_executable: Path) -> bytes:
    executable = str(python_executable)
    if any(character in executable for character in ("\n", "\r")):
        _error("audit Docker broker Python executable is invalid")
    try:
        return (
            f"#!{executable}\n"
            "from zeus.audit_docker_broker_main import main\n"
            "raise SystemExit(main())\n"
        ).encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise AuditDockerBrokerError("audit Docker broker Python executable is invalid") from exc


def install_audit_docker_broker(
    prepared: PreparedAuditContainer,
    *,
    docker_executable: Path,
    limits: AuditLimits,
    deadline: float,
    python_executable: Path,
) -> Path:
    run_id = _validate_prepared(prepared)
    _validate_limits(limits)
    docker = _validate_executable(docker_executable, "Docker executable")
    python = _validate_executable(python_executable, "Python executable")
    now = time.monotonic()
    sealed_deadline = _validate_deadline(deadline, limits, now)
    broker_executable = prepared.broker_dir / _BROKER_FILE_NAME
    state = AuditDockerBrokerState(
        schema_version=_STATE_SCHEMA_VERSION,
        hermes_version=HERMES_VERSION,
        docker_executable=str(docker),
        container_id=prepared.container_id,
        container_name=prepared.container_name,
        profile_name=prepared.profile_name,
        image_ref=prepared.image_ref,
        image_id=prepared.image_id,
        container_labels={
            "com.zeus.audit": "true",
            "com.zeus.audit.run-id": run_id,
            "com.zeus.audit.profile": prepared.profile_name,
        },
        hermes_labels={
            "hermes-agent": "1",
            "hermes-task-id": "default",
            "hermes-profile": prepared.profile_name,
        },
        phase="expect_version",
        deadline=sealed_deadline,
        docker_control_seconds=limits.docker_control_seconds,
        terminal_command_seconds=limits.terminal_command_seconds,
        terminal_call_limit=limits.terminal_calls,
        per_call_reserved_output_bytes=limits.terminal_output_per_call_bytes,
        total_output_limit_bytes=limits.terminal_output_total_bytes,
        terminal_calls=0,
        terminal_output_bytes=0,
        aggregate_reserved_output_bytes=0,
        active_terminal_calls=0,
        bootstrap_complete=False,
        session_id=None,
        limit_breach=False,
        breach_reason=None,
        cleanup_state="not_requested",
        cleanup_owner=None,
        cleanup_lease_deadline=None,
    )
    with _locked_state(prepared.state_path) as locked:
        existing_state = _read_control_file_at(
            locked,
            _STATE_FILE_NAME,
            missing_ok=True,
        )
        try:
            os.lstat(_BROKER_FILE_NAME, dir_fd=locked.fd)
        except FileNotFoundError:
            broker_exists = False
        except OSError as exc:
            raise AuditDockerBrokerError(
                "audit Docker broker executable could not be inspected"
            ) from exc
        else:
            broker_exists = True
        if existing_state is not None or broker_exists:
            _error("audit Docker broker is already installed")
        _write_control_file_at(
            locked,
            _BROKER_FILE_NAME,
            _wrapper_bytes(python),
            mode=0o500,
            replace_existing=False,
        )
        _write_control_file_at(
            locked,
            _STATE_FILE_NAME,
            _state_bytes(state),
            mode=0o600,
            replace_existing=False,
        )
    return broker_executable
