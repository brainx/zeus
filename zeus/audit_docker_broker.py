"""Stateful Docker compatibility broker for the pinned audit terminal backend."""

from __future__ import annotations

import errno
import fcntl
import json
import math
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess  # nosec B404
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import BinaryIO, NoReturn, Protocol, TypeGuard, cast

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


def _expected_bootstrap_script(session_id: str) -> str:
    snapshot = f"{_CONTAINER_TEMP}/hermes-snap-{session_id}.sh"
    temporary = f"{snapshot}.tmp.$BASHPID"
    marker = f"__HERMES_CWD_{session_id}__"
    return (
        "umask 077\n"
        f"export -p > {temporary}\n"
        "__hermes_fns=$(declare -F | awk '{print $3}' | grep -vE '^_[^_]') || true\n"
        f'[ -n "$__hermes_fns" ] && declare -f $__hermes_fns >> {temporary} '
        "2>/dev/null || true\n"
        f"alias -p >> {temporary}\n"
        f"echo 'shopt -s expand_aliases' >> {temporary}\n"
        f"echo 'set +e' >> {temporary}\n"
        f"echo 'set +u' >> {temporary}\n"
        f"mv -f {temporary} {snapshot} || rm -f {temporary}\n"
        "builtin cd -- /workspace 2>/dev/null || true\n"
        f"""printf '\\n{marker}%s{marker}\\n' "$(pwd -P)"\n"""
    )


def _bootstrap_session_id(script: str) -> str | None:
    prefix = "export -p > /tmp/hermes-snap-"
    start = script.find(prefix)
    if start < 0:
        return None
    identifier_start = start + len(prefix)
    session_id = script[identifier_start : identifier_start + 12]
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        return None
    if script != _expected_bootstrap_script(session_id):
        return None
    return session_id


def _expected_cgroup_probe(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "run",
        "--rm",
        "--cpus",
        "0.5",
        "--memory",
        "64m",
        "--pids-limit",
        "32",
        state.image_ref,
        "sleep",
        "0",
    )


def _expected_image_inspect(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "image",
        "inspect",
        state.image_ref,
        "--format",
        "{{json .Config.Entrypoint}}",
    )


def _expected_reuse_probe(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "ps",
        "-a",
        "--filter",
        "label=hermes-agent=1",
        "--filter",
        "label=hermes-task-id=default",
        "--filter",
        f"label=hermes-profile={state.profile_name}",
        "--format",
        "{{.ID}}\t{{.State}}",
    )


def _expected_network_inspect(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "inspect",
        "--format",
        "{{.HostConfig.NetworkMode}}",
        state.container_id,
    )


def _expected_removal(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return ("rm", "-f", state.container_id)


def _arguments_are_bounded(arguments: tuple[str, ...]) -> bool:
    if not isinstance(arguments, tuple) or not 1 <= len(arguments) <= _MAX_ARGV_ITEMS:
        return False
    total = 0
    for argument in arguments:
        if not isinstance(argument, str) or "\0" in argument:
            return False
        try:
            total += len(argument.encode("utf-8", errors="strict")) + 1
        except UnicodeEncodeError:
            return False
        if total > _MAX_ARGV_BYTES:
            return False
    return True


def _breached(state: AuditDockerBrokerState, reason: str) -> AuditDockerBrokerState:
    cleanup_state = (
        state.cleanup_state if state.cleanup_state in {"running", "complete"} else "requested"
    )
    return replace(
        state,
        phase="breached",
        limit_breach=True,
        breach_reason=reason,
        cleanup_state=cleanup_state,
        cleanup_owner=(state.cleanup_owner if cleanup_state == "running" else None),
        cleanup_lease_deadline=(
            state.cleanup_lease_deadline if cleanup_state == "running" else None
        ),
    )


def _claim_cleanup(
    state: AuditDockerBrokerState,
    now: float,
) -> AuditDockerBrokerState:
    return replace(
        state,
        cleanup_state="running",
        cleanup_owner=secrets.token_hex(16),
        cleanup_lease_deadline=now + state.docker_control_seconds,
    )


def _decide(
    state: AuditDockerBrokerState,
    arguments: tuple[str, ...],
    now: float,
) -> _Decision:
    if state.phase in {"closed", "breached"}:
        return _Decision("refuse", state)
    if state.cleanup_state == "running":
        return _Decision("refuse", state)
    if now >= state.deadline:
        return _Decision("breach", _breached(state, "overall deadline"))
    if not _arguments_are_bounded(arguments):
        return _Decision("breach", _breached(state, "invalid argv"))

    if state.phase == "expect_version" and arguments == ("version",):
        return _Decision("emulated", replace(state, phase="expect_cgroup_probe"))
    if state.phase == "expect_cgroup_probe" and arguments == _expected_cgroup_probe(state):
        return _Decision("emulated", replace(state, phase="expect_image_or_info"))
    if state.phase == "expect_image_or_info":
        if arguments == ("info", "--format", "{{.Driver}}"):
            return _Decision("emulated", replace(state, phase="expect_image"), b"vfs\n")
        if arguments == _expected_image_inspect(state):
            return _Decision("image", replace(state, phase="image_inflight"))
    elif state.phase == "expect_image" and arguments == _expected_image_inspect(state):
        return _Decision("image", replace(state, phase="image_inflight"))
    elif state.phase == "expect_reuse" and arguments == _expected_reuse_probe(state):
        output = f"{state.container_id}\trunning\n".encode("ascii")
        return _Decision("emulated", replace(state, phase="expect_network"), output)
    elif state.phase == "expect_network" and arguments == _expected_network_inspect(state):
        return _Decision("network", replace(state, phase="network_inflight"))
    elif (
        state.phase == "expect_bootstrap"
        and len(arguments) == 6
        and arguments[:5] == ("exec", state.container_id, "bash", "-l", "-c")
    ):
        session_id = _bootstrap_session_id(arguments[5])
        if session_id is not None:
            return _Decision(
                "bootstrap",
                replace(state, phase="bootstrap_inflight"),
                session_id=session_id,
            )
    elif state.phase == "terminal":
        if arguments == _expected_removal(state):
            return _Decision(
                "remove",
                _claim_cleanup(replace(state, phase="remove_inflight"), now),
            )
        if len(arguments) == 5 and arguments[:4] == ("exec", state.container_id, "bash", "-c"):
            if state.terminal_calls >= state.terminal_call_limit:
                return _Decision("breach", _breached(state, "terminal call limit"))
            reservation = state.per_call_reserved_output_bytes
            if (
                state.terminal_output_bytes + state.aggregate_reserved_output_bytes + reservation
                > state.total_output_limit_bytes
            ):
                return _Decision("breach", _breached(state, "terminal output limit"))
            updated = replace(
                state,
                terminal_calls=state.terminal_calls + 1,
                aggregate_reserved_output_bytes=(
                    state.aggregate_reserved_output_bytes + reservation
                ),
                active_terminal_calls=state.active_terminal_calls + 1,
            )
            return _Decision("terminal", updated)
    return _Decision("breach", _breached(state, "protocol drift"))


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    group_id = process.pid
    with suppress(OSError):
        os.killpg(group_id, signal.SIGTERM)
    term_deadline = time.monotonic() + 0.2
    while time.monotonic() < term_deadline:
        try:
            os.killpg(group_id, 0)
        except (ProcessLookupError, OSError):
            break
        time.sleep(0.01)
    with suppress(OSError):
        os.killpg(group_id, signal.SIGKILL)
    if process.poll() is None:
        with suppress(OSError):
            process.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=1)


class _SubprocessDockerExecutionRunner:
    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        try:
            process = subprocess.Popen(  # nosec B603
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            raise _DockerExecutionError("Docker execution could not be started") from exc
        if process.stdout is None or process.stderr is None:
            _stop_process(process)
            raise _DockerExecutionError("Docker execution pipes are unavailable")
        selector = selectors.DefaultSelector()
        output: dict[object, bytearray] = {
            process.stdout: bytearray(),
            process.stderr: bytearray(),
        }
        total = 0
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _stop_process(process)
                    raise _DockerExecutionError("Docker execution exceeded its deadline")
                events = selector.select(remaining)
                if not events:
                    _stop_process(process)
                    raise _DockerExecutionError("Docker execution exceeded its deadline")
                for key, _mask in events:
                    stream = cast(BinaryIO, key.fileobj)
                    try:
                        chunk = os.read(key.fd, _PROCESS_CHUNK)
                    except OSError as exc:
                        _stop_process(process)
                        raise _DockerExecutionError(
                            "Docker execution output could not be read"
                        ) from exc
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > output_limit:
                        _stop_process(process)
                        raise _DockerExecutionError(
                            "Docker execution output exceeded its byte limit"
                        )
                    output[stream].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise _DockerExecutionError("Docker execution exceeded its deadline")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                _stop_process(process)
                raise _DockerExecutionError("Docker execution exceeded its deadline") from exc
            return BrokerCommandResult(
                returncode=returncode,
                stdout=bytes(output[process.stdout]),
                stderr=bytes(output[process.stderr]),
            )
        finally:
            selector.close()
            for close_stream in (process.stdout, process.stderr):
                with suppress(OSError):
                    close_stream.close()
            if process.poll() is None:
                _stop_process(process)


def _command_deadline(state: AuditDockerBrokerState, kind: str, now: float) -> float:
    seconds = (
        state.terminal_command_seconds
        if kind in {"bootstrap", "terminal"}
        else state.docker_control_seconds
    )
    deadline = min(state.deadline, now + seconds)
    if deadline <= now:
        raise _DockerExecutionError("Docker execution deadline has expired")
    return deadline


def _valid_image_entrypoint(result: BrokerCommandResult) -> bool:
    if result.returncode != 0 or result.stderr or len(result.stdout) > _CONTROL_OUTPUT_LIMIT:
        return False
    if not result.stdout.endswith(b"\n") or result.stdout.count(b"\n") != 1:
        return False
    try:
        value = json.loads(result.stdout[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        value is None
        or isinstance(value, str)
        or (isinstance(value, list) and all(isinstance(item, str) for item in value))
    )


def _valid_network(result: BrokerCommandResult) -> bool:
    return result.returncode == 0 and result.stdout == b"none\n" and not result.stderr


def _valid_removal(result: BrokerCommandResult, container_id: str) -> bool:
    return (
        result.returncode == 0
        and result.stdout == f"{container_id}\n".encode("ascii")
        and not result.stderr
    )


def _complete_control(
    state_path: Path,
    decision: _Decision,
) -> AuditDockerBrokerState:
    expected_phase = {
        "image": "image_inflight",
        "network": "network_inflight",
        "bootstrap": "bootstrap_inflight",
        "remove": "remove_inflight",
    }[decision.kind]
    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        if current.limit_breach:
            return current
        if decision.kind == "remove" and current.cleanup_state == "complete":
            return current
        cleanup_owner_changed = (
            decision.kind == "remove" and current.cleanup_owner != decision.state.cleanup_owner
        )
        if current.phase != expected_phase or cleanup_owner_changed:
            updated = _breached(current, "protocol state drift")
        elif decision.kind == "image":
            updated = replace(current, phase="expect_reuse")
        elif decision.kind == "network":
            updated = replace(current, phase="expect_bootstrap")
        elif decision.kind == "bootstrap":
            if decision.session_id is None:
                updated = _breached(current, "bootstrap state drift")
            else:
                updated = replace(
                    current,
                    phase="terminal",
                    bootstrap_complete=True,
                    session_id=decision.session_id,
                )
        else:
            updated = replace(
                current,
                phase="closed",
                cleanup_state="complete",
                cleanup_owner=None,
                cleanup_lease_deadline=None,
            )
        _write_state_unlocked(locked, updated)
        return updated


def _breach_control(
    current: AuditDockerBrokerState,
    decision: _Decision,
    reason: str,
) -> AuditDockerBrokerState:
    if (
        decision.kind == "remove"
        and current.cleanup_state == "running"
        and current.cleanup_owner == decision.state.cleanup_owner
    ):
        current = replace(
            current,
            cleanup_state="requested",
            cleanup_owner=None,
            cleanup_lease_deadline=None,
        )
    return _breached(current, reason)


def _release_terminal_reservation(
    state_path: Path,
    *,
    output_bytes: int | None,
    breach_reason: str | None,
) -> AuditDockerBrokerState:
    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        reservation = current.per_call_reserved_output_bytes
        if (
            current.active_terminal_calls < 1
            or current.aggregate_reserved_output_bytes < reservation
        ):
            _error("audit Docker broker reservation ledger is invalid")
        updated = replace(
            current,
            aggregate_reserved_output_bytes=(current.aggregate_reserved_output_bytes - reservation),
            active_terminal_calls=current.active_terminal_calls - 1,
        )
        if breach_reason is not None:
            updated = _breached(updated, breach_reason)
        elif not updated.limit_breach and output_bytes is not None:
            if (
                output_bytes > updated.per_call_reserved_output_bytes
                or updated.terminal_output_bytes + output_bytes > updated.total_output_limit_bytes
            ):
                updated = _breached(updated, "terminal output limit")
            else:
                updated = replace(
                    updated,
                    terminal_output_bytes=updated.terminal_output_bytes + output_bytes,
                )
        _write_state_unlocked(locked, updated)
        return updated


def _perform_cleanup(
    state_path: Path,
    *,
    runner: DockerExecutionRunner,
    clock: Callable[[], float],
    close_on_success: bool,
) -> BrokerCommandResult:
    with _locked_state(state_path) as locked:
        state = _read_state_unlocked(locked)
        now = clock()
        if state.cleanup_state == "complete":
            return BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
        if state.cleanup_state == "running":
            if state.cleanup_lease_deadline is None or now < state.cleanup_lease_deadline:
                return BrokerCommandResult(
                    returncode=126,
                    stdout=b"",
                    stderr=b"audit Docker broker cleanup is already running\n",
                )
        elif (
            state.phase
            in {
                "image_inflight",
                "network_inflight",
                "bootstrap_inflight",
            }
            or state.active_terminal_calls
        ):
            if now < state.deadline:
                return BrokerCommandResult(
                    returncode=126,
                    stdout=b"",
                    stderr=b"audit Docker broker execution is still running\n",
                )
            state = _breached(
                replace(
                    state,
                    active_terminal_calls=0,
                    aggregate_reserved_output_bytes=0,
                ),
                "orphaned execution",
            )
        claimed = _claim_cleanup(state, now)
        _write_state_unlocked(locked, claimed)
    cleanup_owner = claimed.cleanup_owner
    cleanup_deadline = claimed.cleanup_lease_deadline
    if cleanup_owner is None or cleanup_deadline is None:
        _error("audit Docker broker cleanup claim is invalid")
    try:
        result = runner.run(
            (claimed.docker_executable, *_expected_removal(claimed)),
            deadline=cleanup_deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
        successful = _valid_removal(result, claimed.container_id)
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        result = BrokerCommandResult(returncode=126, stdout=b"", stderr=b"")
        successful = False
    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        if current.cleanup_state == "complete":
            cleanup_succeeded = True
        elif current.cleanup_state != "running" or current.cleanup_owner != cleanup_owner:
            return BrokerCommandResult(
                returncode=126,
                stdout=b"",
                stderr=b"audit Docker broker cleanup ownership changed\n",
            )
        else:
            cleanup_succeeded = successful
        phase = (
            "closed"
            if cleanup_succeeded and close_on_success and not current.limit_breach
            else current.phase
        )
        if current.cleanup_state != "complete":
            updated = replace(
                current,
                phase=phase,
                cleanup_state="complete" if cleanup_succeeded else "failed",
                cleanup_owner=None,
                cleanup_lease_deadline=None,
            )
            _write_state_unlocked(locked, updated)
    if cleanup_succeeded:
        return result if successful else BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
    return BrokerCommandResult(
        returncode=126,
        stdout=b"",
        stderr=b"audit Docker broker cleanup failed\n",
    )


def _refusal() -> BrokerCommandResult:
    return BrokerCommandResult(
        returncode=126,
        stdout=b"",
        stderr=b"audit Docker broker refused request\n",
    )


def invoke_audit_docker_broker(
    state_path: Path,
    arguments: tuple[str, ...],
    *,
    runner: DockerExecutionRunner | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> BrokerCommandResult:
    active_runner: DockerExecutionRunner = (
        _SubprocessDockerExecutionRunner() if runner is None else runner
    )
    try:
        with _locked_state(state_path) as locked:
            state = _read_state_unlocked(locked)
            now = clock()
            decision = _decide(state, arguments, now)
            if decision.state != state:
                _write_state_unlocked(locked, decision.state)
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        raise

    if decision.kind == "refuse":
        return _refusal()
    if decision.kind == "breach":
        _perform_cleanup(
            state_path,
            runner=active_runner,
            clock=clock,
            close_on_success=False,
        )
        return _refusal()
    if decision.kind == "emulated":
        return BrokerCommandResult(returncode=0, stdout=decision.stdout, stderr=b"")

    output_limit = (
        decision.state.per_call_reserved_output_bytes
        if decision.kind in {"bootstrap", "terminal"}
        else _CONTROL_OUTPUT_LIMIT
    )
    try:
        command_deadline = _command_deadline(decision.state, decision.kind, clock())
        result = active_runner.run(
            (decision.state.docker_executable, *arguments),
            deadline=command_deadline,
            output_limit=output_limit,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        if decision.kind == "terminal":
            updated = _release_terminal_reservation(
                state_path,
                output_bytes=None,
                breach_reason="terminal execution failure",
            )
        else:
            with _locked_state(state_path) as locked:
                current = _read_state_unlocked(locked)
                updated = _breach_control(
                    current,
                    decision,
                    "Docker control failure",
                )
                _write_state_unlocked(locked, updated)
        _perform_cleanup(
            state_path,
            runner=active_runner,
            clock=clock,
            close_on_success=False,
        )
        return _refusal()

    if decision.kind == "terminal":
        output_bytes = len(result.stdout) + len(result.stderr)
        updated = _release_terminal_reservation(
            state_path,
            output_bytes=output_bytes,
            breach_reason=(
                "terminal output limit"
                if output_bytes > decision.state.per_call_reserved_output_bytes
                else None
            ),
        )
        if updated.limit_breach:
            _perform_cleanup(
                state_path,
                runner=active_runner,
                clock=clock,
                close_on_success=False,
            )
            return _refusal()
        return result

    valid = (
        _valid_image_entrypoint(result)
        if decision.kind == "image"
        else _valid_network(result)
        if decision.kind == "network"
        else result.returncode == 0 and len(result.stdout) + len(result.stderr) <= output_limit
        if decision.kind == "bootstrap"
        else _valid_removal(result, decision.state.container_id)
    )
    if valid:
        completed = _complete_control(state_path, decision)
        if completed.limit_breach:
            _perform_cleanup(
                state_path,
                runner=active_runner,
                clock=clock,
                close_on_success=False,
            )
            return _refusal()
        return result

    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        updated = _breach_control(
            current,
            decision,
            "Docker response drift",
        )
        _write_state_unlocked(locked, updated)
    _perform_cleanup(
        state_path,
        runner=active_runner,
        clock=clock,
        close_on_success=False,
    )
    return _refusal()


def cleanup_audit_docker_broker(
    state_path: Path,
    *,
    runner: DockerExecutionRunner | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> BrokerCommandResult:
    active_runner: DockerExecutionRunner = (
        _SubprocessDockerExecutionRunner() if runner is None else runner
    )
    return _perform_cleanup(
        state_path,
        runner=active_runner,
        clock=clock,
        close_on_success=True,
    )
