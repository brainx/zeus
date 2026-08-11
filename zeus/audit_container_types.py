"""Shared types and fail-closed bounds for the audit container runtime."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NoReturn, Protocol

from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.private_io import ensure_private_directory

AUDIT_UID = AUDIT_GID = 65532


class AuditContainerError(RuntimeError):
    """Raised when an audit container control cannot be proven safe."""


@dataclass(frozen=True)
class DockerCommandResult:
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class PreparedAuditContainer:
    container_id: str
    container_name: str
    profile_name: str
    image_ref: str
    image_id: str
    broker_dir: Path
    state_path: Path
    trusted_container_id: str | None = None
    trusted_container_name: str | None = None
    trusted_snapshot_path: str | None = None
    trusted_snapshot_device: int | None = None
    trusted_snapshot_inode: int | None = None
    trusted_snapshot_owner: int | None = None
    trusted_snapshot_mode: int | None = None
    trusted_execution_uid: int | None = None
    trusted_execution_gid: int | None = None


@dataclass(frozen=True)
class CleanupResult:
    removed: bool
    ambiguous: bool
    observation: str


class DockerCommandRunner(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_stream: BinaryIO | None,
        deadline: float,
        stdout_limit: int,
        stderr_limit: int,
        env: dict[str, str],
    ) -> DockerCommandResult: ...


@dataclass(frozen=True)
class PreparedRecord:
    prepared: PreparedAuditContainer
    limits: AuditLimits
    deadline: float
    labels: dict[str, str]
    image_environment: tuple[str, ...]
    trusted_snapshot_path: str | None = None
    trusted_environment: tuple[str, ...] | None = None


def _error(message: str) -> NoReturn:
    raise AuditContainerError(message)


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        _error("audit container deadline has expired")
    return value


def _validate_deadline(deadline: float) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        _error("audit container deadline must be a finite monotonic timestamp")
    result = float(deadline)
    _remaining(result)
    return result


def _command_deadline(deadline: float, limits: AuditLimits) -> float:
    _remaining(deadline)
    return min(deadline, time.monotonic() + limits.docker_control_seconds)


def _validate_limits(limits: AuditLimits) -> None:
    if not isinstance(limits, AuditLimits):
        _error("audit container limits are invalid")
    for field in (
        "cpu_count",
        "memory_bytes",
        "pids",
        "workspace_bytes",
        "temp_bytes",
    ):
        if getattr(limits, field) != getattr(HARD_LIMITS, field):
            _error("audit container isolation limits cannot be configured")
    if (
        isinstance(limits.docker_control_seconds, bool)
        or not isinstance(limits.docker_control_seconds, int)
        or not 1 <= limits.docker_control_seconds <= HARD_LIMITS.docker_control_seconds
    ):
        _error("audit Docker control deadline is outside its hard limit")


def _safe_private_directory(path: Path) -> None:
    try:
        ensure_private_directory(path)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditContainerError("audit container control directory is unavailable") from exc
