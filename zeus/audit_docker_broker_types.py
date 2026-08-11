"""Shared state and execution types for the audit Docker broker."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from zeus.audit_models import AuditCommandReceipt


class AuditDockerBrokerError(RuntimeError):
    """Raised when broker state or execution cannot be proven safe."""


class DockerExecutionError(AuditDockerBrokerError):
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
    target_commit: str | None = None
    snapshot_digest: str | None = None
    receipt_hmac_key: str | None = None
    terminal_receipts: tuple[AuditCommandReceipt, ...] = ()
    trusted_container_id: str | None = None
    trusted_container_name: str | None = None
    trusted_snapshot_path: str | None = None
    trusted_snapshot_device: int | None = None
    trusted_snapshot_inode: int | None = None
    trusted_snapshot_owner: int | None = None
    trusted_snapshot_mode: int | None = None
    trusted_execution_uid: int | None = None
    trusted_execution_gid: int | None = None
    trusted_command_tags: tuple[str, ...] = ()
    active_trusted_receipt_id: str | None = None


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
class Decision:
    kind: str
    state: AuditDockerBrokerState
    stdout: bytes = b""
    session_id: str | None = None
    receipt_id: str | None = None
    started_at: float | None = None
    isolated_workspace: bool = False
