from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias


class AuditStatus(StrEnum):
    completed = "completed"
    partial = "partial"
    blocked = "blocked"
    failed = "failed"
    cancelled = "cancelled"


class AuditCategory(StrEnum):
    security = "security"
    correctness = "correctness"
    tests = "tests"
    architecture = "architecture"
    dependencies = "dependencies"
    documentation = "documentation"


class AuditSeverity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    note = "note"


class AuditConfidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


class CheckDisposition(StrEnum):
    passed = "passed"
    failed = "failed"
    skipped = "skipped"


@dataclass(frozen=True)
class AuditLimits:
    overall_seconds: int
    git_command_seconds: int
    materialization_seconds: int
    docker_control_seconds: int
    terminal_command_seconds: int
    terminal_calls: int
    model_iterations: int
    terminal_output_per_call_bytes: int
    terminal_output_total_bytes: int
    cpu_count: int
    memory_bytes: int
    pids: int
    workspace_bytes: int
    temp_bytes: int
    findings: int
    model_output_bytes: int
    artifact_bytes: int
    hermes_stderr_bytes: int
    provider_value_bytes: int
    snapshot_entries: int
    git_metadata_bytes: int
    snapshot_blob_bytes: int


@dataclass(frozen=True)
class AuditHardLimits(AuditLimits):
    pass


HARD_LIMITS = AuditHardLimits(
    overall_seconds=3600,
    git_command_seconds=30,
    materialization_seconds=300,
    docker_control_seconds=60,
    terminal_command_seconds=600,
    terminal_calls=64,
    model_iterations=80,
    terminal_output_per_call_bytes=2 * 1024 * 1024,
    terminal_output_total_bytes=16 * 1024 * 1024,
    cpu_count=2,
    memory_bytes=4 * 1024**3,
    pids=256,
    workspace_bytes=2 * 1024**3,
    temp_bytes=512 * 1024**2,
    findings=100,
    model_output_bytes=1024 * 1024,
    artifact_bytes=1024 * 1024,
    hermes_stderr_bytes=256 * 1024,
    provider_value_bytes=16 * 1024,
    snapshot_entries=100_000,
    git_metadata_bytes=64 * 1024 * 1024,
    snapshot_blob_bytes=1024**3,
)


@dataclass(frozen=True)
class SuggestedCommand:
    name: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class AuditConfig:
    schema_version: int
    provider: str | None
    model: str | None
    provider_env: tuple[str, ...]
    image: str
    categories: frozenset[AuditCategory]
    exclude_paths: tuple[str, ...]
    suggested_commands: tuple[SuggestedCommand, ...]
    limits: AuditLimits


@dataclass(frozen=True)
class AuditCheck:
    name: str
    disposition: CheckDisposition
    duration_seconds: float
    observation: str


@dataclass(frozen=True)
class SkippedContent:
    path: str
    reason: str


@dataclass(frozen=True)
class SourceEvidence:
    path: str
    start_line: int
    end_line: int | None
    observation: str


@dataclass(frozen=True)
class CheckEvidence:
    check_name: str
    observation: str


@dataclass(frozen=True)
class RepositoryEvidence:
    observation: str
    inspection_method: str


AuditEvidence: TypeAlias = SourceEvidence | CheckEvidence | RepositoryEvidence


@dataclass(frozen=True)
class AuditFinding:
    finding_id: str
    category: AuditCategory
    severity: AuditSeverity
    confidence: AuditConfidence
    title: str
    evidence: tuple[AuditEvidence, ...]
    impact: str
    recommendation: str
    verification: str


@dataclass(frozen=True)
class AuditMetadata:
    zeus_version: str
    hermes_version: str | None
    skill_version: str | None
    image_digest: str | None
    target_commit: str | None
    started_at: str
    finished_at: str
    termination_reason: str | None
    provider: str | None
    model: str | None
    worktree_changes_excluded: bool


@dataclass(frozen=True)
class AuditCompleteness:
    complete: bool
    rejected_findings: int = 0
    truncated_findings: int = 0
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    note: int = 0


@dataclass(frozen=True)
class ModelAuditResult:
    summary: str
    findings: tuple[AuditFinding, ...]
    skipped_checks: tuple[str, ...]
    completeness: AuditCompleteness


@dataclass(frozen=True)
class AuditReport:
    schema_version: int
    run_id: str
    repository_id: str
    status: AuditStatus
    metadata: AuditMetadata
    summary: str
    checks: tuple[AuditCheck, ...]
    skipped_content: tuple[SkippedContent, ...]
    findings: tuple[AuditFinding, ...]
    severity_counts: SeverityCounts
    completeness: AuditCompleteness
