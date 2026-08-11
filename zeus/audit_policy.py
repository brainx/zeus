from __future__ import annotations

import re
from dataclasses import dataclass

from zeus.audit_models import (
    AuditControlCoverage,
    AuditReport,
    AuditSeverity,
    AuditStatus,
    CoverageDisposition,
)
from zeus.audit_profile import AUDIT_SKILL_VERSION
from zeus.audit_receipts import TRUSTED_EXECUTION_BOUNDARY
from zeus.audit_scanners import AuditScannerRegistryError, select_audit_scanner_adapters
from zeus.audit_surface import SECURITY_CONTROL_CATALOG_VERSION

RELEASE_POLICY_ID = "release-v1"
_REQUIRED_REPORT_SCHEMA_VERSION = 2
_TARGET_COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REPOSITORY_ID_RE = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AuditPolicyReason:
    code: str
    observation: str
    control_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditPolicyEvaluation:
    policy_id: str
    passed: bool
    reasons: tuple[AuditPolicyReason, ...]


def _reason(
    code: str,
    observation: str,
    control_ids: tuple[str, ...] = (),
) -> AuditPolicyReason:
    return AuditPolicyReason(
        code=code,
        observation=observation,
        control_ids=control_ids,
    )


def _control_observation(prefix: str, control_ids: tuple[str, ...]) -> str:
    return f"{prefix}: {', '.join(control_ids)}"


def evaluate_audit_policy(
    report: AuditReport,
    *,
    policy_id: str = RELEASE_POLICY_ID,
    expected_target_commit: str | None = None,
    expected_repository_id: str | None = None,
) -> AuditPolicyEvaluation:
    """Evaluate the deterministic, fail-closed release audit policy."""

    if policy_id != RELEASE_POLICY_ID:
        raise ValueError(f"unknown audit policy: {policy_id}")

    reasons: list[AuditPolicyReason] = []
    if report.schema_version != _REQUIRED_REPORT_SCHEMA_VERSION:
        reasons.append(
            _reason(
                "unsupported_report_schema",
                "release-v1 requires audit report schema version 2",
            )
        )

    surface_valid = False
    if report.surface is None:
        reasons.append(
            _reason(
                "missing_audit_surface",
                "the report does not declare the audited repository surface",
            )
        )
    else:
        if report.surface.catalog_version != SECURITY_CONTROL_CATALOG_VERSION:
            reasons.append(
                _reason(
                    "unsupported_control_catalog",
                    "release-v1 requires the current security control catalog",
                )
            )
        else:
            try:
                select_audit_scanner_adapters(report.surface)
            except AuditScannerRegistryError:
                reasons.append(
                    _reason(
                        "invalid_security_surface",
                        "the declared security surface is inconsistent with the control catalog",
                    )
                )
            else:
                surface_valid = True
        if "SEC-REPO" not in report.surface.required_control_ids:
            reasons.append(
                _reason(
                    "security_scope_missing",
                    "release-v1 requires an audit that selected the security category",
                )
            )

    if report.metadata.skill_version != AUDIT_SKILL_VERSION:
        reasons.append(
            _reason(
                "unsupported_audit_skill",
                "release-v1 requires the current bundled audit skill",
            )
        )

    if (
        report.schema_version == _REQUIRED_REPORT_SCHEMA_VERSION
        and report.metadata.trusted_execution_boundary != TRUSTED_EXECUTION_BOUNDARY
    ):
        reasons.append(
            _reason(
                "unsupported_trusted_execution_boundary",
                "release-v1 requires trusted receipts from the current "
                "isolated read-only snapshot boundary",
            )
        )

    if (
        not isinstance(expected_target_commit, str)
        or _TARGET_COMMIT_RE.fullmatch(expected_target_commit) is None
    ):
        reasons.append(
            _reason(
                "target_commit_unbound",
                "release-v1 requires an explicit canonical target commit",
            )
        )
    elif report.metadata.target_commit != expected_target_commit:
        reasons.append(
            _reason(
                "target_commit_mismatch",
                "the audit target commit does not match the requested release commit",
            )
        )

    if (
        not isinstance(expected_repository_id, str)
        or _REPOSITORY_ID_RE.fullmatch(expected_repository_id) is None
    ):
        reasons.append(
            _reason(
                "repository_unbound",
                "release-v1 requires an explicit canonical repository identity",
            )
        )
    elif report.repository_id != expected_repository_id:
        reasons.append(
            _reason(
                "repository_mismatch",
                "the audit report belongs to a different repository",
            )
        )

    if report.metadata.worktree_changes_excluded is not True:
        reasons.append(
            _reason(
                "worktree_scope_unverified",
                "release-v1 requires a report limited to the committed repository snapshot",
            )
        )

    if report.status is not AuditStatus.completed:
        reasons.append(
            _reason(
                "report_not_completed",
                f"the audit status is {report.status.value}, not completed",
            )
        )

    if not report.completeness.complete:
        reasons.append(
            _reason(
                "report_incomplete",
                "the audit report is marked incomplete",
            )
        )

    if report.skipped_content:
        reasons.append(
            _reason(
                "committed_content_skipped",
                f"the audit skipped {len(report.skipped_content)} committed path(s) or scope(s)",
            )
        )

    missing: list[str] = []
    skipped: list[str] = []
    unsupported: list[str] = []
    not_applicable: list[str] = []
    if report.surface is not None and surface_valid:
        coverage_by_id: dict[str, list[AuditControlCoverage]] = {}
        for coverage in report.coverage:
            coverage_by_id.setdefault(coverage.control_id, []).append(coverage)

        for control_id in sorted(set(report.surface.required_control_ids)):
            matching = coverage_by_id.get(control_id, [])
            if len(matching) != 1 or not matching[0].required:
                missing.append(control_id)
                continue
            disposition = matching[0].disposition
            if disposition is CoverageDisposition.skipped:
                skipped.append(control_id)
            elif disposition is CoverageDisposition.unsupported:
                unsupported.append(control_id)
            elif disposition is CoverageDisposition.not_applicable:
                not_applicable.append(control_id)

    if missing:
        control_ids = tuple(missing)
        reasons.append(
            _reason(
                "required_control_missing",
                _control_observation(
                    "required controls have no single valid coverage record",
                    control_ids,
                ),
                control_ids,
            )
        )
    if skipped:
        control_ids = tuple(skipped)
        reasons.append(
            _reason(
                "required_control_skipped",
                _control_observation("required controls were skipped", control_ids),
                control_ids,
            )
        )
    if unsupported:
        control_ids = tuple(unsupported)
        reasons.append(
            _reason(
                "required_control_unsupported",
                _control_observation(
                    "required controls are unsupported",
                    control_ids,
                ),
                control_ids,
            )
        )
    if not_applicable:
        control_ids = tuple(not_applicable)
        reasons.append(
            _reason(
                "required_control_not_applicable",
                _control_observation(
                    "applicable required controls were marked not applicable",
                    control_ids,
                ),
                control_ids,
            )
        )

    finding_counts = {
        severity: sum(1 for finding in report.findings if finding.severity is severity)
        for severity in (AuditSeverity.critical, AuditSeverity.high)
    }
    critical_count = max(report.severity_counts.critical, finding_counts[AuditSeverity.critical])
    high_count = max(report.severity_counts.high, finding_counts[AuditSeverity.high])
    if critical_count:
        reasons.append(
            _reason(
                "critical_findings",
                f"the report contains {critical_count} critical finding(s)",
            )
        )
    if high_count:
        reasons.append(
            _reason(
                "high_findings",
                f"the report contains {high_count} high finding(s)",
            )
        )

    return AuditPolicyEvaluation(
        policy_id=policy_id,
        passed=not reasons,
        reasons=tuple(reasons),
    )
