from __future__ import annotations

import unittest
from dataclasses import replace

from zeus.audit_models import (
    AuditCategory,
    AuditCompleteness,
    AuditConfidence,
    AuditControlCoverage,
    AuditFinding,
    AuditMetadata,
    AuditReport,
    AuditSeverity,
    AuditStatus,
    AuditSurface,
    CoverageDisposition,
    SeverityCounts,
    SkippedContent,
)
from zeus.audit_policy import RELEASE_POLICY_ID, evaluate_audit_policy
from zeus.audit_profile import AUDIT_SKILL_VERSION
from zeus.audit_receipts import TRUSTED_EXECUTION_BOUNDARY
from zeus.audit_surface import SECURITY_CONTROL_CATALOG_VERSION

_REPOSITORY_ID = "f" * 64


def _surface(*control_ids: str) -> AuditSurface:
    control_set = frozenset(control_ids)
    return AuditSurface(
        catalog_version=SECURITY_CONTROL_CATALOG_VERSION,
        snapshot_digest="a" * 64,
        ecosystems=("python",),
        dependency_manifests=("pyproject.toml",) if "SEC-DEPS" in control_set else (),
        dependency_manifest_count=1 if "SEC-DEPS" in control_set else 0,
        ci_paths=(".github/workflows/ci.yml",) if "SEC-CI" in control_set else (),
        ci_path_count=1 if "SEC-CI" in control_set else 0,
        iac_paths=("Dockerfile",) if "SEC-IAC" in control_set else (),
        iac_path_count=1 if "SEC-IAC" in control_set else 0,
        web_paths=("routes/api.py",) if "SEC-WEB" in control_set else (),
        web_path_count=1 if "SEC-WEB" in control_set else 0,
        required_control_ids=tuple(control_ids),
    )


def _coverage(
    control_id: str,
    disposition: CoverageDisposition,
) -> AuditControlCoverage:
    accounted = disposition in {
        CoverageDisposition.checked,
        CoverageDisposition.not_applicable,
    }
    return AuditControlCoverage(
        control_id=control_id,
        category=AuditCategory.security,
        required=True,
        disposition=disposition,
        check_names=(f"check-{control_id.lower()}",) if accounted else (),
        reason=None if accounted else f"{control_id} could not be checked",
    )


def _finding(severity: AuditSeverity, suffix: str) -> AuditFinding:
    return AuditFinding(
        finding_id=f"finding-{suffix}",
        category=AuditCategory.security,
        severity=severity,
        confidence=AuditConfidence.high,
        title=f"{severity.value} finding",
        evidence=(),
        impact="impact",
        recommendation="recommendation",
        verification="verification",
        control_id="SEC-REPO",
        fingerprint=suffix * 64,
    )


def _report(
    *,
    schema_version: int = 2,
    status: AuditStatus = AuditStatus.completed,
    complete: bool = True,
    surface: AuditSurface | None = None,
    coverage: tuple[AuditControlCoverage, ...] = (),
    findings: tuple[AuditFinding, ...] = (),
    severity_counts: SeverityCounts | None = None,
) -> AuditReport:
    return AuditReport(
        schema_version=schema_version,
        run_id="audit-policy-test",
        repository_id=_REPOSITORY_ID,
        status=status,
        metadata=AuditMetadata(
            zeus_version="0.5.0",
            hermes_version="1.0.0",
            skill_version=AUDIT_SKILL_VERSION,
            image_digest="sha256:" + "b" * 64,
            target_commit="c" * 40,
            started_at="2026-08-04T10:00:00Z",
            finished_at="2026-08-04T10:01:00Z",
            termination_reason=None,
            provider="test",
            model="test",
            worktree_changes_excluded=True,
            trusted_execution_boundary=(
                TRUSTED_EXECUTION_BOUNDARY if schema_version >= 2 else None
            ),
        ),
        summary="policy fixture",
        checks=(),
        skipped_content=(),
        findings=findings,
        severity_counts=severity_counts or SeverityCounts(),
        completeness=AuditCompleteness(
            complete=complete,
            reasons=() if complete else ("fixture incomplete",),
        ),
        surface=surface,
        coverage=coverage,
        command_receipts=(),
    )


class AuditPolicyTests(unittest.TestCase):
    def _evaluate(self, report: AuditReport):
        return evaluate_audit_policy(
            report,
            expected_target_commit="c" * 40,
            expected_repository_id=_REPOSITORY_ID,
        )

    def test_release_policy_passes_accounted_required_controls(self) -> None:
        surface = _surface("SEC-REPO", "SEC-CI")
        report = _report(
            surface=surface,
            coverage=(
                _coverage("SEC-REPO", CoverageDisposition.checked),
                _coverage("SEC-CI", CoverageDisposition.checked),
            ),
        )

        result = self._evaluate(report)

        self.assertEqual(RELEASE_POLICY_ID, result.policy_id)
        self.assertTrue(result.passed)
        self.assertEqual((), result.reasons)

    def test_release_policy_rejects_missing_or_old_trusted_execution_boundary(self) -> None:
        report = _report(
            surface=_surface("SEC-REPO"),
            coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
        )

        for boundary in (None, "shared-writable-workspace-v1"):
            with self.subTest(boundary=boundary):
                result = self._evaluate(
                    replace(
                        report,
                        metadata=replace(
                            report.metadata,
                            trusted_execution_boundary=boundary,
                        ),
                    )
                )

                self.assertFalse(result.passed)
                self.assertEqual(
                    ("unsupported_trusted_execution_boundary",),
                    tuple(reason.code for reason in result.reasons),
                )

    def test_release_policy_fails_closed_for_report_state_and_findings(self) -> None:
        report = _report(
            schema_version=1,
            status=AuditStatus.partial,
            complete=False,
            surface=None,
            findings=(
                _finding(AuditSeverity.high, "d"),
                _finding(AuditSeverity.critical, "e"),
            ),
        )

        result = self._evaluate(report)

        self.assertFalse(result.passed)
        self.assertEqual(
            (
                "unsupported_report_schema",
                "missing_audit_surface",
                "report_not_completed",
                "report_incomplete",
                "critical_findings",
                "high_findings",
            ),
            tuple(reason.code for reason in result.reasons),
        )

    def test_release_policy_reports_missing_skipped_and_unsupported_controls(self) -> None:
        surface = _surface("SEC-REPO", "SEC-CI", "SEC-IAC")
        report = _report(
            surface=surface,
            coverage=(
                _coverage("SEC-REPO", CoverageDisposition.skipped),
                _coverage("SEC-CI", CoverageDisposition.unsupported),
            ),
        )

        result = self._evaluate(report)

        self.assertFalse(result.passed)
        self.assertEqual(
            (
                "required_control_missing",
                "required_control_skipped",
                "required_control_unsupported",
            ),
            tuple(reason.code for reason in result.reasons),
        )
        self.assertEqual("SEC-IAC", result.reasons[0].control_ids[0])
        self.assertEqual("SEC-REPO", result.reasons[1].control_ids[0])
        self.assertEqual("SEC-CI", result.reasons[2].control_ids[0])

    def test_release_policy_uses_findings_and_declared_counts_fail_closed(self) -> None:
        surface = _surface("SEC-REPO")
        report = _report(
            surface=surface,
            coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
            findings=(_finding(AuditSeverity.high, "f"),),
            severity_counts=SeverityCounts(critical=1),
        )

        result = self._evaluate(report)

        self.assertEqual(
            ("critical_findings", "high_findings"),
            tuple(reason.code for reason in result.reasons),
        )

    def test_unknown_policy_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown audit policy"):
            evaluate_audit_policy(_report(), policy_id="unknown")

    def test_release_policy_is_bound_to_the_requested_target_commit(self) -> None:
        surface = _surface("SEC-REPO")
        report = _report(
            surface=surface,
            coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
        )

        result = evaluate_audit_policy(
            report,
            expected_target_commit="d" * 40,
            expected_repository_id=_REPOSITORY_ID,
        )

        self.assertFalse(result.passed)
        self.assertEqual("target_commit_mismatch", result.reasons[0].code)

    def test_required_applicable_control_cannot_pass_as_not_applicable(self) -> None:
        surface = _surface("SEC-REPO")
        report = _report(
            surface=surface,
            coverage=(_coverage("SEC-REPO", CoverageDisposition.not_applicable),),
        )

        result = self._evaluate(report)

        self.assertFalse(result.passed)
        self.assertEqual("required_control_not_applicable", result.reasons[0].code)

    def test_release_policy_requires_security_scope(self) -> None:
        result = self._evaluate(_report(surface=_surface()))

        self.assertFalse(result.passed)
        self.assertEqual("security_scope_missing", result.reasons[0].code)

    def test_release_policy_rejects_skipped_committed_content(self) -> None:
        surface = _surface("SEC-REPO")
        report = replace(
            _report(
                surface=surface,
                coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
            ),
            skipped_content=(SkippedContent("vendor/lockfile", "excluded by configuration"),),
        )

        result = self._evaluate(report)

        self.assertFalse(result.passed)
        self.assertEqual("committed_content_skipped", result.reasons[0].code)

    def test_release_policy_rejects_unknown_catalog_controls_and_skill(self) -> None:
        report = _report(
            surface=replace(_surface("SEC-REPO"), catalog_version="0.9.0"),
            coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
        )

        result = self._evaluate(
            replace(report, metadata=replace(report.metadata, skill_version="1.0.0"))
        )

        self.assertEqual(
            ("unsupported_control_catalog", "unsupported_audit_skill"),
            tuple(reason.code for reason in result.reasons),
        )

        fake_surface = replace(
            _surface("SEC-REPO"),
            required_control_ids=("SEC-FAKE", "SEC-REPO"),
        )
        fake = self._evaluate(
            _report(
                surface=fake_surface,
                coverage=(
                    _coverage("SEC-FAKE", CoverageDisposition.checked),
                    _coverage("SEC-REPO", CoverageDisposition.checked),
                ),
            )
        )
        self.assertEqual("invalid_security_surface", fake.reasons[0].code)

    def test_release_policy_is_bound_to_repository_identity(self) -> None:
        report = _report(
            surface=_surface("SEC-REPO"),
            coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
        )

        unbound = evaluate_audit_policy(
            report,
            expected_target_commit="c" * 40,
        )
        mismatch = evaluate_audit_policy(
            report,
            expected_target_commit="c" * 40,
            expected_repository_id="e" * 64,
        )

        self.assertIn("repository_unbound", tuple(reason.code for reason in unbound.reasons))
        self.assertIn("repository_mismatch", tuple(reason.code for reason in mismatch.reasons))

    def test_release_policy_requires_committed_snapshot_scope(self) -> None:
        report = _report(
            surface=_surface("SEC-REPO"),
            coverage=(_coverage("SEC-REPO", CoverageDisposition.checked),),
        )

        result = self._evaluate(
            replace(
                report,
                metadata=replace(report.metadata, worktree_changes_excluded=False),
            )
        )

        self.assertEqual("worktree_scope_unverified", result.reasons[0].code)


if __name__ == "__main__":
    unittest.main()
