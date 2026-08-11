from __future__ import annotations

import unittest

from zeus.audit_models import (
    AuditCategory,
    AuditCheck,
    AuditCommandReceipt,
    AuditCompleteness,
    AuditConfidence,
    AuditControlCoverage,
    AuditFinding,
    AuditMetadata,
    AuditSeverity,
    AuditStatus,
    AuditSurface,
    CheckDisposition,
    CoverageDisposition,
    ModelAuditResult,
    SkippedContent,
    SourceEvidence,
)
from zeus.audit_profile import AUDIT_SKILL_VERSION
from zeus.audit_receipts import TRUSTED_EXECUTION_BOUNDARY
from zeus.audit_report import build_audit_report, render_audit_markdown


def _metadata() -> AuditMetadata:
    return AuditMetadata(
        zeus_version="0.5.0",
        hermes_version="0.20.0",
        skill_version=AUDIT_SKILL_VERSION,
        image_digest="sha256:" + "a" * 64,
        target_commit="b" * 40,
        started_at="2026-08-04T10:00:00Z",
        finished_at="2026-08-04T10:01:00Z",
        termination_reason=None,
        provider="provider",
        model="model",
        worktree_changes_excluded=True,
        trusted_execution_boundary=TRUSTED_EXECUTION_BOUNDARY,
    )


class AuditReportMarkdownV2Tests(unittest.TestCase):
    def test_schema_v1_rendering_remains_byte_identical(self) -> None:
        report = build_audit_report(
            schema_version=1,
            run_id="run-v1",
            repository_id="repo-v1",
            status=AuditStatus.completed,
            metadata=_metadata(),
            checks=(AuditCheck("lint", CheckDisposition.passed, 1.25, "clean"),),
            skipped_content=(SkippedContent("vendor", "excluded by config"),),
            model_result=ModelAuditResult(
                summary="Audit complete",
                findings=(),
                skipped_checks=(),
                checks=(),
                completeness=AuditCompleteness(complete=True),
            ),
        )

        self.assertEqual(
            """# Zeus Repository Audit

- Run: `run-v1`
- Repository: `repo-v1`
- Status: **completed**
- Target commit: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- Started: 2026-08-04T10:00:00Z
- Finished: 2026-08-04T10:01:00Z

## Summary

Audit complete

## Severity counts

| Critical | High | Medium | Low | Note |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 0 | 0 | 0 |

## Checks

| Check | Disposition | Duration (s) | Observation |
| --- | --- | ---: | --- |
| lint | passed | 1.250 | clean |

## Skipped content

| Path or scope | Reason |
| --- | --- |
| vendor | excluded by config |

## Findings

No validated findings.

## Completeness

Complete within the selected snapshot scope shown above.
""",
            render_audit_markdown(report),
        )

    def test_schema_v2_renders_surface_coverage_receipts_and_stable_evidence(self) -> None:
        receipt = AuditCommandReceipt(
            receipt_id="terminal-000001",
            sequence=1,
            command_tag="hmac-sha256:" + "c" * 64,
            state="exited",
            returncode=0,
            duration_ms=25,
            stdout_bytes=12,
            stderr_bytes=3,
        )
        check = AuditCheck(
            "repository review",
            CheckDisposition.passed,
            0.025,
            "review completed",
            receipt_id=receipt.receipt_id,
        )
        finding = AuditFinding(
            finding_id="finding-run-v2-0001",
            category=AuditCategory.security,
            severity=AuditSeverity.high,
            confidence=AuditConfidence.high,
            title="Unsafe boundary",
            evidence=(
                SourceEvidence(
                    path="zeus/example` **FORGED**.py",
                    start_line=2,
                    end_line=3,
                    observation="unsafe call",
                    blob_sha256="d" * 64,
                ),
            ),
            impact="boundary may fail open",
            recommendation="validate the boundary",
            verification="run the focused test",
            control_id="SEC-REPO",
            fingerprint="finding-fingerprint-" + "e" * 32,
        )
        report = build_audit_report(
            run_id="run-v2",
            repository_id="repo-v2",
            status=AuditStatus.completed,
            metadata=_metadata(),
            checks=(check,),
            skipped_content=(),
            model_result=ModelAuditResult(
                summary="Security audit complete",
                findings=(finding,),
                skipped_checks=(),
                checks=(),
                completeness=AuditCompleteness(complete=True),
                coverage=(
                    AuditControlCoverage(
                        control_id="SEC-REPO",
                        category=AuditCategory.security,
                        required=True,
                        disposition=CoverageDisposition.checked,
                        check_names=(check.name,),
                        reason=None,
                    ),
                ),
            ),
            surface=AuditSurface(
                catalog_version="1.0.0",
                snapshot_digest="f" * 64,
                ecosystems=("github-actions", "python"),
                dependency_manifests=("pyproject.toml",),
                dependency_manifest_count=1,
                ci_paths=(".github/workflows/ci.yml",),
                ci_path_count=1,
                iac_paths=("Dockerfile",),
                iac_path_count=1,
                web_paths=("zeus/web.py",),
                web_path_count=1,
                required_control_ids=("SEC-REPO",),
            ),
            command_receipts=(receipt,),
        )

        markdown = render_audit_markdown(report)

        self.assertIn(
            f"- Trusted execution boundary: {TRUSTED_EXECUTION_BOUNDARY}",
            markdown,
        )
        self.assertIn("## Repository surface", markdown)
        self.assertIn("- Surface catalog: `1.0.0`", markdown)
        self.assertIn(f"- Snapshot digest: `{'f' * 64}`", markdown)
        self.assertIn("| Dependency manifests | 1 | pyproject.toml |", markdown)
        self.assertIn("| CI configuration | 1 | .github/workflows/ci.yml |", markdown)
        self.assertIn("## Security coverage", markdown)
        self.assertIn("| SEC-REPO | security | yes | checked | repository review | — |", markdown)
        self.assertIn("| repository review | passed | terminal-000001 |", markdown)
        self.assertIn("## Command receipts", markdown)
        self.assertIn(
            f"| terminal-000001 | 1 | exited | 0 | 25 | 12 | 3 | hmac-sha256:{'c' * 64} |",
            markdown,
        )
        self.assertIn("- Control: `SEC-REPO`", markdown)
        self.assertIn(f"- Fingerprint: `finding-fingerprint-{'e' * 32}`", markdown)
        self.assertIn(f"blob `{'d' * 64}`", markdown)
        self.assertIn("Source ``zeus/example` **FORGED**.py:2-3``", markdown)
        self.assertNotIn(r"Source `zeus/example\` **FORGED**.py:2-3`", markdown)
        self.assertNotIn("Raw command", markdown)
        self.assertNotIn("Command output", markdown)

    def test_schema_v2_surface_paths_cannot_create_active_markdown(self) -> None:
        report = build_audit_report(
            run_id="run-v2-markdown",
            repository_id="repo-v2",
            status=AuditStatus.partial,
            metadata=_metadata(),
            checks=(),
            skipped_content=(),
            model_result=ModelAuditResult(
                summary="Incomplete surface inventory",
                findings=(),
                skipped_checks=(),
                checks=(),
                completeness=AuditCompleteness(
                    complete=False,
                    reasons=("security coverage was skipped",),
                ),
                coverage=(
                    AuditControlCoverage(
                        control_id="SEC-CI",
                        category=AuditCategory.security,
                        required=True,
                        disposition=CoverageDisposition.skipped,
                        check_names=(),
                        reason="not executed",
                    ),
                ),
            ),
            surface=AuditSurface(
                catalog_version="1.0.0",
                snapshot_digest="f" * 64,
                ecosystems=(),
                dependency_manifests=(),
                dependency_manifest_count=0,
                ci_paths=(".github/workflows/![pixel](https:attacker.invalid/p).yml",),
                ci_path_count=1,
                iac_paths=(),
                iac_path_count=0,
                web_paths=(),
                web_path_count=0,
                required_control_ids=("SEC-CI",),
            ),
        )

        markdown = render_audit_markdown(report)

        self.assertNotIn("![pixel](", markdown)
        self.assertIn(r"\!\[pixel\]\(https:attacker.invalid/p\)", markdown)


if __name__ == "__main__":
    unittest.main()
