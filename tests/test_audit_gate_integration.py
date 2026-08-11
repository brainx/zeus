from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from subprocess import DEVNULL, run
from unittest import mock

from tests.host_capabilities import copy_single_link_git, path_with_tool
from zeus import __version__
from zeus.audit import AuditService
from zeus.audit_docker_broker import HERMES_VERSION
from zeus.audit_models import (
    AuditCategory,
    AuditCheck,
    AuditCommandReceipt,
    AuditCompleteness,
    AuditControlCoverage,
    AuditMetadata,
    AuditReport,
    AuditStatus,
    AuditSurface,
    CheckDisposition,
    CoverageDisposition,
    ModelAuditResult,
)
from zeus.audit_profile import AUDIT_SKILL_VERSION
from zeus.audit_receipts import TRUSTED_EXECUTION_BOUNDARY
from zeus.audit_report import build_audit_report
from zeus.audit_store import AuditStore, AuditStoreError
from zeus.audit_surface import SECURITY_CONTROL_CATALOG_VERSION


class AuditGateIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host_tools = tempfile.TemporaryDirectory()
        self.addCleanup(self.host_tools.cleanup)
        git = copy_single_link_git(Path(self.host_tools.name))
        self.path_patch = mock.patch.dict(os.environ, {"PATH": path_with_tool(git)})
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)

        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve() / "repository"
        self._initialize_repository()
        self.service = AuditService.from_cwd(cwd=self.repository, env={})
        self.store = AuditStore(self.service.settings.state_dir)

    def _initialize_repository(self) -> None:
        run(("git", "init", "-q", str(self.repository)), check=True, stdin=DEVNULL)
        run(
            ("git", "-C", str(self.repository), "config", "user.email", "test@example.invalid"),
            check=True,
            stdin=DEVNULL,
        )
        run(
            ("git", "-C", str(self.repository), "config", "user.name", "Test"),
            check=True,
            stdin=DEVNULL,
        )
        (self.repository / ".gitignore").write_text(".zeus/\n", encoding="utf-8")
        (self.repository / "README").write_text("test\n", encoding="utf-8")
        run(
            ("git", "-C", str(self.repository), "add", ".gitignore", "README"),
            check=True,
            stdin=DEVNULL,
        )
        run(
            ("git", "-C", str(self.repository), "commit", "-qm", "initial"),
            check=True,
            stdin=DEVNULL,
        )

    @staticmethod
    def _surface() -> AuditSurface:
        return AuditSurface(
            catalog_version=SECURITY_CONTROL_CATALOG_VERSION,
            snapshot_digest="a" * 64,
            ecosystems=(),
            dependency_manifests=(),
            dependency_manifest_count=0,
            ci_paths=(),
            ci_path_count=0,
            iac_paths=(),
            iac_path_count=0,
            web_paths=(),
            web_path_count=0,
            required_control_ids=("SEC-REPO",),
        )

    @staticmethod
    def _checked_coverage(control_id: str = "SEC-REPO") -> AuditControlCoverage:
        return AuditControlCoverage(
            control_id=control_id,
            category=AuditCategory.security,
            required=True,
            disposition=CoverageDisposition.checked,
            check_names=("repository-policy",),
            reason=None,
        )

    def _report(
        self,
        run_id: str,
        *,
        target_commit: str | None = None,
        surface: AuditSurface | None = None,
        coverage: tuple[AuditControlCoverage, ...] | None = None,
        trusted_execution_boundary: str | None = TRUSTED_EXECUTION_BOUNDARY,
    ) -> AuditReport:
        receipt = AuditCommandReceipt(
            receipt_id="terminal-000001",
            sequence=1,
            command_tag="hmac-sha256:" + "b" * 64,
            state="exited",
            returncode=0,
            duration_ms=1,
            stdout_bytes=0,
            stderr_bytes=0,
        )
        check = AuditCheck(
            name="repository-policy",
            disposition=CheckDisposition.passed,
            duration_seconds=0.001,
            observation="repository policy passed",
            receipt_id=receipt.receipt_id,
        )
        selected_surface = self._surface() if surface is None else surface
        selected_coverage = (self._checked_coverage(),) if coverage is None else coverage
        return build_audit_report(
            run_id=run_id,
            repository_id=self.service.location.repository_id,
            status=AuditStatus.completed,
            metadata=AuditMetadata(
                zeus_version=__version__,
                hermes_version=HERMES_VERSION,
                skill_version=AUDIT_SKILL_VERSION,
                image_digest="sha256:" + "c" * 64,
                target_commit=target_commit or self.service.location.head,
                started_at="2026-08-11T10:00:00Z",
                finished_at="2026-08-11T10:00:01Z",
                termination_reason=None,
                provider="test-provider",
                model="test-model",
                worktree_changes_excluded=True,
                trusted_execution_boundary=trusted_execution_boundary,
            ),
            checks=(check,),
            skipped_content=(),
            model_result=ModelAuditResult(
                summary="release evidence is complete",
                findings=(),
                skipped_checks=(),
                checks=(),
                completeness=AuditCompleteness(complete=True),
                coverage=selected_coverage,
            ),
            surface=selected_surface,
            command_receipts=(receipt,),
        )

    def test_parser_valid_stored_report_round_trips_and_passes_gate(self) -> None:
        report = self._report("1" * 32)

        self.store.install(report)
        stored = self.store.read_report(report.run_id)
        evaluation = self.service.gate(report.run_id)

        self.assertEqual(report, stored)
        self.assertTrue(evaluation.passed)
        self.assertEqual((), evaluation.reasons)

    def test_parser_valid_missing_or_old_execution_boundary_fails_gate(self) -> None:
        for index, boundary in enumerate(
            (None, "isolated-read-only-snapshot"),
            start=6,
        ):
            with self.subTest(boundary=boundary):
                report = self._report(
                    str(index) * 32,
                    trusted_execution_boundary=boundary,
                )

                self.store.install(report)
                self.assertEqual(report, self.store.read_report(report.run_id))
                evaluation = self.service.gate(report.run_id)

                self.assertFalse(evaluation.passed)
                self.assertEqual(
                    ("unsupported_trusted_execution_boundary",),
                    tuple(reason.code for reason in evaluation.reasons),
                )

    def test_receipt_result_tampering_fails_before_policy_evaluation(self) -> None:
        report = self._report("2" * 32)
        artifacts = self.store.install(report)
        payload = json.loads(artifacts.json_path.read_bytes())
        payload["command_receipts"][0]["returncode"] = 1
        artifacts.json_path.write_bytes(
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )

        with self.assertRaisesRegex(AuditStoreError, "stored audit report JSON is invalid"):
            self.service.gate(report.run_id)

    def test_parser_valid_skipped_coverage_fails_gate(self) -> None:
        skipped = AuditControlCoverage(
            control_id="SEC-REPO",
            category=AuditCategory.security,
            required=True,
            disposition=CoverageDisposition.skipped,
            check_names=(),
            reason="repository policy was not checked",
        )
        report = self._report("3" * 32, coverage=(skipped,))

        self.store.install(report)
        self.assertEqual(report, self.store.read_report(report.run_id))
        evaluation = self.service.gate(report.run_id)

        self.assertFalse(evaluation.passed)
        self.assertEqual(
            ("required_control_skipped",),
            tuple(reason.code for reason in evaluation.reasons),
        )

    def test_parser_valid_commit_mismatch_fails_gate(self) -> None:
        report = self._report("4" * 32, target_commit="0" * 40)

        self.store.install(report)
        self.assertEqual(report, self.store.read_report(report.run_id))
        evaluation = self.service.gate(report.run_id)

        self.assertFalse(evaluation.passed)
        self.assertEqual(
            ("target_commit_mismatch",),
            tuple(reason.code for reason in evaluation.reasons),
        )

    def test_parser_valid_inconsistent_surface_fails_gate(self) -> None:
        surface = replace(
            self._surface(),
            required_control_ids=("SEC-DEPS", "SEC-REPO"),
        )
        report = self._report(
            "5" * 32,
            surface=surface,
            coverage=(self._checked_coverage("SEC-DEPS"), self._checked_coverage()),
        )

        self.store.install(report)
        self.assertEqual(report, self.store.read_report(report.run_id))
        evaluation = self.service.gate(report.run_id)

        self.assertFalse(evaluation.passed)
        self.assertEqual(
            ("invalid_security_surface",),
            tuple(reason.code for reason in evaluation.reasons),
        )


if __name__ == "__main__":
    unittest.main()
