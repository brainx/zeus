from __future__ import annotations

import json
import math
import unittest
from collections.abc import Sequence
from dataclasses import replace

from zeus.audit_models import (
    HARD_LIMITS,
    AuditCategory,
    AuditCheck,
    AuditCompleteness,
    AuditLimits,
    AuditMetadata,
    AuditReport,
    AuditStatus,
    CheckDisposition,
    CheckEvidence,
    ModelAuditResult,
    RepositoryEvidence,
    SkippedContent,
    SourceEvidence,
)
from zeus.audit_report import (
    MAX_REPORT_TEXT_BYTES,
    REPORT_SCHEMA_VERSION,
    AuditReportError,
    build_audit_report,
    parse_audit_report,
    render_audit_markdown,
    serialize_audit_report,
    validate_model_output,
)


def _limits(**changes: int) -> AuditLimits:
    return replace(HARD_LIMITS, **changes)


def _checks() -> tuple[AuditCheck, ...]:
    return (
        AuditCheck("lint", CheckDisposition.passed, 1.25, "clean"),
        AuditCheck("integration", CheckDisposition.failed, 2.5, "one failure"),
        AuditCheck("optional", CheckDisposition.skipped, 0.0, "not configured"),
    )


def _metadata() -> AuditMetadata:
    return AuditMetadata(
        zeus_version="0.4.0",
        hermes_version="0.20.0",
        skill_version="1",
        image_digest="sha256:" + "a" * 64,
        target_commit="b" * 40,
        started_at="2026-07-23T10:00:00Z",
        finished_at="2026-07-23T10:01:00Z",
        termination_reason=None,
        provider="provider",
        model="model",
        worktree_changes_excluded=True,
    )


def _finding(
    *,
    category: str = "security",
    severity: str = "high",
    title: str = "Unsafe behavior",
    evidence: list[object] | None = None,
) -> dict[str, object]:
    return {
        "category": category,
        "severity": severity,
        "confidence": "high",
        "title": title,
        "evidence": evidence
        if evidence is not None
        else [
            {
                "type": "source",
                "path": "zeus/example.py",
                "start_line": 2,
                "end_line": 3,
                "observation": "unsafe call",
            }
        ],
        "impact": "could fail closed",
        "recommendation": "validate the boundary",
        "verification": "run the focused test",
    }


def _model_bytes(
    findings: Sequence[object],
    *,
    summary: str = "Audit complete",
    skipped_checks: Sequence[object] | None = None,
) -> bytes:
    return json.dumps(
        {
            "summary": summary,
            "findings": findings,
            "skipped_checks": [] if skipped_checks is None else skipped_checks,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _validate(data: bytes, **changes: object) -> ModelAuditResult:
    arguments = {
        "run_id": "run-123",
        "allowed_categories": frozenset(AuditCategory),
        "source_line_counts": {"zeus/example.py": 12, "README.md": 4},
        "checks": _checks(),
        "limits": HARD_LIMITS,
    }
    arguments.update(changes)
    return validate_model_output(data, **arguments)  # type: ignore[arg-type]


class ModelOutputValidationTests(unittest.TestCase):
    def test_validates_all_evidence_variants_and_assigns_stable_ids(self) -> None:
        findings: list[object] = [
            _finding(),
            _finding(
                category="tests",
                severity="medium",
                title="Check evidence",
                evidence=[
                    {
                        "type": "check",
                        "check_name": "integration",
                        "observation": "focused failure",
                    }
                ],
            ),
            _finding(
                category="architecture",
                severity="note",
                title="Repository evidence",
                evidence=[
                    {
                        "type": "repository",
                        "observation": "no ownership document",
                        "inspection_method": "listed committed root files",
                    }
                ],
            ),
        ]

        first = _validate(_model_bytes(findings, skipped_checks=["optional"]))
        second = _validate(_model_bytes(findings, skipped_checks=["optional"]))

        self.assertEqual(first, second)
        self.assertTrue(first.completeness.complete)
        self.assertEqual(("optional",), first.skipped_checks)
        self.assertEqual(3, len(first.findings))
        self.assertEqual(3, len({finding.finding_id for finding in first.findings}))
        self.assertIsInstance(first.findings[0].evidence[0], SourceEvidence)
        self.assertIsInstance(first.findings[1].evidence[0], CheckEvidence)
        self.assertIsInstance(first.findings[2].evidence[0], RepositoryEvidence)

    def test_top_level_schema_duplicate_keys_nonfinite_and_utf8_are_rejected(self) -> None:
        invalid_documents = (
            b"null",
            b"{}",
            b'{"summary":"ok","findings":[],"skipped_checks":[],"extra":true}',
            b'{"summary":"a","summary":"b","findings":[],"skipped_checks":[]}',
            b'{"summary":"ok","findings":[],"skipped_checks":[],"x":NaN}',
            b'{"summary":"ok","findings":[],"skipped_checks":[],"x":Infinity}',
            b'{"summary":"ok","findings":[],"skipped_checks":[],"x":-Infinity}',
            b'{"summary":"\\ud800","findings":[],"skipped_checks":[]}',
            b'{"summary":"\xff","findings":[],"skipped_checks":[]}',
        )
        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(AuditReportError):
                _validate(document)

        with self.assertRaises(AuditReportError):
            _validate(
                _model_bytes([]),
                limits=_limits(model_output_bytes=len(_model_bytes([])) - 1),
            )

    def test_findings_are_validated_independently(self) -> None:
        result = _validate(
            _model_bytes(
                [
                    _finding(title="kept first"),
                    {"category": "security"},
                    _finding(title="kept second", severity="low"),
                ]
            )
        )

        self.assertEqual(
            ["kept first", "kept second"],
            [finding.title for finding in result.findings],
        )
        self.assertFalse(result.completeness.complete)
        self.assertEqual(1, result.completeness.rejected_findings)
        self.assertEqual(0, result.completeness.truncated_findings)
        self.assertIn("1 invalid finding was rejected", result.completeness.reasons)

    def test_finding_and_evidence_schemas_are_exact(self) -> None:
        invalid_findings: list[object] = [
            [],
            {**_finding(), "extra": True},
            {**_finding(), "category": "dependencies"},
            {**_finding(), "severity": "urgent"},
            {**_finding(), "confidence": "certain"},
            {**_finding(), "title": ""},
            {**_finding(), "evidence": []},
            {**_finding(), "evidence": [_finding()["evidence"][0]] * 5},  # type: ignore[index]
            {
                **_finding(),
                "evidence": [
                    {
                        "type": "source",
                        "path": "zeus/example.py",
                        "start_line": 1,
                        "observation": "x",
                        "extra": True,
                    }
                ],
            },
            {
                **_finding(),
                "evidence": [{"type": "unknown", "observation": "x"}],
            },
        ]
        for finding in invalid_findings:
            with self.subTest(finding=finding):
                result = _validate(
                    _model_bytes([finding]),
                    allowed_categories=frozenset({AuditCategory.security}),
                )
                self.assertEqual((), result.findings)
                self.assertEqual(1, result.completeness.rejected_findings)

    def test_source_evidence_must_reference_verified_text_and_existing_lines(self) -> None:
        without_end_line = _finding(
            evidence=[
                {
                    "type": "source",
                    "path": "zeus/example.py",
                    "start_line": 2,
                    "observation": "single line",
                }
            ]
        )
        accepted = _validate(_model_bytes([without_end_line]))
        self.assertEqual(1, len(accepted.findings))
        self.assertIsNone(accepted.findings[0].evidence[0].end_line)  # type: ignore[union-attr]

        invalid_sources = (
            "/etc/passwd",
            "../secret",
            "zeus\\example.py",
            ".git/config",
            "missing.py",
            "assets/binary.bin",
            "vendor/excluded.py",
        )
        for path in invalid_sources:
            with self.subTest(path=path):
                finding = _finding(
                    evidence=[
                        {
                            "type": "source",
                            "path": path,
                            "start_line": 1,
                            "end_line": 1,
                            "observation": "claim",
                        }
                    ]
                )
                result = _validate(_model_bytes([finding]))
                self.assertEqual((), result.findings)

        for start, end in ((0, None), (13, None), (4, 3), (1, 13), (True, None)):
            with self.subTest(start=start, end=end):
                finding = _finding(
                    evidence=[
                        {
                            "type": "source",
                            "path": "zeus/example.py",
                            "start_line": start,
                            "end_line": end,
                            "observation": "claim",
                        }
                    ]
                )
                result = _validate(_model_bytes([finding]))
                self.assertEqual((), result.findings)

    def test_source_evidence_rejects_paths_that_would_be_redacted(self) -> None:
        secret = "path-secret"
        secret_path = f"src/token={secret}.py"
        finding = _finding(
            evidence=[
                {
                    "type": "source",
                    "path": secret_path,
                    "start_line": 1,
                    "end_line": None,
                    "observation": "claim",
                }
            ]
        )

        result = _validate(
            _model_bytes([finding]),
            source_line_counts={secret_path: 2},
        )

        self.assertEqual((), result.findings)
        self.assertEqual(1, result.completeness.rejected_findings)
        self.assertNotIn(secret, repr(result))

    def test_check_and_repository_evidence_must_be_verifiable(self) -> None:
        invalid_evidence = (
            {"type": "check", "check_name": "missing", "observation": "claim"},
            {"type": "check", "check_name": "", "observation": "claim"},
            {
                "type": "repository",
                "observation": "no tests",
                "inspection_method": "",
            },
            {"type": "repository", "observation": "no tests"},
        )
        for evidence in invalid_evidence:
            with self.subTest(evidence=evidence):
                result = _validate(_model_bytes([_finding(evidence=[evidence])]))
                self.assertEqual((), result.findings)

    def test_skipped_checks_are_strict_unique_and_reference_skipped_records(self) -> None:
        invalid: tuple[list[object], ...] = (
            ["missing"],
            ["lint"],
            ["optional", "optional"],
            [1],
        )
        for skipped in invalid:
            with self.subTest(skipped=skipped), self.assertRaises(AuditReportError):
                _validate(_model_bytes([], skipped_checks=skipped))

    def test_every_stored_model_string_is_redacted_before_return(self) -> None:
        secret = "secret-value"
        result = _validate(
            _model_bytes(
                [
                    _finding(
                        title=f"API_KEY={secret}",
                        evidence=[
                            {
                                "type": "repository",
                                "observation": f"Bearer {secret}",
                                "inspection_method": f"token={secret}",
                            }
                        ],
                    )
                ],
                summary=f"PASSWORD={secret}",
                skipped_checks=["optional"],
            )
        )

        self.assertNotIn(secret, repr(result))
        self.assertIn("[redacted]", repr(result))

    def test_utf8_field_caps_are_bytes_and_any_truncation_marks_loss(self) -> None:
        oversized = "🧪" * (MAX_REPORT_TEXT_BYTES // 4 + 2)
        result = _validate(_model_bytes([_finding(title=oversized)]))

        self.assertEqual(1, len(result.findings))
        self.assertLessEqual(len(result.findings[0].title.encode()), MAX_REPORT_TEXT_BYTES)
        self.assertFalse(result.completeness.complete)
        self.assertIn("stored text was truncated to byte limits", result.completeness.reasons)

    def test_excess_findings_are_truncated_after_validation(self) -> None:
        result = _validate(
            _model_bytes([_finding(title=f"finding {index}") for index in range(3)]),
            limits=_limits(findings=2),
        )

        self.assertEqual(["finding 0", "finding 1"], [finding.title for finding in result.findings])
        self.assertEqual(1, result.completeness.truncated_findings)
        self.assertFalse(result.completeness.complete)
        self.assertIn("1 valid finding was truncated", result.completeness.reasons)


class AuditReportTests(unittest.TestCase):
    def _model_result(
        self,
        findings: Sequence[object] | None = None,
    ) -> ModelAuditResult:
        return _validate(_model_bytes([_finding()] if findings is None else findings))

    def _report(
        self,
        *,
        status: AuditStatus = AuditStatus.completed,
        model_result: ModelAuditResult | None = None,
    ) -> AuditReport:
        return build_audit_report(
            run_id="run-123",
            repository_id="repo-456",
            status=status,
            metadata=_metadata(),
            checks=_checks(),
            skipped_content=(SkippedContent("vendor", "excluded by config"),),
            model_result=self._model_result() if model_result is None else model_result,
        )

    def test_build_sorts_findings_and_computes_counts(self) -> None:
        result = self._model_result(
            [
                _finding(category="tests", severity="low", title="Zulu"),
                _finding(category="security", severity="critical", title="Later"),
                _finding(category="architecture", severity="critical", title="First"),
                _finding(category="security", severity="high", title="Alpha"),
                _finding(category="security", severity="high", title="Alpha"),
            ]
        )

        report = self._report(model_result=result)

        self.assertEqual(
            [
                ("critical", "architecture", "First"),
                ("critical", "security", "Later"),
                ("high", "security", "Alpha"),
                ("high", "security", "Alpha"),
                ("low", "tests", "Zulu"),
            ],
            [
                (finding.severity.value, finding.category.value, finding.title)
                for finding in report.findings
            ],
        )
        self.assertEqual(2, report.severity_counts.critical)
        self.assertEqual(2, report.severity_counts.high)
        self.assertEqual(0, report.severity_counts.medium)
        self.assertEqual(1, report.severity_counts.low)
        self.assertEqual(0, report.severity_counts.note)

    def test_incomplete_results_cannot_have_completed_status(self) -> None:
        incomplete = ModelAuditResult(
            summary="partial",
            findings=(),
            skipped_checks=(),
            completeness=AuditCompleteness(
                complete=False,
                rejected_findings=1,
                reasons=("1 invalid finding was rejected",),
            ),
        )

        report = self._report(status=AuditStatus.completed, model_result=incomplete)

        self.assertEqual(AuditStatus.partial, report.status)
        self.assertFalse(report.completeness.complete)

    def test_unexplained_incompleteness_gets_an_authoritative_reason(self) -> None:
        incomplete = replace(
            self._model_result(),
            completeness=AuditCompleteness(complete=False),
        )

        report = self._report(status=AuditStatus.completed, model_result=incomplete)

        self.assertEqual(AuditStatus.partial, report.status)
        self.assertEqual(
            ("model result reported incomplete",),
            report.completeness.reasons,
        )

    def test_build_rejects_negative_completeness_counters(self) -> None:
        invalid_completeness = (
            replace(
                self._model_result().completeness,
                rejected_findings=-1,
            ),
            replace(
                self._model_result().completeness,
                truncated_findings=-1,
            ),
        )
        for completeness in invalid_completeness:
            with self.subTest(completeness=completeness):
                model_result = replace(
                    self._model_result(),
                    completeness=completeness,
                )
                with self.assertRaises(AuditReportError):
                    self._report(
                        status=AuditStatus.completed,
                        model_result=model_result,
                    )

    def test_build_redacts_authoritative_non_model_strings(self) -> None:
        secret = "persisted-secret"
        metadata = replace(
            _metadata(),
            provider=f"API_KEY={secret}",
            termination_reason=f"Bearer {secret}",
        )
        report = build_audit_report(
            run_id="run-123",
            repository_id="repo-456",
            status=AuditStatus.completed,
            metadata=metadata,
            checks=(AuditCheck("lint", CheckDisposition.failed, 0.5, f"token={secret}"),),
            skipped_content=(SkippedContent("vendor", f"PASSWORD={secret}"),),
            model_result=self._model_result(),
        )

        self.assertNotIn(secret, repr(report))
        self.assertIn("[redacted]", repr(report))

    def test_completeness_reasons_and_direct_render_sinks_are_redacted(self) -> None:
        secret = "sink-secret"
        incomplete = replace(
            self._model_result(),
            completeness=AuditCompleteness(
                complete=False,
                reasons=(f"PASSWORD={secret}",),
            ),
        )
        report = self._report(status=AuditStatus.partial, model_result=incomplete)
        self.assertNotIn(secret, repr(report))

        untrusted = replace(report, summary=f"token={secret}")
        serialized = serialize_audit_report(untrusted)
        markdown = render_audit_markdown(untrusted)
        self.assertNotIn(secret, serialized.decode())
        self.assertNotIn(secret, markdown)
        self.assertIn("[redacted]", serialized.decode())
        self.assertIn("[redacted]", markdown)

    def test_json_is_canonical_and_stored_envelope_round_trips(self) -> None:
        report = self._report()

        serialized = serialize_audit_report(report)
        decoded = json.loads(serialized)

        self.assertEqual(REPORT_SCHEMA_VERSION, decoded["schema_version"])
        self.assertEqual(
            serialized,
            json.dumps(
                decoded,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
        )
        self.assertEqual(report, parse_audit_report(serialized, max_bytes=len(serialized)))

    def test_stored_envelope_rejects_size_duplicates_nonfinite_and_schema_drift(self) -> None:
        serialized = serialize_audit_report(self._report())
        with self.assertRaises(AuditReportError):
            parse_audit_report(serialized, max_bytes=len(serialized) - 1)

        decoded = json.loads(serialized)
        decoded["extra"] = True
        with self.assertRaises(AuditReportError):
            parse_audit_report(json.dumps(decoded).encode(), max_bytes=HARD_LIMITS.artifact_bytes)

        for document in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":NaN}',
            b'{"schema_version":Infinity}',
            b'{"schema_version":-Infinity}',
            b"\xff",
        ):
            with self.subTest(document=document), self.assertRaises(AuditReportError):
                parse_audit_report(document, max_bytes=HARD_LIMITS.artifact_bytes)

    def test_source_paths_requiring_redaction_are_rejected_at_every_sink(self) -> None:
        secret = "path-secret"
        secret_path = f"src/token={secret}.py"
        report = self._report()
        original_evidence = report.findings[0].evidence[0]
        self.assertIsInstance(original_evidence, SourceEvidence)
        assert isinstance(original_evidence, SourceEvidence)
        evidence = replace(original_evidence, path=secret_path)
        finding = replace(report.findings[0], evidence=(evidence,))
        untrusted = replace(report, findings=(finding,))

        with self.assertRaises(AuditReportError):
            serialize_audit_report(untrusted)
        with self.assertRaises(AuditReportError):
            render_audit_markdown(untrusted)

        decoded = json.loads(serialize_audit_report(report))
        decoded["findings"][0]["evidence"][0]["path"] = secret_path
        with self.assertRaises(AuditReportError):
            parse_audit_report(
                json.dumps(decoded).encode(),
                max_bytes=HARD_LIMITS.artifact_bytes,
            )

    def test_source_line_invariants_are_enforced_by_json_and_markdown_sinks(self) -> None:
        report = self._report()
        invalid_ranges = (
            (0, None),
            (-1, None),
            (2, 0),
            (3, 2),
        )
        for start_line, end_line in invalid_ranges:
            with self.subTest(start_line=start_line, end_line=end_line):
                original_evidence = report.findings[0].evidence[0]
                self.assertIsInstance(original_evidence, SourceEvidence)
                assert isinstance(original_evidence, SourceEvidence)
                evidence = replace(
                    original_evidence,
                    start_line=start_line,
                    end_line=end_line,
                )
                finding = replace(report.findings[0], evidence=(evidence,))
                invalid = replace(report, findings=(finding,))
                with self.assertRaises(AuditReportError):
                    serialize_audit_report(invalid)
                with self.assertRaises(AuditReportError):
                    render_audit_markdown(invalid)

        serialized = serialize_audit_report(report)
        self.assertEqual(
            report,
            parse_audit_report(serialized, max_bytes=len(serialized)),
        )

    def test_parse_rejects_invalid_stored_counts_and_completeness_invariants(self) -> None:
        decoded = json.loads(serialize_audit_report(self._report()))
        decoded["severity_counts"]["high"] = 999
        with self.assertRaises(AuditReportError):
            parse_audit_report(json.dumps(decoded).encode(), max_bytes=HARD_LIMITS.artifact_bytes)

        for status in ("partial", "completed"):
            with self.subTest(status=status):
                decoded = json.loads(serialize_audit_report(self._report()))
                decoded["completeness"]["complete"] = False
                decoded["status"] = status
                with self.assertRaises(AuditReportError):
                    parse_audit_report(
                        json.dumps(decoded).encode(),
                        max_bytes=HARD_LIMITS.artifact_bytes,
                    )

    def test_noncanonical_check_and_skipped_content_order_is_rejected(self) -> None:
        report = build_audit_report(
            run_id="run-123",
            repository_id="repo-456",
            status=AuditStatus.completed,
            metadata=_metadata(),
            checks=_checks(),
            skipped_content=(
                SkippedContent("z-last", "excluded"),
                SkippedContent("a-first", "excluded"),
            ),
            model_result=self._model_result(),
        )
        self.assertEqual(
            ["a-first", "z-last"],
            [item.path for item in report.skipped_content],
        )

        for field in ("checks", "skipped_content"):
            with self.subTest(field=field):
                decoded = json.loads(serialize_audit_report(report))
                decoded[field].reverse()
                with self.assertRaises(AuditReportError):
                    parse_audit_report(
                        json.dumps(decoded).encode(),
                        max_bytes=HARD_LIMITS.artifact_bytes,
                    )

        with self.assertRaises(AuditReportError):
            serialize_audit_report(replace(report, checks=tuple(reversed(report.checks))))
        with self.assertRaises(AuditReportError):
            serialize_audit_report(
                replace(
                    report,
                    skipped_content=tuple(reversed(report.skipped_content)),
                )
            )

    def test_serializer_rejects_unverified_check_evidence(self) -> None:
        report = self._report()
        finding = replace(
            report.findings[0],
            evidence=(CheckEvidence("missing", "unverified"),),
        )
        report = replace(
            report,
            findings=(finding,),
            severity_counts=replace(
                report.severity_counts,
                high=1,
            ),
        )

        with self.assertRaises(AuditReportError):
            serialize_audit_report(report)

    def test_markdown_is_deterministic_and_escapes_controls_and_table_delimiters(self) -> None:
        result = _validate(
            _model_bytes(
                [
                    _finding(
                        title="Zulu | row\nnext",
                        evidence=[
                            {
                                "type": "check",
                                "check_name": "integration",
                                "observation": "line | one\nline two\tend",
                            }
                        ],
                    ),
                    _finding(severity="critical", title="Alpha"),
                ],
                summary="Summary | value\nnext\u0085control",
            )
        )
        report = self._report(model_result=result)

        first = render_audit_markdown(report)
        second = render_audit_markdown(report)

        self.assertEqual(first, second)
        self.assertLess(first.index("Alpha"), first.index("Zulu"))
        self.assertIn(r"\|", first)
        self.assertNotIn("\t", first)
        self.assertNotIn("\u0085", first)
        self.assertIn(r"\u0085", first)
        self.assertNotIn("Zulu | row", first)
        self.assertIn("run-123", first)

    def test_serializer_rejects_nonfinite_duration(self) -> None:
        report = replace(
            self._report(),
            checks=(AuditCheck("lint", CheckDisposition.passed, math.nan, "bad"),),
        )
        with self.assertRaises(AuditReportError):
            serialize_audit_report(report)

    def test_boolean_duration_is_rejected_by_build_serialize_and_parse(self) -> None:
        boolean_check = AuditCheck(
            "lint",
            CheckDisposition.passed,
            True,
            "not a numeric duration",
        )
        with self.subTest(boundary="build"), self.assertRaises(AuditReportError):
            build_audit_report(
                run_id="run-123",
                repository_id="repo-456",
                status=AuditStatus.completed,
                metadata=_metadata(),
                checks=(boolean_check,),
                skipped_content=(),
                model_result=self._model_result(),
            )

        report = replace(self._report(), checks=(boolean_check,))
        with self.subTest(boundary="serialize"), self.assertRaises(AuditReportError):
            serialize_audit_report(report)

        decoded = json.loads(serialize_audit_report(self._report()))
        decoded["checks"][0]["duration_seconds"] = True
        with self.assertRaises(AuditReportError):
            parse_audit_report(
                json.dumps(decoded).encode(),
                max_bytes=HARD_LIMITS.artifact_bytes,
            )


if __name__ == "__main__":
    unittest.main()
