from __future__ import annotations

from zeus.audit_models import (
    AuditEvidence,
    AuditReport,
    CheckEvidence,
    RepositoryEvidence,
    SourceEvidence,
)
from zeus.audit_report_core import (
    _error,
)
from zeus.audit_report_serialization import (
    _normalize_report_for_sink,
)


def _markdown_text(value: str) -> str:
    result: list[str] = []
    for character in value:
        if character == "\\":
            result.append("\\\\")
        elif character == "|":
            result.append(r"\|")
        elif character in {"\r", "\n"}:
            if not result or result[-1] != "<br>":
                result.append("<br>")
        elif character == "\t":
            result.append(" ")
        elif ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F:
            result.append(f"\\u{ord(character):04x}")
        else:
            result.append(character)
    return "".join(result)


def _markdown_optional(value: str | None) -> str:
    return "—" if value is None else _markdown_text(value)


def _evidence_markdown(evidence: AuditEvidence) -> str:
    if isinstance(evidence, SourceEvidence):
        lines = str(evidence.start_line)
        if evidence.end_line is not None and evidence.end_line != evidence.start_line:
            lines += f"-{evidence.end_line}"
        return (
            f"Source `{_markdown_text(evidence.path)}:{lines}` — "
            f"{_markdown_text(evidence.observation)}"
        )
    if isinstance(evidence, CheckEvidence):
        return (
            f"Check `{_markdown_text(evidence.check_name)}` — "
            f"{_markdown_text(evidence.observation)}"
        )
    if isinstance(evidence, RepositoryEvidence):
        return (
            f"Repository — {_markdown_text(evidence.observation)} "
            f"(inspection: {_markdown_text(evidence.inspection_method)})"
        )
    _error("finding contains unsupported evidence")


def render_audit_markdown(report: AuditReport) -> str:
    report = _normalize_report_for_sink(report)
    counts = report.severity_counts
    metadata = report.metadata
    lines = [
        "# Zeus Repository Audit",
        "",
        f"- Run: `{_markdown_text(report.run_id)}`",
        f"- Repository: `{_markdown_text(report.repository_id)}`",
        f"- Status: **{report.status.value}**",
        f"- Target commit: `{_markdown_optional(metadata.target_commit)}`",
        f"- Started: {_markdown_text(metadata.started_at)}",
        f"- Finished: {_markdown_text(metadata.finished_at)}",
        "",
        "## Summary",
        "",
        _markdown_text(report.summary),
        "",
        "## Severity counts",
        "",
        "| Critical | High | Medium | Low | Note |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {counts.critical} | {counts.high} | {counts.medium} | {counts.low} | {counts.note} |",
        "",
        "## Checks",
        "",
        "| Check | Disposition | Duration (s) | Observation |",
        "| --- | --- | ---: | --- |",
    ]
    if report.checks:
        lines.extend(
            f"| {_markdown_text(check.name)} | {check.disposition.value} | "
            f"{check.duration_seconds:.3f} | {_markdown_text(check.observation)} |"
            for check in report.checks
        )
    else:
        lines.append("| — | — | — | No checks recorded |")
    lines.extend(
        [
            "",
            "## Skipped content",
            "",
            "| Path or scope | Reason |",
            "| --- | --- |",
        ]
    )
    if report.skipped_content:
        lines.extend(
            f"| {_markdown_text(skipped.path)} | {_markdown_text(skipped.reason)} |"
            for skipped in report.skipped_content
        )
    else:
        lines.append("| — | No committed content was skipped |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.extend(["No validated findings.", ""])
    for finding in report.findings:
        lines.extend(
            [
                f"### [{finding.severity.value.upper()}] {_markdown_text(finding.title)}",
                "",
                f"- ID: `{_markdown_text(finding.finding_id)}`",
                f"- Category: {finding.category.value}",
                f"- Confidence: {finding.confidence.value}",
                f"- Impact: {_markdown_text(finding.impact)}",
                f"- Recommendation: {_markdown_text(finding.recommendation)}",
                f"- Verification: {_markdown_text(finding.verification)}",
                "- Evidence:",
            ]
        )
        lines.extend(f"  - {_evidence_markdown(evidence)}" for evidence in finding.evidence)
        lines.append("")
    lines.extend(["## Completeness", ""])
    if report.completeness.complete and report.skipped_content:
        lines.append("Complete within the selected snapshot scope shown above.")
    else:
        lines.append("Complete." if report.completeness.complete else "Incomplete.")
    if report.completeness.rejected_findings:
        lines.append(f"- Rejected findings: {report.completeness.rejected_findings}")
    if report.completeness.truncated_findings:
        lines.append(f"- Truncated findings: {report.completeness.truncated_findings}")
    lines.extend(f"- {_markdown_text(reason)}" for reason in report.completeness.reasons)
    return "\n".join(lines).rstrip() + "\n"
