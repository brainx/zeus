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


def _markdown_untrusted_text(value: str) -> str:
    """Escape active Markdown/HTML syntax while keeping v1 rendering unchanged."""
    return "".join(
        f"\\{character}" if character in "![]()<>`" else character
        for character in _markdown_text(value)
    )


def _markdown_untrusted_optional(value: str | None) -> str:
    return "—" if value is None else _markdown_untrusted_text(value)


def _markdown_code_span(value: str, *, schema_version: int) -> str:
    normalized = _markdown_text(value)
    if schema_version < 2:
        return f"`{normalized}`"
    longest_run = 0
    current_run = 0
    for character in normalized:
        if character == "`":
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0
    delimiter = "`" * (longest_run + 1)
    if normalized[:1] in {"`", " "} or normalized[-1:] in {"`", " "}:
        return f"{delimiter} {normalized} {delimiter}"
    return f"{delimiter}{normalized}{delimiter}"


def _evidence_markdown(evidence: AuditEvidence, *, schema_version: int) -> str:
    text = _markdown_untrusted_text if schema_version >= 2 else _markdown_text
    if isinstance(evidence, SourceEvidence):
        lines = str(evidence.start_line)
        if evidence.end_line is not None and evidence.end_line != evidence.start_line:
            lines += f"-{evidence.end_line}"
        blob = ""
        if schema_version >= 2:
            blob = f" @ blob `{_markdown_optional(evidence.blob_sha256)}`"
        source = _markdown_code_span(
            f"{evidence.path}:{lines}",
            schema_version=schema_version,
        )
        return f"Source {source}{blob} — {text(evidence.observation)}"
    if isinstance(evidence, CheckEvidence):
        check_name = _markdown_code_span(
            evidence.check_name,
            schema_version=schema_version,
        )
        return f"Check {check_name} — {text(evidence.observation)}"
    if isinstance(evidence, RepositoryEvidence):
        return (
            f"Repository — {text(evidence.observation)} "
            f"(inspection: {text(evidence.inspection_method)})"
        )
    _error("finding contains unsupported evidence")


def _markdown_values(values: tuple[str, ...]) -> str:
    if not values:
        return "—"
    return "<br>".join(_markdown_untrusted_text(value) for value in values)


def _append_repository_surface(lines: list[str], report: AuditReport) -> None:
    lines.extend(["", "## Repository surface", ""])
    surface = report.surface
    if surface is None:
        lines.append("No authoritative repository surface recorded.")
        return
    lines.extend(
        [
            f"- Surface catalog: `{_markdown_text(surface.catalog_version)}`",
            f"- Snapshot digest: `{_markdown_text(surface.snapshot_digest)}`",
            "",
            "| Surface | Total | Deterministic sample |",
            "| --- | ---: | --- |",
            f"| Ecosystems | {len(surface.ecosystems)} | {_markdown_values(surface.ecosystems)} |",
            "| Dependency manifests | "
            f"{surface.dependency_manifest_count} | "
            f"{_markdown_values(surface.dependency_manifests)} |",
            f"| CI configuration | {surface.ci_path_count} | "
            f"{_markdown_values(surface.ci_paths)} |",
            f"| Infrastructure as code | {surface.iac_path_count} | "
            f"{_markdown_values(surface.iac_paths)} |",
            f"| Web surface | {surface.web_path_count} | {_markdown_values(surface.web_paths)} |",
        ]
    )


def _append_security_coverage(lines: list[str], report: AuditReport) -> None:
    lines.extend(
        [
            "",
            "## Security coverage",
            "",
            "| Control | Category | Required | Disposition | Receipt-backed checks | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    if report.coverage:
        lines.extend(
            f"| {_markdown_text(item.control_id)} | {item.category.value} | "
            f"{'yes' if item.required else 'no'} | {item.disposition.value} | "
            f"{_markdown_values(item.check_names)} | {_markdown_untrusted_optional(item.reason)} |"
            for item in report.coverage
        )
    else:
        lines.append("| — | — | — | — | — | No security controls recorded |")


def _append_command_receipts(lines: list[str], report: AuditReport) -> None:
    lines.extend(
        [
            "",
            "## Command receipts",
            "",
            "Receipts contain execution metadata only; raw commands and output are not stored.",
            "",
            "| Receipt | Sequence | State | Exit | Duration (ms) | Stdout (bytes) | "
            "Stderr (bytes) | Command tag |",
            "| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    if report.command_receipts:
        lines.extend(
            f"| {_markdown_text(receipt.receipt_id)} | {receipt.sequence} | "
            f"{_markdown_text(receipt.state)} | {receipt.returncode} | "
            f"{receipt.duration_ms} | {receipt.stdout_bytes} | {receipt.stderr_bytes} | "
            f"{_markdown_text(receipt.command_tag)} |"
            for receipt in report.command_receipts
        )
    else:
        lines.append("| — | — | — | — | — | — | — | No terminal receipts recorded |")


def render_audit_markdown(report: AuditReport) -> str:
    report = _normalize_report_for_sink(report)
    untrusted_text = _markdown_untrusted_text if report.schema_version >= 2 else _markdown_text
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
        *(
            [
                "- Trusted execution boundary: "
                f"{_markdown_untrusted_optional(metadata.trusted_execution_boundary)}"
            ]
            if report.schema_version >= 2
            else []
        ),
        "",
        "## Summary",
        "",
        untrusted_text(report.summary),
        "",
        "## Severity counts",
        "",
        "| Critical | High | Medium | Low | Note |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {counts.critical} | {counts.high} | {counts.medium} | {counts.low} | {counts.note} |",
    ]
    if report.schema_version >= 2:
        _append_repository_surface(lines, report)
        _append_security_coverage(lines, report)
    lines.extend(["", "## Checks", ""])
    if report.schema_version >= 2:
        lines.extend(
            [
                "| Check | Disposition | Receipt | Duration (s) | Observation |",
                "| --- | --- | --- | ---: | --- |",
            ]
        )
    else:
        lines.extend(
            [
                "| Check | Disposition | Duration (s) | Observation |",
                "| --- | --- | ---: | --- |",
            ]
        )
    if report.checks:
        if report.schema_version >= 2:
            lines.extend(
                f"| {_markdown_untrusted_text(check.name)} | {check.disposition.value} | "
                f"{_markdown_optional(check.receipt_id)} | {check.duration_seconds:.3f} | "
                f"{_markdown_untrusted_text(check.observation)} |"
                for check in report.checks
            )
        else:
            lines.extend(
                f"| {_markdown_text(check.name)} | {check.disposition.value} | "
                f"{check.duration_seconds:.3f} | {_markdown_text(check.observation)} |"
                for check in report.checks
            )
    else:
        if report.schema_version >= 2:
            lines.append("| — | — | — | — | No checks recorded |")
        else:
            lines.append("| — | — | — | No checks recorded |")
    if report.schema_version >= 2:
        _append_command_receipts(lines, report)
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
            f"| {untrusted_text(skipped.path)} | {untrusted_text(skipped.reason)} |"
            for skipped in report.skipped_content
        )
    else:
        lines.append("| — | No committed content was skipped |")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.extend(["No validated findings.", ""])
    for finding in report.findings:
        finding_lines = [
            f"### [{finding.severity.value.upper()}] {untrusted_text(finding.title)}",
            "",
            f"- ID: `{_markdown_text(finding.finding_id)}`",
            f"- Category: {finding.category.value}",
            f"- Confidence: {finding.confidence.value}",
        ]
        if report.schema_version >= 2:
            finding_lines.extend(
                [
                    f"- Control: `{_markdown_optional(finding.control_id)}`",
                    f"- Fingerprint: `{_markdown_optional(finding.fingerprint)}`",
                ]
            )
        finding_lines.extend(
            [
                f"- Impact: {untrusted_text(finding.impact)}",
                f"- Recommendation: {untrusted_text(finding.recommendation)}",
                f"- Verification: {untrusted_text(finding.verification)}",
                "- Evidence:",
            ]
        )
        lines.extend(finding_lines)
        lines.extend(
            f"  - {_evidence_markdown(evidence, schema_version=report.schema_version)}"
            for evidence in finding.evidence
        )
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
    lines.extend(f"- {untrusted_text(reason)}" for reason in report.completeness.reasons)
    return "\n".join(lines).rstrip() + "\n"
