from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace

from zeus.audit_models import (
    AuditCategory,
    AuditCheck,
    AuditCompleteness,
    AuditConfidence,
    AuditEvidence,
    AuditFinding,
    AuditMetadata,
    AuditReport,
    AuditSeverity,
    AuditStatus,
    CheckDisposition,
    CheckEvidence,
    ModelAuditResult,
    RepositoryEvidence,
    SeverityCounts,
    SkippedContent,
    SourceEvidence,
)
from zeus.audit_report_core import (
    _CHECK_EVIDENCE_FIELDS,
    _CHECK_FIELDS,
    _COMPLETENESS_FIELDS,
    _COUNTS_FIELDS,
    _METADATA_FIELDS,
    _REPORT_FIELDS,
    _REPOSITORY_EVIDENCE_FIELDS,
    _SKIPPED_CONTENT_FIELDS,
    _SOURCE_EVIDENCE_FIELDS,
    _STORED_FINDING_FIELDS,
    REPORT_SCHEMA_VERSION,
    AuditReportError,
    _check_duration_seconds,
    _enum_value,
    _error,
    _exact_object,
    _load_json,
    _relative_source_path,
    _sanitize_finding,
    _sanitize_metadata,
    _sanitize_report_text,
    _severity_counts,
    _sort_findings,
    _stored_text,
    _strict_bool,
    _strict_int,
)


def build_audit_report(
    *,
    run_id: str,
    repository_id: str,
    status: AuditStatus,
    metadata: AuditMetadata,
    checks: Sequence[AuditCheck],
    skipped_content: Sequence[SkippedContent],
    model_result: ModelAuditResult,
) -> AuditReport:
    _strict_int(
        model_result.completeness.rejected_findings,
        "rejected_findings",
    )
    _strict_int(
        model_result.completeness.truncated_findings,
        "truncated_findings",
    )
    safe_run_id, run_id_truncated = _sanitize_report_text(run_id, "run_id")
    safe_repository_id, repository_truncated = _sanitize_report_text(repository_id, "repository_id")
    safe_metadata, metadata_truncated = _sanitize_metadata(metadata)
    summary, summary_truncated = _sanitize_report_text(model_result.summary, "summary")

    safe_checks: list[AuditCheck] = []
    check_truncated = False
    for check in checks:
        duration_seconds = _check_duration_seconds(check.duration_seconds)
        name, name_truncated = _sanitize_report_text(check.name, "check name")
        observation, observation_truncated = _sanitize_report_text(
            check.observation, "check observation", allow_empty=True
        )
        safe_checks.append(
            replace(
                check,
                name=name,
                duration_seconds=duration_seconds,
                observation=observation,
            )
        )
        check_truncated = check_truncated or name_truncated or observation_truncated
    safe_checks.sort(key=lambda check: check.name)
    if len({check.name for check in safe_checks}) != len(safe_checks):
        _error("check names must be unique")

    safe_skipped: list[SkippedContent] = []
    skipped_truncated = False
    for skipped in skipped_content:
        path, path_truncated = _sanitize_report_text(skipped.path, "skipped content path")
        reason, reason_truncated = _sanitize_report_text(skipped.reason, "skipped content reason")
        safe_skipped.append(replace(skipped, path=path, reason=reason))
        skipped_truncated = skipped_truncated or path_truncated or reason_truncated
    safe_skipped.sort(key=lambda skipped: (skipped.path, skipped.reason))

    safe_findings: list[AuditFinding] = []
    finding_truncated = False
    for finding in model_result.findings:
        safe_finding, truncated = _sanitize_finding(finding)
        safe_findings.append(safe_finding)
        finding_truncated = finding_truncated or truncated
    sorted_findings = _sort_findings(safe_findings)

    reasons: list[str] = []
    reasons_truncated = False
    for reason in model_result.completeness.reasons:
        safe_reason, reason_truncated = _sanitize_report_text(reason, "completeness reason")
        if safe_reason in reasons:
            _error("completeness reasons must be unique")
        reasons.append(safe_reason)
        reasons_truncated = reasons_truncated or reason_truncated
    if (
        not model_result.completeness.complete
        and model_result.completeness.rejected_findings == 0
        and model_result.completeness.truncated_findings == 0
        and not reasons
    ):
        reasons.append("model result reported incomplete")
    any_text_truncated = any(
        (
            run_id_truncated,
            repository_truncated,
            metadata_truncated,
            summary_truncated,
            check_truncated,
            skipped_truncated,
            finding_truncated,
            reasons_truncated,
        )
    )
    if any_text_truncated and "stored text was truncated to byte limits" not in reasons:
        reasons.append("stored text was truncated to byte limits")
    has_recorded_loss = (
        model_result.completeness.rejected_findings > 0
        or model_result.completeness.truncated_findings > 0
        or bool(reasons)
    )
    complete = model_result.completeness.complete and not has_recorded_loss
    completeness = AuditCompleteness(
        complete=complete,
        rejected_findings=model_result.completeness.rejected_findings,
        truncated_findings=model_result.completeness.truncated_findings,
        reasons=tuple(reasons),
    )
    if status is AuditStatus.completed and not completeness.complete:
        status = AuditStatus.partial
    report = AuditReport(
        schema_version=REPORT_SCHEMA_VERSION,
        run_id=safe_run_id,
        repository_id=safe_repository_id,
        status=status,
        metadata=safe_metadata,
        summary=summary,
        checks=tuple(safe_checks),
        skipped_content=tuple(safe_skipped),
        findings=sorted_findings,
        severity_counts=_severity_counts(sorted_findings),
        completeness=completeness,
    )
    _validate_report_invariants(report)
    return report


def _evidence_value(evidence: AuditEvidence) -> dict[str, object]:
    if isinstance(evidence, SourceEvidence):
        return {
            "type": "source",
            "path": evidence.path,
            "start_line": evidence.start_line,
            "end_line": evidence.end_line,
            "observation": evidence.observation,
        }
    if isinstance(evidence, CheckEvidence):
        return {
            "type": "check",
            "check_name": evidence.check_name,
            "observation": evidence.observation,
        }
    if isinstance(evidence, RepositoryEvidence):
        return {
            "type": "repository",
            "observation": evidence.observation,
            "inspection_method": evidence.inspection_method,
        }
    _error("finding contains unsupported evidence")


def _report_value(report: AuditReport) -> dict[str, object]:
    metadata = report.metadata
    counts = report.severity_counts
    completeness = report.completeness
    return {
        "schema_version": report.schema_version,
        "run_id": report.run_id,
        "repository_id": report.repository_id,
        "status": report.status.value,
        "metadata": {
            "zeus_version": metadata.zeus_version,
            "hermes_version": metadata.hermes_version,
            "skill_version": metadata.skill_version,
            "image_digest": metadata.image_digest,
            "target_commit": metadata.target_commit,
            "started_at": metadata.started_at,
            "finished_at": metadata.finished_at,
            "termination_reason": metadata.termination_reason,
            "provider": metadata.provider,
            "model": metadata.model,
            "worktree_changes_excluded": metadata.worktree_changes_excluded,
        },
        "summary": report.summary,
        "checks": [
            {
                "name": check.name,
                "disposition": check.disposition.value,
                "duration_seconds": check.duration_seconds,
                "observation": check.observation,
            }
            for check in report.checks
        ],
        "skipped_content": [
            {"path": skipped.path, "reason": skipped.reason} for skipped in report.skipped_content
        ],
        "findings": [
            {
                "finding_id": finding.finding_id,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "title": finding.title,
                "evidence": [_evidence_value(evidence) for evidence in finding.evidence],
                "impact": finding.impact,
                "recommendation": finding.recommendation,
                "verification": finding.verification,
            }
            for finding in report.findings
        ],
        "severity_counts": {
            "critical": counts.critical,
            "high": counts.high,
            "medium": counts.medium,
            "low": counts.low,
            "note": counts.note,
        },
        "completeness": {
            "complete": completeness.complete,
            "rejected_findings": completeness.rejected_findings,
            "truncated_findings": completeness.truncated_findings,
            "reasons": list(completeness.reasons),
        },
    }


def _validate_report_invariants(report: AuditReport) -> None:
    if report.schema_version != REPORT_SCHEMA_VERSION:
        _error(f"report schema_version must be exactly {REPORT_SCHEMA_VERSION}")
    if report.findings != _sort_findings(report.findings):
        _error("report findings are not in canonical order")
    if report.checks != tuple(sorted(report.checks, key=lambda check: check.name)):
        _error("report checks are not in canonical order")
    if report.skipped_content != tuple(
        sorted(
            report.skipped_content,
            key=lambda skipped: (skipped.path, skipped.reason),
        )
    ):
        _error("report skipped content is not in canonical order")
    if report.severity_counts != _severity_counts(report.findings):
        _error("report severity counts do not match findings")
    if len({finding.finding_id for finding in report.findings}) != len(report.findings):
        _error("report finding IDs must be unique")
    completeness = report.completeness
    if completeness.rejected_findings < 0 or completeness.truncated_findings < 0:
        _error("report completeness counts must be non-negative")
    has_loss = (
        completeness.rejected_findings > 0
        or completeness.truncated_findings > 0
        or bool(completeness.reasons)
    )
    if completeness.complete and has_loss:
        _error("a complete report cannot record loss")
    if not completeness.complete and not has_loss:
        _error("an incomplete report must record a reason for its loss")
    if report.status is AuditStatus.completed and not completeness.complete:
        _error("a completed report must be complete")
    check_names = {check.name for check in report.checks}
    if len(check_names) != len(report.checks):
        _error("report check names must be unique")
    for check in report.checks:
        _check_duration_seconds(check.duration_seconds)
    for finding in report.findings:
        for evidence in finding.evidence:
            if isinstance(evidence, SourceEvidence):
                _relative_source_path(evidence.path)
                if type(evidence.start_line) is not int or evidence.start_line < 1:
                    _error("source evidence start_line must be a positive integer")
                if evidence.end_line is not None and (
                    type(evidence.end_line) is not int or evidence.end_line < evidence.start_line
                ):
                    _error("source evidence end_line must not precede start_line")
            elif isinstance(evidence, CheckEvidence) and evidence.check_name not in check_names:
                _error("check evidence must reference a recorded check")


def _normalize_report_for_sink(report: AuditReport) -> AuditReport:
    _validate_report_invariants(report)
    normalized = build_audit_report(
        run_id=report.run_id,
        repository_id=report.repository_id,
        status=report.status,
        metadata=report.metadata,
        checks=report.checks,
        skipped_content=report.skipped_content,
        model_result=ModelAuditResult(
            summary=report.summary,
            findings=report.findings,
            skipped_checks=(),
            checks=(),
            completeness=report.completeness,
        ),
    )
    _validate_report_invariants(normalized)
    return normalized


def serialize_audit_report(report: AuditReport) -> bytes:
    value = _report_value(_normalize_report_for_sink(report))
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError) as exc:
        raise AuditReportError("report cannot be serialized as canonical JSON") from exc


def _stored_optional(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _stored_text(value, name)


def _parse_metadata(value: object) -> AuditMetadata:
    metadata = _exact_object(value, _METADATA_FIELDS, "report metadata")
    return AuditMetadata(
        zeus_version=_stored_text(metadata["zeus_version"], "metadata zeus_version"),
        hermes_version=_stored_optional(metadata["hermes_version"], "metadata hermes_version"),
        skill_version=_stored_optional(metadata["skill_version"], "metadata skill_version"),
        image_digest=_stored_optional(metadata["image_digest"], "metadata image_digest"),
        target_commit=_stored_optional(metadata["target_commit"], "metadata target_commit"),
        started_at=_stored_text(metadata["started_at"], "metadata started_at"),
        finished_at=_stored_text(metadata["finished_at"], "metadata finished_at"),
        termination_reason=_stored_optional(
            metadata["termination_reason"], "metadata termination_reason"
        ),
        provider=_stored_optional(metadata["provider"], "metadata provider"),
        model=_stored_optional(metadata["model"], "metadata model"),
        worktree_changes_excluded=_strict_bool(
            metadata["worktree_changes_excluded"], "metadata worktree_changes_excluded"
        ),
    )


def _parse_check(value: object) -> AuditCheck:
    check = _exact_object(value, _CHECK_FIELDS, "report check")
    return AuditCheck(
        name=_stored_text(check["name"], "check name"),
        disposition=_enum_value(CheckDisposition, check["disposition"], "check disposition"),
        duration_seconds=_check_duration_seconds(check["duration_seconds"]),
        observation=_stored_text(check["observation"], "check observation", allow_empty=True),
    )


def _parse_skipped_content(value: object) -> SkippedContent:
    skipped = _exact_object(value, _SKIPPED_CONTENT_FIELDS, "skipped content")
    return SkippedContent(
        path=_stored_text(skipped["path"], "skipped content path"),
        reason=_stored_text(skipped["reason"], "skipped content reason"),
    )


def _parse_stored_evidence(value: object) -> AuditEvidence:
    if not isinstance(value, dict):
        _error("stored evidence must be an object")
    evidence_type = value.get("type")
    if evidence_type == "source":
        source = _exact_object(value, _SOURCE_EVIDENCE_FIELDS, "stored source evidence")
        path = _relative_source_path(source["path"])
        start_line = _strict_int(source["start_line"], "source start_line", minimum=1)
        end_value = source["end_line"]
        end_line = (
            None if end_value is None else _strict_int(end_value, "source end_line", minimum=1)
        )
        if end_line is not None and end_line < start_line:
            _error("source end_line must not precede start_line")
        return SourceEvidence(
            path=path,
            start_line=start_line,
            end_line=end_line,
            observation=_stored_text(source["observation"], "source observation"),
        )
    if evidence_type == "check":
        check = _exact_object(value, _CHECK_EVIDENCE_FIELDS, "stored check evidence")
        return CheckEvidence(
            check_name=_stored_text(check["check_name"], "evidence check_name"),
            observation=_stored_text(check["observation"], "check observation"),
        )
    if evidence_type == "repository":
        repository = _exact_object(
            value,
            _REPOSITORY_EVIDENCE_FIELDS,
            "stored repository evidence",
        )
        return RepositoryEvidence(
            observation=_stored_text(repository["observation"], "repository observation"),
            inspection_method=_stored_text(
                repository["inspection_method"], "repository inspection_method"
            ),
        )
    _error("stored evidence has an unsupported type")


def _parse_stored_finding(value: object) -> AuditFinding:
    finding = _exact_object(value, _STORED_FINDING_FIELDS, "stored finding")
    evidence_value = finding["evidence"]
    if not isinstance(evidence_value, list) or not 1 <= len(evidence_value) <= 4:
        _error("stored finding must contain between one and four evidence entries")
    return AuditFinding(
        finding_id=_stored_text(finding["finding_id"], "finding_id"),
        category=_enum_value(AuditCategory, finding["category"], "finding category"),
        severity=_enum_value(AuditSeverity, finding["severity"], "finding severity"),
        confidence=_enum_value(AuditConfidence, finding["confidence"], "finding confidence"),
        title=_stored_text(finding["title"], "finding title"),
        evidence=tuple(_parse_stored_evidence(item) for item in evidence_value),
        impact=_stored_text(finding["impact"], "finding impact"),
        recommendation=_stored_text(finding["recommendation"], "finding recommendation"),
        verification=_stored_text(finding["verification"], "finding verification"),
    )


def _parse_counts(value: object) -> SeverityCounts:
    counts = _exact_object(value, _COUNTS_FIELDS, "severity counts")
    return SeverityCounts(
        critical=_strict_int(counts["critical"], "critical count"),
        high=_strict_int(counts["high"], "high count"),
        medium=_strict_int(counts["medium"], "medium count"),
        low=_strict_int(counts["low"], "low count"),
        note=_strict_int(counts["note"], "note count"),
    )


def _parse_completeness(value: object) -> AuditCompleteness:
    completeness = _exact_object(value, _COMPLETENESS_FIELDS, "report completeness")
    reasons_value = completeness["reasons"]
    if not isinstance(reasons_value, list):
        _error("completeness reasons must be a list")
    reasons = tuple(_stored_text(reason, "completeness reason") for reason in reasons_value)
    if len(set(reasons)) != len(reasons):
        _error("completeness reasons must be unique")
    return AuditCompleteness(
        complete=_strict_bool(completeness["complete"], "completeness complete"),
        rejected_findings=_strict_int(completeness["rejected_findings"], "rejected_findings"),
        truncated_findings=_strict_int(completeness["truncated_findings"], "truncated_findings"),
        reasons=reasons,
    )


def parse_audit_report(data: bytes, *, max_bytes: int) -> AuditReport:
    value = _load_json(data, max_bytes=max_bytes, name="audit report")
    stored = _exact_object(value, _REPORT_FIELDS, "audit report")
    schema_version = _strict_int(stored["schema_version"], "schema_version")
    if schema_version != REPORT_SCHEMA_VERSION:
        _error(f"report schema_version must be exactly {REPORT_SCHEMA_VERSION}")
    checks_value = stored["checks"]
    skipped_value = stored["skipped_content"]
    findings_value = stored["findings"]
    if not isinstance(checks_value, list):
        _error("report checks must be a list")
    if not isinstance(skipped_value, list):
        _error("report skipped_content must be a list")
    if not isinstance(findings_value, list):
        _error("report findings must be a list")
    report = AuditReport(
        schema_version=schema_version,
        run_id=_stored_text(stored["run_id"], "run_id"),
        repository_id=_stored_text(stored["repository_id"], "repository_id"),
        status=_enum_value(AuditStatus, stored["status"], "report status"),
        metadata=_parse_metadata(stored["metadata"]),
        summary=_stored_text(stored["summary"], "report summary"),
        checks=tuple(_parse_check(check) for check in checks_value),
        skipped_content=tuple(_parse_skipped_content(item) for item in skipped_value),
        findings=tuple(_parse_stored_finding(finding) for finding in findings_value),
        severity_counts=_parse_counts(stored["severity_counts"]),
        completeness=_parse_completeness(stored["completeness"]),
    )
    _validate_report_invariants(report)
    return report
