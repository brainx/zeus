from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import replace
from enum import StrEnum
from typing import NoReturn, TypeVar

from zeus.audit_models import (
    AuditCategory,
    AuditCheck,
    AuditCompleteness,
    AuditConfidence,
    AuditEvidence,
    AuditFinding,
    AuditLimits,
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
from zeus.sanitization import sanitize_text

REPORT_SCHEMA_VERSION = 1
MAX_REPORT_TEXT_BYTES = 8 * 1024

_MODEL_FIELDS = frozenset({"summary", "findings", "skipped_checks"})
_FINDING_FIELDS = frozenset(
    {
        "category",
        "severity",
        "confidence",
        "title",
        "evidence",
        "impact",
        "recommendation",
        "verification",
    }
)
_SOURCE_EVIDENCE_FIELDS = frozenset(
    {"type", "path", "start_line", "end_line", "observation"}
)
_CHECK_EVIDENCE_FIELDS = frozenset({"type", "check_name", "observation"})
_REPOSITORY_EVIDENCE_FIELDS = frozenset(
    {"type", "observation", "inspection_method"}
)
_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "repository_id",
        "status",
        "metadata",
        "summary",
        "checks",
        "skipped_content",
        "findings",
        "severity_counts",
        "completeness",
    }
)
_METADATA_FIELDS = frozenset(
    {
        "zeus_version",
        "hermes_version",
        "skill_version",
        "image_digest",
        "target_commit",
        "started_at",
        "finished_at",
        "termination_reason",
        "provider",
        "model",
        "worktree_changes_excluded",
    }
)
_CHECK_FIELDS = frozenset({"name", "disposition", "duration_seconds", "observation"})
_SKIPPED_CONTENT_FIELDS = frozenset({"path", "reason"})
_STORED_FINDING_FIELDS = _FINDING_FIELDS | {"finding_id"}
_COUNTS_FIELDS = frozenset({"critical", "high", "medium", "low", "note"})
_COMPLETENESS_FIELDS = frozenset(
    {"complete", "rejected_findings", "truncated_findings", "reasons"}
)
_SEVERITY_ORDER = {
    AuditSeverity.critical: 0,
    AuditSeverity.high: 1,
    AuditSeverity.medium: 2,
    AuditSeverity.low: 3,
    AuditSeverity.note: 4,
}
EnumT = TypeVar("EnumT", bound=StrEnum)


class AuditReportError(ValueError):
    pass


def _error(message: str) -> NoReturn:
    raise AuditReportError(message)


def _exact_object(
    value: object,
    fields: frozenset[str],
    name: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        _error(f"{name} must be an object")
    if not all(type(key) is str for key in value):
        _error(f"{name} field names must be strings")
    actual = frozenset(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unknown = sorted(actual - fields)
        details: list[str] = []
        if missing:
            details.append(f"missing fields: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown fields: {', '.join(unknown)}")
        _error(f"{name} has an invalid schema ({'; '.join(details)})")
    return value


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _error(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    _error(f"non-finite JSON number is not allowed: {value}")


def _load_json(data: bytes, *, max_bytes: int, name: str) -> object:
    if type(max_bytes) is not int or max_bytes < 1:
        _error("maximum byte count must be a positive integer")
    if len(data) > max_bytes:
        _error(f"{name} exceeds its byte limit")
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except AuditReportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditReportError(f"{name} is not valid UTF-8 JSON") from exc


def _truncate_utf8(value: str, maximum: int) -> tuple[str, bool]:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AuditReportError("report text contains an invalid Unicode scalar") from exc
    if len(encoded) <= maximum:
        return value, False
    bounded = encoded[:maximum]
    while True:
        try:
            return bounded.decode("utf-8", errors="strict"), True
        except UnicodeDecodeError as exc:
            bounded = bounded[: exc.start]


def _sanitize_report_text(
    value: object,
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, bool]:
    if type(value) is not str:
        _error(f"{name} must be a string")
    if not value and not allow_empty:
        _error(f"{name} must not be empty")
    sanitized = sanitize_text(value, max_length=len(value))
    bounded, truncated = _truncate_utf8(sanitized, MAX_REPORT_TEXT_BYTES)
    if not bounded and not allow_empty:
        _error(f"{name} must not be empty")
    return bounded, truncated


def _stored_text(value: object, name: str, *, allow_empty: bool = False) -> str:
    text, truncated = _sanitize_report_text(value, name, allow_empty=allow_empty)
    if truncated or text != value:
        _error(f"{name} is not a canonical redacted bounded string")
    return text


def _strict_int(value: object, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _error(f"{name} must be an integer greater than or equal to {minimum}")
    return value


def _strict_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        _error(f"{name} must be a boolean")
    return value


def _check_duration_seconds(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        _error("check duration_seconds must be a finite non-negative number")
    return float(value)


def _enum_value(
    enum_type: type[EnumT],
    value: object,
    name: str,
) -> EnumT:
    if type(value) is not str:
        _error(f"{name} must be a string")
    try:
        return enum_type(value)
    except ValueError:
        _error(f"{name} has an unsupported value: {value}")


def _relative_source_path(value: object) -> str:
    if type(value) is not str or not value:
        _error("source evidence path must be a non-empty string")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        _error("source evidence path must be a confined relative POSIX path")
    components = value.split("/")
    if (
        any(component in {"", ".", ".."} for component in components)
        or any(component.casefold() == ".git" for component in components)
        or (components and components[0].endswith(":"))
    ):
        _error("source evidence path must be a confined relative POSIX path")
    sanitized, truncated = _sanitize_report_text(value, "source evidence path")
    if truncated or sanitized != value:
        _error("source evidence path must be redacted and within its byte limit")
    return value


def _finding_id(run_id: str, ordinal: int) -> str:
    digest = hashlib.sha256(f"{run_id}\0{ordinal}".encode()).hexdigest()
    return f"finding-{digest[:20]}"


def _model_evidence(
    value: object,
    *,
    source_line_counts: Mapping[str, int],
    check_names: frozenset[str],
) -> tuple[AuditEvidence, bool]:
    if not isinstance(value, dict):
        _error("finding evidence must be an object")
    evidence_type = value.get("type")
    truncated = False
    if evidence_type == "source":
        expected_fields = (
            _SOURCE_EVIDENCE_FIELDS
            if "end_line" in value
            else _SOURCE_EVIDENCE_FIELDS - {"end_line"}
        )
        source = _exact_object(value, expected_fields, "source evidence")
        path = _relative_source_path(source["path"])
        line_count = source_line_counts.get(path)
        if type(line_count) is not int or line_count < 1:
            _error("source evidence must reference a verified regular text file")
        start_line = _strict_int(source["start_line"], "source evidence start_line", minimum=1)
        end_value = source.get("end_line")
        end_line = (
            None
            if end_value is None
            else _strict_int(end_value, "source evidence end_line", minimum=1)
        )
        if start_line > line_count:
            _error("source evidence start_line is outside the verified file")
        if end_line is not None and (end_line < start_line or end_line > line_count):
            _error("source evidence end_line is outside the verified range")
        observation, text_truncated = _sanitize_report_text(
            source["observation"], "source evidence observation"
        )
        return (
            SourceEvidence(path, start_line, end_line, observation),
            truncated or text_truncated,
        )
    if evidence_type == "check":
        check = _exact_object(value, _CHECK_EVIDENCE_FIELDS, "check evidence")
        check_name, name_truncated = _sanitize_report_text(
            check["check_name"], "check evidence check_name"
        )
        if name_truncated or check_name not in check_names:
            _error("check evidence must reference a recorded check")
        observation, text_truncated = _sanitize_report_text(
            check["observation"], "check evidence observation"
        )
        return CheckEvidence(check_name, observation), name_truncated or text_truncated
    if evidence_type == "repository":
        repository = _exact_object(
            value,
            _REPOSITORY_EVIDENCE_FIELDS,
            "repository evidence",
        )
        observation, observation_truncated = _sanitize_report_text(
            repository["observation"], "repository evidence observation"
        )
        inspection_method, method_truncated = _sanitize_report_text(
            repository["inspection_method"],
            "repository evidence inspection_method",
        )
        return (
            RepositoryEvidence(observation, inspection_method),
            observation_truncated or method_truncated,
        )
    _error("finding evidence has an unsupported type")


def _model_finding(
    value: object,
    *,
    run_id: str,
    ordinal: int,
    allowed_categories: frozenset[AuditCategory],
    source_line_counts: Mapping[str, int],
    check_names: frozenset[str],
) -> tuple[AuditFinding, bool]:
    finding = _exact_object(value, _FINDING_FIELDS, "finding")
    category = _enum_value(AuditCategory, finding["category"], "finding category")
    if category not in allowed_categories:
        _error("finding category was not selected for this audit")
    severity = _enum_value(AuditSeverity, finding["severity"], "finding severity")
    confidence = _enum_value(AuditConfidence, finding["confidence"], "finding confidence")
    title, title_truncated = _sanitize_report_text(finding["title"], "finding title")
    evidence_values = finding["evidence"]
    if not isinstance(evidence_values, list) or not 1 <= len(evidence_values) <= 4:
        _error("finding evidence must contain between one and four entries")
    evidence: list[AuditEvidence] = []
    evidence_truncated = False
    for item in evidence_values:
        parsed, truncated = _model_evidence(
            item,
            source_line_counts=source_line_counts,
            check_names=check_names,
        )
        evidence.append(parsed)
        evidence_truncated = evidence_truncated or truncated
    impact, impact_truncated = _sanitize_report_text(finding["impact"], "finding impact")
    recommendation, recommendation_truncated = _sanitize_report_text(
        finding["recommendation"], "finding recommendation"
    )
    verification, verification_truncated = _sanitize_report_text(
        finding["verification"], "finding verification"
    )
    return (
        AuditFinding(
            finding_id=_finding_id(run_id, ordinal),
            category=category,
            severity=severity,
            confidence=confidence,
            title=title,
            evidence=tuple(evidence),
            impact=impact,
            recommendation=recommendation,
            verification=verification,
        ),
        any(
            (
                title_truncated,
                evidence_truncated,
                impact_truncated,
                recommendation_truncated,
                verification_truncated,
            )
        ),
    )


def validate_model_output(
    data: bytes,
    *,
    run_id: str,
    allowed_categories: frozenset[AuditCategory],
    source_line_counts: Mapping[str, int],
    checks: Sequence[AuditCheck],
    limits: AuditLimits,
) -> ModelAuditResult:
    value = _load_json(data, max_bytes=limits.model_output_bytes, name="model output")
    model = _exact_object(value, _MODEL_FIELDS, "model output")
    safe_run_id, run_id_truncated = _sanitize_report_text(run_id, "run_id")
    if run_id_truncated or safe_run_id != run_id:
        _error("run_id must be a canonical bounded string")
    if not allowed_categories or not all(
        isinstance(category, AuditCategory) for category in allowed_categories
    ):
        _error("allowed_categories must contain audit categories")
    check_names = frozenset(check.name for check in checks)
    if len(check_names) != len(checks):
        _error("recorded check names must be unique")

    summary, summary_truncated = _sanitize_report_text(model["summary"], "model summary")
    finding_values = model["findings"]
    if not isinstance(finding_values, list):
        _error("model findings must be a list")
    skipped_values = model["skipped_checks"]
    if not isinstance(skipped_values, list):
        _error("model skipped_checks must be a list")
    skipped_record_names = frozenset(
        check.name for check in checks if check.disposition is CheckDisposition.skipped
    )
    skipped_checks: list[str] = []
    for value in skipped_values:
        skipped, truncated = _sanitize_report_text(value, "skipped check")
        if truncated or skipped not in skipped_record_names:
            _error("skipped_checks must reference recorded skipped checks")
        if skipped in skipped_checks:
            _error("skipped_checks must be unique")
        skipped_checks.append(skipped)

    accepted: list[AuditFinding] = []
    rejected = 0
    text_truncated = summary_truncated
    for ordinal, raw_finding in enumerate(finding_values):
        try:
            finding, finding_text_truncated = _model_finding(
                raw_finding,
                run_id=run_id,
                ordinal=ordinal,
                allowed_categories=allowed_categories,
                source_line_counts=source_line_counts,
                check_names=check_names,
            )
        except AuditReportError:
            rejected += 1
            continue
        accepted.append(finding)
        text_truncated = text_truncated or finding_text_truncated

    truncated_findings = max(0, len(accepted) - limits.findings)
    if truncated_findings:
        del accepted[limits.findings :]
    reasons: list[str] = []
    if rejected:
        noun = "finding was" if rejected == 1 else "findings were"
        reasons.append(f"{rejected} invalid {noun} rejected")
    if truncated_findings:
        noun = "finding was" if truncated_findings == 1 else "findings were"
        reasons.append(f"{truncated_findings} valid {noun} truncated")
    if text_truncated:
        reasons.append("stored text was truncated to byte limits")
    return ModelAuditResult(
        summary=summary,
        findings=tuple(accepted),
        skipped_checks=tuple(skipped_checks),
        completeness=AuditCompleteness(
            complete=not reasons,
            rejected_findings=rejected,
            truncated_findings=truncated_findings,
            reasons=tuple(reasons),
        ),
    )


def _sanitize_optional(value: str | None, name: str) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    return _sanitize_report_text(value, name)


def _sanitize_metadata(metadata: AuditMetadata) -> tuple[AuditMetadata, bool]:
    zeus_version, zeus_truncated = _sanitize_report_text(
        metadata.zeus_version, "metadata zeus_version"
    )
    hermes_version, hermes_truncated = _sanitize_optional(
        metadata.hermes_version, "metadata hermes_version"
    )
    skill_version, skill_truncated = _sanitize_optional(
        metadata.skill_version, "metadata skill_version"
    )
    image_digest, image_truncated = _sanitize_optional(
        metadata.image_digest, "metadata image_digest"
    )
    target_commit, commit_truncated = _sanitize_optional(
        metadata.target_commit, "metadata target_commit"
    )
    started_at, started_truncated = _sanitize_report_text(
        metadata.started_at, "metadata started_at"
    )
    finished_at, finished_truncated = _sanitize_report_text(
        metadata.finished_at, "metadata finished_at"
    )
    termination_reason, reason_truncated = _sanitize_optional(
        metadata.termination_reason, "metadata termination_reason"
    )
    provider, provider_truncated = _sanitize_optional(metadata.provider, "metadata provider")
    model, model_truncated = _sanitize_optional(metadata.model, "metadata model")
    return (
        AuditMetadata(
            zeus_version=zeus_version,
            hermes_version=hermes_version,
            skill_version=skill_version,
            image_digest=image_digest,
            target_commit=target_commit,
            started_at=started_at,
            finished_at=finished_at,
            termination_reason=termination_reason,
            provider=provider,
            model=model,
            worktree_changes_excluded=metadata.worktree_changes_excluded,
        ),
        any(
            (
                zeus_truncated,
                hermes_truncated,
                skill_truncated,
                image_truncated,
                commit_truncated,
                started_truncated,
                finished_truncated,
                reason_truncated,
                provider_truncated,
                model_truncated,
            )
        ),
    )


def _sanitize_evidence(evidence: AuditEvidence) -> tuple[AuditEvidence, bool]:
    if isinstance(evidence, SourceEvidence):
        path = _relative_source_path(evidence.path)
        observation, truncated = _sanitize_report_text(
            evidence.observation, "source evidence observation"
        )
        return replace(evidence, path=path, observation=observation), truncated
    if isinstance(evidence, CheckEvidence):
        check_name, name_truncated = _sanitize_report_text(
            evidence.check_name, "check evidence check_name"
        )
        observation, observation_truncated = _sanitize_report_text(
            evidence.observation, "check evidence observation"
        )
        return (
            replace(evidence, check_name=check_name, observation=observation),
            name_truncated or observation_truncated,
        )
    if isinstance(evidence, RepositoryEvidence):
        observation, observation_truncated = _sanitize_report_text(
            evidence.observation, "repository evidence observation"
        )
        method, method_truncated = _sanitize_report_text(
            evidence.inspection_method, "repository evidence inspection_method"
        )
        return (
            replace(evidence, observation=observation, inspection_method=method),
            observation_truncated or method_truncated,
        )
    _error("finding contains unsupported evidence")


def _sanitize_finding(finding: AuditFinding) -> tuple[AuditFinding, bool]:
    finding_id, id_truncated = _sanitize_report_text(finding.finding_id, "finding_id")
    title, title_truncated = _sanitize_report_text(finding.title, "finding title")
    evidence: list[AuditEvidence] = []
    evidence_truncated = False
    if not 1 <= len(finding.evidence) <= 4:
        _error("finding evidence must contain between one and four entries")
    for item in finding.evidence:
        safe_item, truncated = _sanitize_evidence(item)
        evidence.append(safe_item)
        evidence_truncated = evidence_truncated or truncated
    impact, impact_truncated = _sanitize_report_text(finding.impact, "finding impact")
    recommendation, recommendation_truncated = _sanitize_report_text(
        finding.recommendation, "finding recommendation"
    )
    verification, verification_truncated = _sanitize_report_text(
        finding.verification, "finding verification"
    )
    return (
        replace(
            finding,
            finding_id=finding_id,
            title=title,
            evidence=tuple(evidence),
            impact=impact,
            recommendation=recommendation,
            verification=verification,
        ),
        any(
            (
                id_truncated,
                title_truncated,
                evidence_truncated,
                impact_truncated,
                recommendation_truncated,
                verification_truncated,
            )
        ),
    )


def _severity_counts(findings: Sequence[AuditFinding]) -> SeverityCounts:
    counts = {severity: 0 for severity in AuditSeverity}
    for finding in findings:
        counts[finding.severity] += 1
    return SeverityCounts(
        critical=counts[AuditSeverity.critical],
        high=counts[AuditSeverity.high],
        medium=counts[AuditSeverity.medium],
        low=counts[AuditSeverity.low],
        note=counts[AuditSeverity.note],
    )


def _sort_findings(findings: Sequence[AuditFinding]) -> tuple[AuditFinding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                _SEVERITY_ORDER[finding.severity],
                finding.category.value,
                finding.title,
                finding.finding_id,
            ),
        )
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
    safe_repository_id, repository_truncated = _sanitize_report_text(
        repository_id, "repository_id"
    )
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
        reason, reason_truncated = _sanitize_report_text(
            skipped.reason, "skipped content reason"
        )
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
        safe_reason, reason_truncated = _sanitize_report_text(
            reason, "completeness reason"
        )
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
            {"path": skipped.path, "reason": skipped.reason}
            for skipped in report.skipped_content
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
                    type(evidence.end_line) is not int
                    or evidence.end_line < evidence.start_line
                ):
                    _error("source evidence end_line must not precede start_line")
            elif (
                isinstance(evidence, CheckEvidence)
                and evidence.check_name not in check_names
            ):
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
        disposition=_enum_value(
            CheckDisposition, check["disposition"], "check disposition"
        ),
        duration_seconds=_check_duration_seconds(check["duration_seconds"]),
        observation=_stored_text(
            check["observation"], "check observation", allow_empty=True
        ),
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
            None
            if end_value is None
            else _strict_int(end_value, "source end_line", minimum=1)
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
            observation=_stored_text(
                repository["observation"], "repository observation"
            ),
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
        confidence=_enum_value(
            AuditConfidence, finding["confidence"], "finding confidence"
        ),
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
        rejected_findings=_strict_int(
            completeness["rejected_findings"], "rejected_findings"
        ),
        truncated_findings=_strict_int(
            completeness["truncated_findings"], "truncated_findings"
        ),
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
    lines.append("Complete." if report.completeness.complete else "Incomplete.")
    if report.completeness.rejected_findings:
        lines.append(
            f"- Rejected findings: {report.completeness.rejected_findings}"
        )
    if report.completeness.truncated_findings:
        lines.append(
            f"- Truncated findings: {report.completeness.truncated_findings}"
        )
    lines.extend(
        f"- {_markdown_text(reason)}" for reason in report.completeness.reasons
    )
    return "\n".join(lines).rstrip() + "\n"
