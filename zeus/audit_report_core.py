from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import replace
from enum import StrEnum
from typing import NoReturn, TypeVar

from zeus.audit_models import (
    AUDIT_RESERVED_CHECK_NAMES,
    AuditCategory,
    AuditCheck,
    AuditCompleteness,
    AuditConfidence,
    AuditEvidence,
    AuditFinding,
    AuditLimits,
    AuditMetadata,
    AuditSeverity,
    CheckDisposition,
    CheckEvidence,
    ModelAuditResult,
    RepositoryEvidence,
    SeverityCounts,
    SourceEvidence,
)
from zeus.sanitization import sanitize_text

REPORT_SCHEMA_VERSION = 1
MAX_REPORT_TEXT_BYTES = 8 * 1024

_MODEL_FIELDS = frozenset({"summary", "findings", "checks", "skipped_checks"})
_MODEL_CHECK_FIELDS = frozenset({"name", "disposition", "observation"})
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
_SOURCE_EVIDENCE_FIELDS = frozenset({"type", "path", "start_line", "end_line", "observation"})
_CHECK_EVIDENCE_FIELDS = frozenset({"type", "check_name", "observation"})
_REPOSITORY_EVIDENCE_FIELDS = frozenset({"type", "observation", "inspection_method"})
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
_COMPLETENESS_FIELDS = frozenset({"complete", "rejected_findings", "truncated_findings", "reasons"})
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
    configured_check_names: Sequence[str] = (),
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
    preflight_check_names = frozenset(check.name for check in checks)
    if len(preflight_check_names) != len(checks):
        _error("recorded check names must be unique")
    configured_names: list[str] = []
    for raw_name in configured_check_names:
        name, truncated = _sanitize_report_text(raw_name, "configured check name")
        if truncated or name != raw_name or name in configured_names:
            _error("configured check names must be unique bounded strings")
        if name in preflight_check_names:
            _error("configured check names must not conflict with preflight checks")
        configured_names.append(name)
    if len(configured_names) > limits.terminal_calls:
        _error("configured check names exceed the terminal call limit")
    configured_name_set = frozenset(configured_names)

    summary, summary_truncated = _sanitize_report_text(model["summary"], "model summary")
    finding_values = model["findings"]
    if not isinstance(finding_values, list):
        _error("model findings must be a list")
    skipped_values = model["skipped_checks"]
    if not isinstance(skipped_values, list):
        _error("model skipped_checks must be a list")
    model_check_values = model["checks"]
    if not isinstance(model_check_values, list) or len(model_check_values) > limits.terminal_calls:
        _error("model checks must be a bounded list")

    explicit_checks: dict[str, AuditCheck] = {}
    checks_truncated = False
    for raw_check in model_check_values:
        check = _exact_object(raw_check, _MODEL_CHECK_FIELDS, "model check")
        name, name_truncated = _sanitize_report_text(check["name"], "model check name")
        if name_truncated or name in AUDIT_RESERVED_CHECK_NAMES or name in explicit_checks:
            _error("model check names must be unique and distinct from Zeus checks")
        disposition = _enum_value(
            CheckDisposition,
            check["disposition"],
            "model check disposition",
        )
        observation, observation_truncated = _sanitize_report_text(
            check["observation"],
            "model check observation",
            allow_empty=True,
        )
        explicit_checks[name] = AuditCheck(name, disposition, 0.0, observation)
        checks_truncated = checks_truncated or name_truncated or observation_truncated
    if len(configured_name_set | frozenset(explicit_checks)) > limits.terminal_calls:
        _error("recorded model checks exceed the terminal call limit")

    skipped_record_names = frozenset(
        check.name for check in checks if check.disposition is CheckDisposition.skipped
    )
    requested_skips: list[str] = []
    for value in skipped_values:
        skipped, truncated = _sanitize_report_text(value, "skipped check")
        explicit = explicit_checks.get(skipped)
        if (
            truncated
            or (
                skipped not in skipped_record_names
                and skipped not in configured_name_set
                and skipped not in explicit_checks
            )
            or (explicit is not None and explicit.disposition is not CheckDisposition.skipped)
        ):
            _error("skipped_checks must reference skipped or omitted checks")
        if skipped in requested_skips:
            _error("skipped_checks must be unique")
        requested_skips.append(skipped)
    for name, recorded_check in explicit_checks.items():
        if recorded_check.disposition is CheckDisposition.skipped and name not in requested_skips:
            _error("model skipped checks must also appear in skipped_checks")

    model_checks = list(explicit_checks.values())
    model_checks.extend(
        AuditCheck(
            name,
            CheckDisposition.skipped,
            0.0,
            "configured check was not reported by the audit model",
        )
        for name in configured_names
        if name not in explicit_checks
    )
    skipped_checks = sorted(
        {
            *skipped_record_names.intersection(requested_skips),
            *(
                check.name
                for check in model_checks
                if check.disposition is CheckDisposition.skipped
            ),
        }
    )
    finding_check_names = preflight_check_names | frozenset(explicit_checks)

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
                check_names=finding_check_names,
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
    if checks_truncated:
        reasons.append("stored check text was truncated to byte limits")
    return ModelAuditResult(
        summary=summary,
        findings=tuple(accepted),
        skipped_checks=tuple(skipped_checks),
        checks=tuple(model_checks),
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
