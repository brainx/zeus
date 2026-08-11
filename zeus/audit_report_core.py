from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from enum import StrEnum
from typing import NoReturn, TypeVar

from zeus.audit_models import (
    AUDIT_RESERVED_CHECK_NAMES,
    AuditCategory,
    AuditCheck,
    AuditCommandReceipt,
    AuditCompleteness,
    AuditConfidence,
    AuditControlCoverage,
    AuditControlSpec,
    AuditEvidence,
    AuditFinding,
    AuditLimits,
    AuditMetadata,
    AuditSeverity,
    CheckDisposition,
    CheckEvidence,
    CoverageDisposition,
    ModelAuditResult,
    RepositoryEvidence,
    SeverityCounts,
    SourceEvidence,
    TrustedCheckBinding,
)
from zeus.sanitization import sanitize_text

REPORT_SCHEMA_VERSION = 2
MAX_REPORT_TEXT_BYTES = 8 * 1024

_LEGACY_MODEL_FIELDS = frozenset({"summary", "findings", "checks", "skipped_checks"})
_MODEL_FIELDS = _LEGACY_MODEL_FIELDS | {"coverage"}
_LEGACY_MODEL_CHECK_FIELDS = frozenset({"name", "disposition", "observation"})
_MODEL_CHECK_FIELDS = _LEGACY_MODEL_CHECK_FIELDS | {"receipt_id"}
_COVERAGE_FIELDS = frozenset({"control_id", "disposition", "check_names", "reason"})
_LEGACY_FINDING_FIELDS = frozenset(
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
_FINDING_FIELDS = frozenset(
    {
        *_LEGACY_FINDING_FIELDS,
        "control_id",
    }
)
_LEGACY_SOURCE_EVIDENCE_FIELDS = frozenset(
    {"type", "path", "start_line", "end_line", "observation"}
)
_SOURCE_EVIDENCE_FIELDS = _LEGACY_SOURCE_EVIDENCE_FIELDS | {"blob_sha256"}
_CHECK_EVIDENCE_FIELDS = frozenset({"type", "check_name", "observation"})
_REPOSITORY_EVIDENCE_FIELDS = frozenset({"type", "observation", "inspection_method"})
_LEGACY_REPORT_FIELDS = frozenset(
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
_REPORT_FIELDS = _LEGACY_REPORT_FIELDS | {"surface", "coverage", "command_receipts"}
_LEGACY_METADATA_FIELDS = frozenset(
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
_METADATA_FIELDS = _LEGACY_METADATA_FIELDS | {"trusted_execution_boundary"}
_LEGACY_CHECK_FIELDS = frozenset({"name", "disposition", "duration_seconds", "observation"})
_CHECK_FIELDS = _LEGACY_CHECK_FIELDS | {"receipt_id"}
_SKIPPED_CONTENT_FIELDS = frozenset({"path", "reason"})
_LEGACY_STORED_FINDING_FIELDS = _LEGACY_FINDING_FIELDS | {"finding_id"}
_STORED_FINDING_FIELDS = _FINDING_FIELDS | {"finding_id", "fingerprint"}
_SURFACE_FIELDS = frozenset(
    {
        "catalog_version",
        "snapshot_digest",
        "ecosystems",
        "dependency_manifests",
        "dependency_manifest_count",
        "ci_paths",
        "ci_path_count",
        "iac_paths",
        "iac_path_count",
        "web_paths",
        "web_path_count",
        "required_control_ids",
    }
)
_CONTROL_COVERAGE_FIELDS = frozenset(
    {"control_id", "category", "required", "disposition", "check_names", "reason"}
)
_COMMAND_RECEIPT_FIELDS = frozenset(
    {
        "receipt_id",
        "sequence",
        "command_tag",
        "state",
        "returncode",
        "duration_ms",
        "stdout_bytes",
        "stderr_bytes",
    }
)
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
_CONTROL_ID_RE = re.compile(r"[A-Z][A-Z0-9-]{2,63}\Z")
_RECEIPT_ID_RE = re.compile(r"terminal-[0-9]{6}\Z")
_COMMAND_TAG_RE = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


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


def _normalized_fingerprint_text(value: str) -> str:
    return " ".join(value.casefold().split())


def _finding_fingerprint(
    *,
    control_id: str | None,
    category: AuditCategory,
    title: str,
    evidence: Sequence[AuditEvidence],
) -> str:
    anchors: list[dict[str, object]] = []
    for item in evidence:
        if isinstance(item, SourceEvidence):
            anchors.append(
                {
                    "type": "source",
                    "path": item.path,
                    "start_line": item.start_line,
                    "end_line": item.end_line,
                }
            )
        elif isinstance(item, CheckEvidence):
            anchors.append({"type": "check", "check_name": item.check_name})
        else:
            anchors.append(
                {
                    "type": "repository",
                    "inspection_method": _normalized_fingerprint_text(item.inspection_method),
                }
            )
    canonical = json.dumps(
        {
            "anchors": anchors,
            "category": category.value,
            "control_id": control_id,
            "title": _normalized_fingerprint_text(title),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"finding-fingerprint-{hashlib.sha256(canonical).hexdigest()[:32]}"


def _validated_control_specs(
    controls: Sequence[AuditControlSpec] | None,
    *,
    allowed_categories: frozenset[AuditCategory],
) -> tuple[AuditControlSpec, ...] | None:
    if controls is None:
        return None
    result: list[AuditControlSpec] = []
    seen: set[str] = set()
    for control in controls:
        if (
            not isinstance(control, AuditControlSpec)
            or _CONTROL_ID_RE.fullmatch(control.control_id) is None
            or control.category not in allowed_categories
            or type(control.required) is not bool
            or control.control_id in seen
        ):
            _error("required security control catalog is invalid")
        seen.add(control.control_id)
        result.append(control)
    return tuple(sorted(result, key=lambda item: item.control_id))


def _validated_receipts(
    receipts: Sequence[AuditCommandReceipt],
) -> dict[str, AuditCommandReceipt]:
    result: dict[str, AuditCommandReceipt] = {}
    for expected_sequence, receipt in enumerate(receipts, start=1):
        if (
            not isinstance(receipt, AuditCommandReceipt)
            or receipt.receipt_id != f"terminal-{expected_sequence:06d}"
            or type(receipt.sequence) is not int
            or receipt.sequence != expected_sequence
            or receipt.receipt_id in result
            or _RECEIPT_ID_RE.fullmatch(receipt.receipt_id) is None
            or type(receipt.command_tag) is not str
            or _COMMAND_TAG_RE.fullmatch(receipt.command_tag) is None
            or receipt.state != "exited"
            or type(receipt.returncode) is not int
            or not -255 <= receipt.returncode <= 255
            or type(receipt.duration_ms) is not int
            or receipt.duration_ms < 0
            or type(receipt.stdout_bytes) is not int
            or receipt.stdout_bytes < 0
            or type(receipt.stderr_bytes) is not int
            or receipt.stderr_bytes < 0
        ):
            _error("command receipt ledger is invalid")
        result[receipt.receipt_id] = receipt
    return result


def _validated_trusted_checks(
    bindings: Sequence[TrustedCheckBinding],
) -> dict[str, TrustedCheckBinding]:
    result: dict[str, TrustedCheckBinding] = {}
    seen_pairs: set[tuple[str, str]] = set()
    for binding in bindings:
        if not isinstance(binding, TrustedCheckBinding) or type(binding.name) is not str:
            _error("trusted check bindings are invalid")
        safe_name, name_truncated = _sanitize_report_text(binding.name, "trusted check name")
        if (
            name_truncated
            or safe_name != binding.name
            or binding.name != binding.name.strip()
            or binding.name in AUDIT_RESERVED_CHECK_NAMES
            or binding.name in result
            or type(binding.receipt_tags) is not tuple
            or type(binding.control_ids) is not tuple
            or len(binding.control_ids) > 16
        ):
            _error("trusted check bindings are invalid")
        receipt_ids: set[str] = set()
        for pair in binding.receipt_tags:
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or type(pair[0]) is not str
                or _RECEIPT_ID_RE.fullmatch(pair[0]) is None
                or pair[0] in receipt_ids
                or type(pair[1]) is not str
                or _COMMAND_TAG_RE.fullmatch(pair[1]) is None
                or pair in seen_pairs
            ):
                _error("trusted check receipt bindings are invalid")
            receipt_ids.add(pair[0])
            seen_pairs.add(pair)
        seen_controls: set[str] = set()
        for control_id in binding.control_ids:
            if (
                type(control_id) is not str
                or _CONTROL_ID_RE.fullmatch(control_id) is None
                or control_id in seen_controls
            ):
                _error("trusted check control bindings are invalid")
            seen_controls.add(control_id)
        result[binding.name] = binding
    return result


def _model_evidence(
    value: object,
    *,
    source_line_counts: Mapping[str, int],
    source_digests: Mapping[str, str] | None,
    check_names: frozenset[str],
) -> tuple[AuditEvidence, bool]:
    if not isinstance(value, dict):
        _error("finding evidence must be an object")
    evidence_type = value.get("type")
    truncated = False
    if evidence_type == "source":
        expected_fields = (
            _LEGACY_SOURCE_EVIDENCE_FIELDS
            if "end_line" in value
            else _LEGACY_SOURCE_EVIDENCE_FIELDS - {"end_line"}
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
        blob_sha256 = None
        if source_digests is not None:
            blob_sha256 = source_digests.get(path)
            if not isinstance(blob_sha256, str) or _SHA256_RE.fullmatch(blob_sha256) is None:
                _error("source evidence must reference an authoritative snapshot digest")
        return (
            SourceEvidence(path, start_line, end_line, observation, blob_sha256),
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
    source_digests: Mapping[str, str] | None,
    check_names: frozenset[str],
    control_specs: Mapping[str, AuditControlSpec],
    model_schema_version: int,
) -> tuple[AuditFinding, bool]:
    finding = _exact_object(
        value,
        _FINDING_FIELDS if model_schema_version == 2 else _LEGACY_FINDING_FIELDS,
        "finding",
    )
    category = _enum_value(AuditCategory, finding["category"], "finding category")
    if category not in allowed_categories:
        _error("finding category was not selected for this audit")
    severity = _enum_value(AuditSeverity, finding["severity"], "finding severity")
    confidence = _enum_value(AuditConfidence, finding["confidence"], "finding confidence")
    title, title_truncated = _sanitize_report_text(finding["title"], "finding title")
    control_id: str | None = None
    if model_schema_version == 2:
        raw_control_id = finding["control_id"]
        if raw_control_id is not None:
            control_id, control_truncated = _sanitize_report_text(
                raw_control_id,
                "finding control_id",
            )
            if control_truncated or _CONTROL_ID_RE.fullmatch(control_id) is None:
                _error("finding control_id is invalid")
        if category is AuditCategory.security and control_specs and control_id not in control_specs:
            _error("security finding must reference an applicable security control")
        if category is not AuditCategory.security and control_id is not None:
            _error("non-security finding must not reference a security control")
    evidence_values = finding["evidence"]
    if not isinstance(evidence_values, list) or not 1 <= len(evidence_values) <= 4:
        _error("finding evidence must contain between one and four entries")
    evidence: list[AuditEvidence] = []
    evidence_truncated = False
    for item in evidence_values:
        parsed, truncated = _model_evidence(
            item,
            source_line_counts=source_line_counts,
            source_digests=source_digests,
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
            control_id=control_id,
            fingerprint=_finding_fingerprint(
                control_id=control_id,
                category=category,
                title=title,
                evidence=evidence,
            ),
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
    trusted_checks: Sequence[TrustedCheckBinding] = (),
    required_controls: Sequence[AuditControlSpec] | None = None,
    command_receipts: Sequence[AuditCommandReceipt] = (),
    source_digests: Mapping[str, str] | None = None,
) -> ModelAuditResult:
    value = _load_json(data, max_bytes=limits.model_output_bytes, name="model output")
    if not isinstance(value, dict):
        _error("model output must be an object")
    actual_model_fields = frozenset(value)
    if actual_model_fields == _MODEL_FIELDS:
        model_schema_version = 2
        model = value
    elif actual_model_fields == _LEGACY_MODEL_FIELDS:
        model_schema_version = 1
        model = value
    else:
        model = _exact_object(value, _MODEL_FIELDS, "model output")
        model_schema_version = 2
    safe_run_id, run_id_truncated = _sanitize_report_text(run_id, "run_id")
    if run_id_truncated or safe_run_id != run_id:
        _error("run_id must be a canonical bounded string")
    if not allowed_categories or not all(
        isinstance(category, AuditCategory) for category in allowed_categories
    ):
        _error("allowed_categories must contain audit categories")
    control_specs = _validated_control_specs(
        required_controls,
        allowed_categories=allowed_categories,
    )
    control_by_id = (
        {} if control_specs is None else {control.control_id: control for control in control_specs}
    )
    receipts_by_id = _validated_receipts(command_receipts)
    trusted_by_name = _validated_trusted_checks(trusted_checks)
    if source_digests is not None and any(
        type(path) is not str
        or type(digest) is not str
        or _SHA256_RE.fullmatch(digest) is None
        or path not in source_line_counts
        for path, digest in source_digests.items()
    ):
        _error("authoritative source digest map is invalid")
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
    for name in trusted_by_name:
        if name in preflight_check_names:
            _error("trusted check names must not conflict with preflight checks")
        if name not in configured_names:
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
    used_receipts: set[str] = set()
    checks_truncated = False
    for raw_check in model_check_values:
        check = _exact_object(
            raw_check,
            _MODEL_CHECK_FIELDS if model_schema_version == 2 else _LEGACY_MODEL_CHECK_FIELDS,
            "model check",
        )
        name, name_truncated = _sanitize_report_text(check["name"], "model check name")
        if name_truncated or name in AUDIT_RESERVED_CHECK_NAMES or name in explicit_checks:
            _error("model check names must be unique and distinct from Zeus checks")
        check_disposition = _enum_value(
            CheckDisposition,
            check["disposition"],
            "model check disposition",
        )
        observation, observation_truncated = _sanitize_report_text(
            check["observation"],
            "model check observation",
            allow_empty=True,
        )
        receipt_id: str | None = None
        duration_seconds = 0.0
        if model_schema_version == 2:
            raw_receipt_id = check["receipt_id"]
            if check_disposition is CheckDisposition.skipped:
                if raw_receipt_id is not None:
                    _error("skipped model checks must not reference a command receipt")
            else:
                receipt_id, receipt_truncated = _sanitize_report_text(
                    raw_receipt_id,
                    "model check receipt_id",
                )
                receipt = receipts_by_id.get(receipt_id)
                if (
                    receipt_truncated
                    or receipt is None
                    or receipt_id in used_receipts
                    or receipt.returncode is None
                    or receipt.duration_ms is None
                ):
                    _error("model check must reference one completed unique command receipt")
                trusted = trusted_by_name.get(name)
                if trusted is not None:
                    expected_tags = dict(trusted.receipt_tags)
                    if expected_tags.get(receipt_id) != receipt.command_tag:
                        _error("configured model check does not match its trusted command tag")
                authoritative_disposition = (
                    CheckDisposition.passed if receipt.returncode == 0 else CheckDisposition.failed
                )
                if check_disposition is not authoritative_disposition:
                    _error("model check disposition does not match its command receipt")
                used_receipts.add(receipt_id)
                duration_seconds = receipt.duration_ms / 1000.0
        elif control_specs is not None and check_disposition is not CheckDisposition.skipped:
            check_disposition = CheckDisposition.skipped
            observation = "model check had no authoritative command receipt"
        explicit_checks[name] = AuditCheck(
            name,
            check_disposition,
            duration_seconds,
            observation,
            receipt_id,
        )
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

    coverage_values = model.get("coverage", [])
    if not isinstance(coverage_values, list) or len(coverage_values) > 64:
        _error("model coverage must be a bounded list")
    if control_specs is None and coverage_values:
        _error("model coverage requires an authoritative control catalog")
    coverage_by_id: dict[str, AuditControlCoverage] = {}
    coverage_truncated = False
    for raw_coverage in coverage_values:
        coverage_value = _exact_object(raw_coverage, _COVERAGE_FIELDS, "model coverage")
        control_id, control_truncated = _sanitize_report_text(
            coverage_value["control_id"],
            "coverage control_id",
        )
        spec = control_by_id.get(control_id)
        if (
            control_truncated
            or _CONTROL_ID_RE.fullmatch(control_id) is None
            or spec is None
            or control_id in coverage_by_id
        ):
            _error("model coverage must reference unique applicable controls")
        coverage_disposition = _enum_value(
            CoverageDisposition,
            coverage_value["disposition"],
            "coverage disposition",
        )
        if spec.required and coverage_disposition is CoverageDisposition.not_applicable:
            _error("required applicable controls cannot use not_applicable coverage")
        raw_check_names = coverage_value["check_names"]
        if not isinstance(raw_check_names, list) or len(raw_check_names) > 16:
            _error("coverage check_names must be a bounded list")
        check_names: list[str] = []
        for raw_check_name in raw_check_names:
            check_name, name_truncated = _sanitize_report_text(
                raw_check_name,
                "coverage check_name",
            )
            recorded = explicit_checks.get(check_name)
            if (
                name_truncated
                or check_name in check_names
                or recorded is None
                or recorded.disposition is CheckDisposition.skipped
                or recorded.receipt_id is None
            ):
                _error("coverage must reference unique receipt-backed model checks")
            trusted = trusted_by_name.get(check_name)
            if trusted is None or control_id not in trusted.control_ids:
                _error("coverage may reference only authorized trusted checks")
            check_names.append(check_name)
        raw_reason = coverage_value["reason"]
        reason: str | None = None
        reason_truncated = False
        if raw_reason is not None:
            reason, reason_truncated = _sanitize_report_text(raw_reason, "coverage reason")
        if coverage_disposition in {
            CoverageDisposition.checked,
            CoverageDisposition.not_applicable,
        }:
            if not check_names or reason is not None:
                _error("accounted coverage requires checks and no skip reason")
        elif check_names or reason is None:
            _error("uncovered controls require a reason and no checks")
        coverage_by_id[control_id] = AuditControlCoverage(
            control_id=control_id,
            category=spec.category,
            required=spec.required,
            disposition=coverage_disposition,
            check_names=tuple(check_names),
            reason=reason,
        )
        coverage_truncated = coverage_truncated or control_truncated or reason_truncated
    if control_specs is not None:
        for spec in control_specs:
            if spec.control_id not in coverage_by_id:
                coverage_by_id[spec.control_id] = AuditControlCoverage(
                    control_id=spec.control_id,
                    category=spec.category,
                    required=spec.required,
                    disposition=CoverageDisposition.skipped,
                    check_names=(),
                    reason="required control was not reported by the audit model",
                )
    model_coverage = tuple(coverage_by_id[key] for key in sorted(coverage_by_id))

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
                source_digests=source_digests,
                check_names=finding_check_names,
                control_specs=control_by_id,
                model_schema_version=model_schema_version,
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
    if coverage_truncated:
        reasons.append("stored coverage text was truncated to byte limits")
    if (
        control_specs is not None
        and AuditCategory.security in allowed_categories
        and not control_specs
    ):
        reasons.append("security control catalog was unavailable")
    for coverage_record in model_coverage:
        if not coverage_record.required or coverage_record.disposition not in {
            CoverageDisposition.skipped,
            CoverageDisposition.unsupported,
        }:
            continue
        if coverage_record.reason == "required control was not reported by the audit model":
            reasons.append(
                f"required security control {coverage_record.control_id} was not reported"
            )
        else:
            action = (
                "was skipped"
                if coverage_record.disposition is CoverageDisposition.skipped
                else "is unsupported"
            )
            reasons.append(
                f"required security control {coverage_record.control_id} {action}: "
                f"{coverage_record.reason}"
            )
    if control_specs is not None:
        for recorded_check in model_checks:
            if (
                recorded_check.disposition is not CheckDisposition.failed
                or recorded_check.receipt_id is None
            ):
                continue
            receipt = receipts_by_id[recorded_check.receipt_id]
            reasons.append(
                f"receipt-backed audit check {recorded_check.name} failed with exit code "
                f"{receipt.returncode}"
            )
    unused_receipts = frozenset(receipts_by_id) - used_receipts
    if control_specs is not None and unused_receipts:
        noun = "receipt was" if len(unused_receipts) == 1 else "receipts were"
        reasons.append(
            f"{len(unused_receipts)} terminal command {noun} not represented by model checks"
        )
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
        coverage=model_coverage,
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
    trusted_execution_boundary, boundary_truncated = _sanitize_optional(
        metadata.trusted_execution_boundary,
        "metadata trusted_execution_boundary",
    )
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
            trusted_execution_boundary=trusted_execution_boundary,
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
                boundary_truncated,
            )
        ),
    )


def _sanitize_evidence(evidence: AuditEvidence) -> tuple[AuditEvidence, bool]:
    if isinstance(evidence, SourceEvidence):
        path = _relative_source_path(evidence.path)
        if evidence.blob_sha256 is not None and (
            type(evidence.blob_sha256) is not str
            or _SHA256_RE.fullmatch(evidence.blob_sha256) is None
        ):
            _error("source evidence blob_sha256 is invalid")
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
    control_id, control_truncated = _sanitize_optional(finding.control_id, "finding control_id")
    if control_id is not None and _CONTROL_ID_RE.fullmatch(control_id) is None:
        _error("finding control_id is invalid")
    fingerprint, fingerprint_truncated = _sanitize_optional(
        finding.fingerprint,
        "finding fingerprint",
    )
    if (
        fingerprint is not None
        and re.fullmatch(r"finding-fingerprint-[0-9a-f]{32}", fingerprint) is None
    ):
        _error("finding fingerprint is invalid")
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
            control_id=control_id,
            fingerprint=fingerprint,
            evidence=tuple(evidence),
            impact=impact,
            recommendation=recommendation,
            verification=verification,
        ),
        any(
            (
                id_truncated,
                title_truncated,
                control_truncated,
                fingerprint_truncated,
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
