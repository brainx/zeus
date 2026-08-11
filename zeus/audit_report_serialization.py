from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace

from zeus.audit_models import (
    HARD_LIMITS,
    AuditCategory,
    AuditCheck,
    AuditCommandReceipt,
    AuditCompleteness,
    AuditConfidence,
    AuditControlCoverage,
    AuditEvidence,
    AuditFinding,
    AuditMetadata,
    AuditReport,
    AuditSeverity,
    AuditStatus,
    AuditSurface,
    CheckDisposition,
    CheckEvidence,
    CoverageDisposition,
    ModelAuditResult,
    RepositoryEvidence,
    SeverityCounts,
    SkippedContent,
    SourceEvidence,
)
from zeus.audit_report_core import (
    _CHECK_EVIDENCE_FIELDS,
    _CHECK_FIELDS,
    _COMMAND_RECEIPT_FIELDS,
    _COMPLETENESS_FIELDS,
    _CONTROL_COVERAGE_FIELDS,
    _COUNTS_FIELDS,
    _LEGACY_CHECK_FIELDS,
    _LEGACY_METADATA_FIELDS,
    _LEGACY_REPORT_FIELDS,
    _LEGACY_SOURCE_EVIDENCE_FIELDS,
    _LEGACY_STORED_FINDING_FIELDS,
    _METADATA_FIELDS,
    _REPORT_FIELDS,
    _REPOSITORY_EVIDENCE_FIELDS,
    _SKIPPED_CONTENT_FIELDS,
    _SOURCE_EVIDENCE_FIELDS,
    _STORED_FINDING_FIELDS,
    _SURFACE_FIELDS,
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
    surface: AuditSurface | None = None,
    command_receipts: Sequence[AuditCommandReceipt] = (),
    schema_version: int = REPORT_SCHEMA_VERSION,
) -> AuditReport:
    if schema_version not in {1, REPORT_SCHEMA_VERSION}:
        _error("report schema_version is unsupported")
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

    safe_surface = surface
    surface_truncated = False
    if surface is not None:
        catalog_version, catalog_truncated = _sanitize_report_text(
            surface.catalog_version,
            "surface catalog_version",
        )
        if (
            type(surface.snapshot_digest) is not str
            or len(surface.snapshot_digest) != 64
            or any(character not in "0123456789abcdef" for character in surface.snapshot_digest)
        ):
            _error("surface snapshot_digest is invalid")

        def safe_values(values: tuple[str, ...], name: str, *, paths: bool) -> tuple[str, ...]:
            nonlocal surface_truncated
            if (
                any(type(value) is not str for value in values)
                or tuple(sorted(set(values))) != values
                or len(values) > 32
                or (paths and sum(len(value.encode("utf-8")) for value in values) > 1024)
            ):
                _error(f"surface {name} is not canonical or bounded")
            result: list[str] = []
            for value in values:
                if paths:
                    safe = _relative_source_path(value)
                    truncated = False
                else:
                    safe, truncated = _sanitize_report_text(value, f"surface {name} entry")
                result.append(safe)
                surface_truncated = surface_truncated or truncated
            return tuple(result)

        ecosystems = safe_values(surface.ecosystems, "ecosystems", paths=False)
        dependency_manifests = safe_values(
            surface.dependency_manifests,
            "dependency_manifests",
            paths=True,
        )
        ci_paths = safe_values(surface.ci_paths, "ci_paths", paths=True)
        iac_paths = safe_values(surface.iac_paths, "iac_paths", paths=True)
        web_paths = safe_values(surface.web_paths, "web_paths", paths=True)
        required_control_ids = safe_values(
            surface.required_control_ids,
            "required_control_ids",
            paths=False,
        )
        for control_id in required_control_ids:
            if not control_id.startswith("SEC-"):
                _error("surface required control ID is invalid")
        counts = (
            (surface.dependency_manifest_count, len(dependency_manifests)),
            (surface.ci_path_count, len(ci_paths)),
            (surface.iac_path_count, len(iac_paths)),
            (surface.web_path_count, len(web_paths)),
        )
        if any(type(count) is not int or count < sampled for count, sampled in counts):
            _error("surface path count is invalid")
        safe_surface = AuditSurface(
            catalog_version=catalog_version,
            snapshot_digest=surface.snapshot_digest,
            ecosystems=ecosystems,
            dependency_manifests=dependency_manifests,
            dependency_manifest_count=surface.dependency_manifest_count,
            ci_paths=ci_paths,
            ci_path_count=surface.ci_path_count,
            iac_paths=iac_paths,
            iac_path_count=surface.iac_path_count,
            web_paths=web_paths,
            web_path_count=surface.web_path_count,
            required_control_ids=required_control_ids,
        )
        surface_truncated = surface_truncated or catalog_truncated

    safe_coverage: list[AuditControlCoverage] = []
    coverage_truncated = False
    for item in model_result.coverage:
        control_id, control_truncated = _sanitize_report_text(
            item.control_id,
            "coverage control_id",
        )
        check_names: list[str] = []
        for raw_name in item.check_names:
            name, name_truncated = _sanitize_report_text(raw_name, "coverage check_name")
            check_names.append(name)
            coverage_truncated = coverage_truncated or name_truncated
        coverage_reason: str | None = None
        reason_truncated = False
        if item.reason is not None:
            coverage_reason, reason_truncated = _sanitize_report_text(
                item.reason,
                "coverage reason",
            )
        safe_coverage.append(
            AuditControlCoverage(
                control_id=control_id,
                category=item.category,
                required=item.required,
                disposition=item.disposition,
                check_names=tuple(sorted(check_names)),
                reason=coverage_reason,
            )
        )
        coverage_truncated = coverage_truncated or control_truncated or reason_truncated
    safe_coverage.sort(key=lambda item: item.control_id)

    safe_receipts = tuple(sorted(command_receipts, key=lambda item: item.sequence))

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
            surface_truncated,
            coverage_truncated,
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
    if schema_version == 1 and (
        safe_surface is not None
        or safe_coverage
        or safe_receipts
        or any(
            finding.control_id is not None
            or finding.fingerprint is not None
            or any(
                isinstance(evidence, SourceEvidence) and evidence.blob_sha256 is not None
                for evidence in finding.evidence
            )
            for finding in sorted_findings
        )
        or any(check.receipt_id is not None for check in safe_checks)
    ):
        _error("schema-v1 reports cannot contain schema-v2 evidence")
    report = AuditReport(
        schema_version=schema_version,
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
        surface=safe_surface,
        coverage=tuple(safe_coverage),
        command_receipts=safe_receipts,
    )
    _validate_report_invariants(report)
    return report


def _evidence_value(evidence: AuditEvidence, *, schema_version: int) -> dict[str, object]:
    if isinstance(evidence, SourceEvidence):
        value: dict[str, object] = {
            "type": "source",
            "path": evidence.path,
            "start_line": evidence.start_line,
            "end_line": evidence.end_line,
            "observation": evidence.observation,
        }
        if schema_version >= 2:
            value["blob_sha256"] = evidence.blob_sha256
        return value
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
    metadata_value: dict[str, object] = {
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
    }
    if report.schema_version >= 2:
        metadata_value["trusted_execution_boundary"] = metadata.trusted_execution_boundary
    value: dict[str, object] = {
        "schema_version": report.schema_version,
        "run_id": report.run_id,
        "repository_id": report.repository_id,
        "status": report.status.value,
        "metadata": metadata_value,
        "summary": report.summary,
        "checks": [
            {
                "name": check.name,
                "disposition": check.disposition.value,
                "duration_seconds": check.duration_seconds,
                "observation": check.observation,
                **({"receipt_id": check.receipt_id} if report.schema_version >= 2 else {}),
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
                "evidence": [
                    _evidence_value(evidence, schema_version=report.schema_version)
                    for evidence in finding.evidence
                ],
                "impact": finding.impact,
                "recommendation": finding.recommendation,
                "verification": finding.verification,
                **(
                    {
                        "control_id": finding.control_id,
                        "fingerprint": finding.fingerprint,
                    }
                    if report.schema_version >= 2
                    else {}
                ),
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
    if report.schema_version >= 2:
        surface = report.surface
        value["surface"] = (
            None
            if surface is None
            else {
                "catalog_version": surface.catalog_version,
                "snapshot_digest": surface.snapshot_digest,
                "ecosystems": list(surface.ecosystems),
                "dependency_manifests": list(surface.dependency_manifests),
                "dependency_manifest_count": surface.dependency_manifest_count,
                "ci_paths": list(surface.ci_paths),
                "ci_path_count": surface.ci_path_count,
                "iac_paths": list(surface.iac_paths),
                "iac_path_count": surface.iac_path_count,
                "web_paths": list(surface.web_paths),
                "web_path_count": surface.web_path_count,
                "required_control_ids": list(surface.required_control_ids),
            }
        )
        value["coverage"] = [
            {
                "control_id": item.control_id,
                "category": item.category.value,
                "required": item.required,
                "disposition": item.disposition.value,
                "check_names": list(item.check_names),
                "reason": item.reason,
            }
            for item in report.coverage
        ]
        value["command_receipts"] = [
            {
                "receipt_id": receipt.receipt_id,
                "sequence": receipt.sequence,
                "command_tag": receipt.command_tag,
                "state": receipt.state,
                "returncode": receipt.returncode,
                "duration_ms": receipt.duration_ms,
                "stdout_bytes": receipt.stdout_bytes,
                "stderr_bytes": receipt.stderr_bytes,
            }
            for receipt in report.command_receipts
        ]
    return value


def _validate_report_invariants(report: AuditReport) -> None:
    if report.schema_version not in {1, REPORT_SCHEMA_VERSION}:
        _error("report schema_version is unsupported")
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
    if report.schema_version == 1:
        if report.surface is not None or report.coverage or report.command_receipts:
            _error("schema-v1 report contains schema-v2 fields")
        if any(check.receipt_id is not None for check in report.checks):
            _error("schema-v1 report contains command receipts")
    receipt_ids: set[str] = set()
    receipts_by_id: dict[str, AuditCommandReceipt] = {}
    for expected_sequence, receipt in enumerate(report.command_receipts, start=1):
        identity_invalid = (
            type(receipt.sequence) is not int
            or receipt.sequence != expected_sequence
            or receipt.receipt_id != f"terminal-{expected_sequence:06d}"
            or receipt.receipt_id in receipt_ids
            or not receipt.command_tag.startswith("hmac-sha256:")
            or len(receipt.command_tag) != len("hmac-sha256:") + 64
            or any(
                character not in "0123456789abcdef"
                for character in receipt.command_tag.removeprefix("hmac-sha256:")
            )
            or receipt.state not in {"exited", "execution_failed", "orphaned", "inflight"}
        )
        if receipt.state == "exited":
            result_invalid = (
                type(receipt.returncode) is not int
                or not -255 <= receipt.returncode <= 255
                or type(receipt.duration_ms) is not int
                or receipt.duration_ms < 0
                or type(receipt.stdout_bytes) is not int
                or receipt.stdout_bytes < 0
                or type(receipt.stderr_bytes) is not int
                or receipt.stderr_bytes < 0
                or receipt.stdout_bytes + receipt.stderr_bytes
                > HARD_LIMITS.terminal_output_per_call_bytes
                or receipt.duration_ms > HARD_LIMITS.overall_seconds * 1000
            )
        else:
            result_invalid = any(
                value is not None
                for value in (
                    receipt.returncode,
                    receipt.duration_ms,
                    receipt.stdout_bytes,
                    receipt.stderr_bytes,
                )
            )
        if identity_invalid or result_invalid:
            _error("report command receipt is invalid")
        receipt_ids.add(receipt.receipt_id)
        receipts_by_id[receipt.receipt_id] = receipt
    used_receipts: set[str] = set()
    checks_by_name = {check.name: check for check in report.checks}
    for check in report.checks:
        if check.receipt_id is None:
            continue
        if check.receipt_id not in receipt_ids or check.receipt_id in used_receipts:
            _error("report check receipt binding is invalid")
        receipt = receipts_by_id[check.receipt_id]
        if receipt.state != "exited" or receipt.returncode is None:
            _error("report checks can only bind exited command receipts")
        expected_disposition = (
            CheckDisposition.passed if receipt.returncode == 0 else CheckDisposition.failed
        )
        if check.disposition is not expected_disposition:
            _error("report check disposition does not match its command receipt")
        used_receipts.add(check.receipt_id)
    if completeness.complete and any(
        check.receipt_id is not None and check.disposition is CheckDisposition.failed
        for check in report.checks
    ):
        _error("a complete report cannot contain a failed receipt-backed check")
    if completeness.complete and used_receipts != receipt_ids:
        _error("a complete report must account for every command receipt")
    if completeness.complete and any(
        receipt.state != "exited" for receipt in report.command_receipts
    ):
        _error("a complete report cannot contain unfinished command receipts")
    if report.coverage != tuple(sorted(report.coverage, key=lambda item: item.control_id)):
        _error("report coverage is not in canonical order")
    if len({item.control_id for item in report.coverage}) != len(report.coverage):
        _error("report coverage control IDs must be unique")
    for item in report.coverage:
        if (
            item.required is not True
            or item.category is not AuditCategory.security
            or not item.control_id.startswith("SEC-")
        ):
            _error("report coverage control is invalid")
        if tuple(sorted(set(item.check_names))) != item.check_names:
            _error("report coverage check names are not canonical")
        if item.disposition in {
            CoverageDisposition.checked,
            CoverageDisposition.not_applicable,
        }:
            if item.required and item.disposition is CoverageDisposition.not_applicable:
                _error("required applicable report coverage cannot be not_applicable")
            if item.reason is not None or not item.check_names:
                _error("accounted report coverage is invalid")
            for name in item.check_names:
                referenced_check = checks_by_name.get(name)
                if referenced_check is None or referenced_check.receipt_id is None:
                    _error("report coverage must reference receipt-backed checks")
        elif item.reason is None or item.check_names:
            _error("uncovered report coverage is invalid")
    if report.surface is None:
        if report.coverage:
            _error("report coverage requires an authoritative surface inventory")
    elif tuple(item.control_id for item in report.coverage) != report.surface.required_control_ids:
        _error("report coverage does not match the authoritative surface inventory")
    for finding in report.findings:
        _sanitize_finding(finding)
        if report.schema_version >= 2:
            if finding.category is AuditCategory.security:
                if report.surface is not None and (
                    finding.control_id is None
                    or finding.control_id not in report.surface.required_control_ids
                ):
                    _error("schema-v2 security finding control is invalid")
            elif finding.control_id is not None:
                _error("schema-v2 non-security finding cannot declare a security control")
        for evidence in finding.evidence:
            if isinstance(evidence, SourceEvidence):
                _relative_source_path(evidence.path)
                if type(evidence.start_line) is not int or evidence.start_line < 1:
                    _error("source evidence start_line must be a positive integer")
                if evidence.end_line is not None and (
                    type(evidence.end_line) is not int or evidence.end_line < evidence.start_line
                ):
                    _error("source evidence end_line must not precede start_line")
                if report.schema_version >= 2 and evidence.blob_sha256 is None:
                    _error("schema-v2 source evidence requires an authoritative blob digest")
            elif isinstance(evidence, CheckEvidence) and evidence.check_name not in check_names:
                _error("check evidence must reference a recorded check")
        if report.schema_version >= 2 and finding.fingerprint is None:
            _error("schema-v2 findings require stable fingerprints")


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
            coverage=report.coverage,
        ),
        surface=report.surface,
        command_receipts=report.command_receipts,
        schema_version=report.schema_version,
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


def _parse_metadata(value: object, *, schema_version: int) -> AuditMetadata:
    metadata = _exact_object(
        value,
        _METADATA_FIELDS if schema_version >= 2 else _LEGACY_METADATA_FIELDS,
        "report metadata",
    )
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
        trusted_execution_boundary=(
            _stored_optional(
                metadata["trusted_execution_boundary"],
                "metadata trusted_execution_boundary",
            )
            if schema_version >= 2
            else None
        ),
    )


def _parse_check(value: object, *, schema_version: int) -> AuditCheck:
    check = _exact_object(
        value,
        _CHECK_FIELDS if schema_version >= 2 else _LEGACY_CHECK_FIELDS,
        "report check",
    )
    return AuditCheck(
        name=_stored_text(check["name"], "check name"),
        disposition=_enum_value(CheckDisposition, check["disposition"], "check disposition"),
        duration_seconds=_check_duration_seconds(check["duration_seconds"]),
        observation=_stored_text(check["observation"], "check observation", allow_empty=True),
        receipt_id=(
            _stored_optional(check["receipt_id"], "check receipt_id")
            if schema_version >= 2
            else None
        ),
    )


def _parse_skipped_content(value: object) -> SkippedContent:
    skipped = _exact_object(value, _SKIPPED_CONTENT_FIELDS, "skipped content")
    return SkippedContent(
        path=_stored_text(skipped["path"], "skipped content path"),
        reason=_stored_text(skipped["reason"], "skipped content reason"),
    )


def _parse_stored_evidence(value: object, *, schema_version: int) -> AuditEvidence:
    if not isinstance(value, dict):
        _error("stored evidence must be an object")
    evidence_type = value.get("type")
    if evidence_type == "source":
        source = _exact_object(
            value,
            _SOURCE_EVIDENCE_FIELDS if schema_version >= 2 else _LEGACY_SOURCE_EVIDENCE_FIELDS,
            "stored source evidence",
        )
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
            blob_sha256=(
                _stored_optional(source["blob_sha256"], "source blob_sha256")
                if schema_version >= 2
                else None
            ),
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


def _parse_stored_finding(value: object, *, schema_version: int) -> AuditFinding:
    finding = _exact_object(
        value,
        _STORED_FINDING_FIELDS if schema_version >= 2 else _LEGACY_STORED_FINDING_FIELDS,
        "stored finding",
    )
    evidence_value = finding["evidence"]
    if not isinstance(evidence_value, list) or not 1 <= len(evidence_value) <= 4:
        _error("stored finding must contain between one and four evidence entries")
    return AuditFinding(
        finding_id=_stored_text(finding["finding_id"], "finding_id"),
        category=_enum_value(AuditCategory, finding["category"], "finding category"),
        severity=_enum_value(AuditSeverity, finding["severity"], "finding severity"),
        confidence=_enum_value(AuditConfidence, finding["confidence"], "finding confidence"),
        title=_stored_text(finding["title"], "finding title"),
        evidence=tuple(
            _parse_stored_evidence(item, schema_version=schema_version) for item in evidence_value
        ),
        impact=_stored_text(finding["impact"], "finding impact"),
        recommendation=_stored_text(finding["recommendation"], "finding recommendation"),
        verification=_stored_text(finding["verification"], "finding verification"),
        control_id=(
            _stored_optional(finding["control_id"], "finding control_id")
            if schema_version >= 2
            else None
        ),
        fingerprint=(
            _stored_optional(finding["fingerprint"], "finding fingerprint")
            if schema_version >= 2
            else None
        ),
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


def _parse_string_tuple(
    value: object,
    name: str,
    *,
    paths: bool = False,
    max_bytes: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 32:
        _error(f"{name} must be a bounded list")
    result = tuple(
        _relative_source_path(item) if paths else _stored_text(item, f"{name} entry")
        for item in value
    )
    if tuple(sorted(set(result))) != result:
        _error(f"{name} must be unique and canonical")
    if max_bytes is not None and sum(len(item.encode("utf-8")) for item in result) > max_bytes:
        _error(f"{name} exceeds its byte limit")
    return result


def _parse_surface(value: object) -> AuditSurface | None:
    if value is None:
        return None
    surface = _exact_object(value, _SURFACE_FIELDS, "report surface")
    snapshot_digest = _stored_text(surface["snapshot_digest"], "surface snapshot_digest")
    if len(snapshot_digest) != 64 or any(
        character not in "0123456789abcdef" for character in snapshot_digest
    ):
        _error("surface snapshot_digest is invalid")
    dependency_manifests = _parse_string_tuple(
        surface["dependency_manifests"],
        "surface dependency_manifests",
        paths=True,
        max_bytes=1024,
    )
    ci_paths = _parse_string_tuple(
        surface["ci_paths"], "surface ci_paths", paths=True, max_bytes=1024
    )
    iac_paths = _parse_string_tuple(
        surface["iac_paths"], "surface iac_paths", paths=True, max_bytes=1024
    )
    web_paths = _parse_string_tuple(
        surface["web_paths"], "surface web_paths", paths=True, max_bytes=1024
    )
    counts = (
        (
            _strict_int(surface["dependency_manifest_count"], "dependency manifest count"),
            dependency_manifests,
        ),
        (_strict_int(surface["ci_path_count"], "CI path count"), ci_paths),
        (_strict_int(surface["iac_path_count"], "IaC path count"), iac_paths),
        (_strict_int(surface["web_path_count"], "web path count"), web_paths),
    )
    if any(count < len(paths) for count, paths in counts):
        _error("surface path count is invalid")
    return AuditSurface(
        catalog_version=_stored_text(surface["catalog_version"], "surface catalog_version"),
        snapshot_digest=snapshot_digest,
        ecosystems=_parse_string_tuple(surface["ecosystems"], "surface ecosystems"),
        dependency_manifests=dependency_manifests,
        dependency_manifest_count=counts[0][0],
        ci_paths=ci_paths,
        ci_path_count=counts[1][0],
        iac_paths=iac_paths,
        iac_path_count=counts[2][0],
        web_paths=web_paths,
        web_path_count=counts[3][0],
        required_control_ids=_parse_string_tuple(
            surface["required_control_ids"],
            "surface required_control_ids",
        ),
    )


def _parse_control_coverage(value: object) -> AuditControlCoverage:
    item = _exact_object(value, _CONTROL_COVERAGE_FIELDS, "report coverage")
    reason = _stored_optional(item["reason"], "coverage reason")
    return AuditControlCoverage(
        control_id=_stored_text(item["control_id"], "coverage control_id"),
        category=_enum_value(AuditCategory, item["category"], "coverage category"),
        required=_strict_bool(item["required"], "coverage required"),
        disposition=_enum_value(
            CoverageDisposition,
            item["disposition"],
            "coverage disposition",
        ),
        check_names=_parse_string_tuple(item["check_names"], "coverage check_names"),
        reason=reason,
    )


def _optional_stored_int(value: object, name: str, *, minimum: int = 0) -> int | None:
    return None if value is None else _strict_int(value, name, minimum=minimum)


def _parse_command_receipt(value: object) -> AuditCommandReceipt:
    receipt = _exact_object(value, _COMMAND_RECEIPT_FIELDS, "report command receipt")
    return AuditCommandReceipt(
        receipt_id=_stored_text(receipt["receipt_id"], "receipt_id"),
        sequence=_strict_int(receipt["sequence"], "receipt sequence", minimum=1),
        command_tag=_stored_text(receipt["command_tag"], "receipt command_tag"),
        state=_stored_text(receipt["state"], "receipt state"),
        returncode=_optional_stored_int(
            receipt["returncode"],
            "receipt returncode",
            minimum=-255,
        ),
        duration_ms=_optional_stored_int(receipt["duration_ms"], "receipt duration_ms"),
        stdout_bytes=_optional_stored_int(receipt["stdout_bytes"], "receipt stdout_bytes"),
        stderr_bytes=_optional_stored_int(receipt["stderr_bytes"], "receipt stderr_bytes"),
    )


def parse_audit_report(data: bytes, *, max_bytes: int) -> AuditReport:
    value = _load_json(data, max_bytes=max_bytes, name="audit report")
    if not isinstance(value, dict):
        _error("audit report must be an object")
    schema_version = _strict_int(value.get("schema_version"), "schema_version")
    if schema_version not in {1, REPORT_SCHEMA_VERSION}:
        _error("report schema_version is unsupported")
    stored = _exact_object(
        value,
        _REPORT_FIELDS if schema_version >= 2 else _LEGACY_REPORT_FIELDS,
        "audit report",
    )
    checks_value = stored["checks"]
    skipped_value = stored["skipped_content"]
    findings_value = stored["findings"]
    if not isinstance(checks_value, list):
        _error("report checks must be a list")
    if not isinstance(skipped_value, list):
        _error("report skipped_content must be a list")
    if not isinstance(findings_value, list):
        _error("report findings must be a list")
    coverage_value = stored.get("coverage", [])
    receipts_value = stored.get("command_receipts", [])
    if not isinstance(coverage_value, list):
        _error("report coverage must be a list")
    if not isinstance(receipts_value, list):
        _error("report command_receipts must be a list")
    report = AuditReport(
        schema_version=schema_version,
        run_id=_stored_text(stored["run_id"], "run_id"),
        repository_id=_stored_text(stored["repository_id"], "repository_id"),
        status=_enum_value(AuditStatus, stored["status"], "report status"),
        metadata=_parse_metadata(stored["metadata"], schema_version=schema_version),
        summary=_stored_text(stored["summary"], "report summary"),
        checks=tuple(_parse_check(check, schema_version=schema_version) for check in checks_value),
        skipped_content=tuple(_parse_skipped_content(item) for item in skipped_value),
        findings=tuple(
            _parse_stored_finding(finding, schema_version=schema_version)
            for finding in findings_value
        ),
        severity_counts=_parse_counts(stored["severity_counts"]),
        completeness=_parse_completeness(stored["completeness"]),
        surface=_parse_surface(stored.get("surface")) if schema_version >= 2 else None,
        coverage=tuple(_parse_control_coverage(item) for item in coverage_value),
        command_receipts=tuple(_parse_command_receipt(item) for item in receipts_value),
    )
    _validate_report_invariants(report)
    return report
