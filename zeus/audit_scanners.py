from __future__ import annotations

import string
from collections.abc import Callable
from dataclasses import dataclass

from zeus.audit_models import AuditSurface
from zeus.audit_surface import SECURITY_CONTROL_CATALOG_VERSION, SECURITY_CONTROL_IDS

SCANNER_REGISTRY_VERSION = "1.0.0"
_SCANNER_OUTPUT_LIMIT_BYTES = 1024 * 1024
_NATIVE_ECOSYSTEMS = frozenset({"c", "cpp", "go", "rust"})


class AuditScannerRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class AuditScannerAdapterSpec:
    """A fixed, non-executable contract for a future scanner integration."""

    adapter_id: str
    control_ids: tuple[str, ...]
    input_selector: str
    input_contract: str = "zeus.committed-snapshot/v1"
    output_contract: str = "zeus.audit-scanner-result/v1"
    output_limit_bytes: int = _SCANNER_OUTPUT_LIMIT_BYTES
    committed_snapshot_only: bool = True
    read_only: bool = True
    network_allowed: bool = False
    shell_allowed: bool = False
    dynamic_plugins_allowed: bool = False
    execution_available: bool = False


def _adapter(
    adapter_id: str,
    control_id: str,
    input_selector: str,
) -> AuditScannerAdapterSpec:
    return AuditScannerAdapterSpec(
        adapter_id=adapter_id,
        control_ids=(control_id,),
        input_selector=input_selector,
    )


SCANNER_ADAPTER_REGISTRY = (
    _adapter("zeus.ci-policy.v1", "SEC-CI", "ci_paths"),
    _adapter("zeus.dependency-advisory.v1", "SEC-DEPS", "dependency_manifests"),
    _adapter("zeus.iac-policy.v1", "SEC-IAC", "iac_paths"),
    _adapter("zeus.native-analysis.v1", "SEC-NATIVE", "native_ecosystems"),
    _adapter("zeus.repository-policy.v1", "SEC-REPO", "manifest"),
    _adapter("zeus.web-analysis.v1", "SEC-WEB", "web_paths"),
)


def _repo_applicable(_surface: AuditSurface) -> bool:
    return True


def _dependencies_applicable(surface: AuditSurface) -> bool:
    return surface.dependency_manifest_count > 0


def _ci_applicable(surface: AuditSurface) -> bool:
    return surface.ci_path_count > 0


def _iac_applicable(surface: AuditSurface) -> bool:
    return surface.iac_path_count > 0


def _native_applicable(surface: AuditSurface) -> bool:
    return bool(set(surface.ecosystems).intersection(_NATIVE_ECOSYSTEMS))


def _web_applicable(surface: AuditSurface) -> bool:
    return surface.web_path_count > 0


_CONTROL_APPLICABILITY: dict[str, Callable[[AuditSurface], bool]] = {
    "SEC-CI": _ci_applicable,
    "SEC-DEPS": _dependencies_applicable,
    "SEC-IAC": _iac_applicable,
    "SEC-NATIVE": _native_applicable,
    "SEC-REPO": _repo_applicable,
    "SEC-WEB": _web_applicable,
}


def _validate_surface(surface: AuditSurface) -> frozenset[str]:
    if not isinstance(surface, AuditSurface):
        raise AuditScannerRegistryError("scanner selection requires an audit surface")
    if surface.catalog_version != SECURITY_CONTROL_CATALOG_VERSION:
        raise AuditScannerRegistryError("unsupported audit surface catalog version")
    if (
        len(surface.snapshot_digest) != 64
        or any(character not in string.hexdigits for character in surface.snapshot_digest)
        or surface.snapshot_digest.lower() != surface.snapshot_digest
    ):
        raise AuditScannerRegistryError("audit surface snapshot digest is invalid")

    required_values = surface.required_control_ids
    if len(required_values) != len(set(required_values)):
        raise AuditScannerRegistryError("audit surface has duplicate required controls")
    required = frozenset(required_values)
    if frozenset(_CONTROL_APPLICABILITY) != SECURITY_CONTROL_IDS:
        raise AuditScannerRegistryError("security control catalog implementation is inconsistent")
    unknown = sorted(required.difference(_CONTROL_APPLICABILITY))
    if unknown:
        raise AuditScannerRegistryError(f"unsupported required control: {unknown[0]}")
    for control_id in required:
        if not _CONTROL_APPLICABILITY[control_id](surface):
            raise AuditScannerRegistryError(
                f"required control {control_id} is inconsistent with the audit surface"
            )
    if required:
        expected = frozenset(
            control_id
            for control_id, applicable in _CONTROL_APPLICABILITY.items()
            if applicable(surface)
        )
        if required != expected:
            raise AuditScannerRegistryError(
                "required controls do not match the complete applicable security surface"
            )
    return required


def select_audit_scanner_adapters(
    surface: AuditSurface,
) -> tuple[AuditScannerAdapterSpec, ...]:
    """Select fixed adapter contracts for a surface without executing scanners."""

    required = _validate_surface(surface)
    return tuple(
        spec
        for spec in SCANNER_ADAPTER_REGISTRY
        if any(control_id in required for control_id in spec.control_ids)
    )
