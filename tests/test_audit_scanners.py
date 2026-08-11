from __future__ import annotations

import unittest

from zeus.audit_models import AuditSurface
from zeus.audit_scanners import (
    SCANNER_ADAPTER_REGISTRY,
    AuditScannerRegistryError,
    select_audit_scanner_adapters,
)


def _surface(
    *,
    required_control_ids: tuple[str, ...],
    ecosystems: tuple[str, ...] = (),
    dependency_manifest_count: int = 0,
    ci_path_count: int = 0,
    iac_path_count: int = 0,
    web_path_count: int = 0,
    catalog_version: str = "1.0.0",
) -> AuditSurface:
    return AuditSurface(
        catalog_version=catalog_version,
        snapshot_digest="a" * 64,
        ecosystems=ecosystems,
        dependency_manifests=("requirements.txt",) if dependency_manifest_count else (),
        dependency_manifest_count=dependency_manifest_count,
        ci_paths=(".github/workflows/ci.yml",) if ci_path_count else (),
        ci_path_count=ci_path_count,
        iac_paths=("infra/main.tf",) if iac_path_count else (),
        iac_path_count=iac_path_count,
        web_paths=("routes/api.py",) if web_path_count else (),
        web_path_count=web_path_count,
        required_control_ids=required_control_ids,
    )


class AuditScannerRegistryTests(unittest.TestCase):
    def test_registry_is_fixed_metadata_with_non_executable_constraints(self) -> None:
        adapter_ids = tuple(spec.adapter_id for spec in SCANNER_ADAPTER_REGISTRY)

        self.assertEqual(tuple(sorted(adapter_ids)), adapter_ids)
        self.assertEqual(len(adapter_ids), len(set(adapter_ids)))
        self.assertEqual(
            {
                "SEC-CI",
                "SEC-DEPS",
                "SEC-IAC",
                "SEC-NATIVE",
                "SEC-REPO",
                "SEC-WEB",
            },
            {control_id for spec in SCANNER_ADAPTER_REGISTRY for control_id in spec.control_ids},
        )
        for spec in SCANNER_ADAPTER_REGISTRY:
            with self.subTest(adapter_id=spec.adapter_id):
                self.assertEqual("zeus.committed-snapshot/v1", spec.input_contract)
                self.assertEqual("zeus.audit-scanner-result/v1", spec.output_contract)
                self.assertGreater(spec.output_limit_bytes, 0)
                self.assertTrue(spec.committed_snapshot_only)
                self.assertTrue(spec.read_only)
                self.assertFalse(spec.network_allowed)
                self.assertFalse(spec.shell_allowed)
                self.assertFalse(spec.dynamic_plugins_allowed)
                self.assertFalse(spec.execution_available)
                self.assertFalse(hasattr(spec, "command"))
                self.assertFalse(hasattr(spec, "entry_point"))

    def test_selection_is_deterministic_and_uses_surface_applicability(self) -> None:
        surface = _surface(
            required_control_ids=(
                "SEC-WEB",
                "SEC-REPO",
                "SEC-NATIVE",
                "SEC-IAC",
                "SEC-DEPS",
                "SEC-CI",
            ),
            ecosystems=("python", "rust"),
            dependency_manifest_count=1,
            ci_path_count=1,
            iac_path_count=1,
            web_path_count=1,
        )

        selected = select_audit_scanner_adapters(surface)

        self.assertEqual(
            (
                "zeus.ci-policy.v1",
                "zeus.dependency-advisory.v1",
                "zeus.iac-policy.v1",
                "zeus.native-analysis.v1",
                "zeus.repository-policy.v1",
                "zeus.web-analysis.v1",
            ),
            tuple(spec.adapter_id for spec in selected),
        )

    def test_non_security_surface_selects_no_adapters(self) -> None:
        surface = _surface(
            required_control_ids=(),
            ecosystems=("python",),
            dependency_manifest_count=1,
            web_path_count=1,
        )

        self.assertEqual((), select_audit_scanner_adapters(surface))

    def test_unknown_catalog_or_inconsistent_required_control_fails_closed(self) -> None:
        with self.assertRaisesRegex(AuditScannerRegistryError, "catalog"):
            select_audit_scanner_adapters(
                _surface(required_control_ids=("SEC-REPO",), catalog_version="2.0.0")
            )
        with self.assertRaisesRegex(AuditScannerRegistryError, "SEC-DEPS"):
            select_audit_scanner_adapters(_surface(required_control_ids=("SEC-DEPS",)))

        with self.assertRaisesRegex(AuditScannerRegistryError, "complete applicable"):
            select_audit_scanner_adapters(
                _surface(
                    required_control_ids=("SEC-REPO",),
                    dependency_manifest_count=1,
                )
            )


if __name__ == "__main__":
    unittest.main()
