from __future__ import annotations

import unittest

from zeus.audit_models import AuditCategory
from zeus.audit_surface import (
    SECURITY_CONTROL_CATALOG_VERSION,
    build_audit_surface,
)
from zeus.audit_workspace import SnapshotManifestEntry


def _entry(path: str, *, digest: str = "a" * 64, size: int = 10) -> SnapshotManifestEntry:
    return SnapshotManifestEntry(
        path=path,
        object_id="b" * 40,
        git_mode="100644",
        mode=0o600,
        size=size,
        sha256=digest,
    )


class AuditSurfaceTests(unittest.TestCase):
    def test_inventory_is_canonical_and_selects_applicable_security_controls(self) -> None:
        entries = (
            _entry("infra/main.tf", digest="1" * 64),
            _entry("src/server.py", digest="2" * 64),
            _entry("package-lock.json", digest="3" * 64),
            _entry(".github/workflows/ci.yml", digest="4" * 64),
            _entry("Cargo.toml", digest="5" * 64),
            _entry("src/lib.rs", digest="6" * 64),
            _entry("routes/api.ts", digest="7" * 64),
        )

        first = build_audit_surface(entries, frozenset({AuditCategory.security}))
        second = build_audit_surface(tuple(reversed(entries)), frozenset({AuditCategory.security}))

        self.assertEqual(first, second)
        self.assertEqual(SECURITY_CONTROL_CATALOG_VERSION, first.catalog_version)
        self.assertEqual(
            ("javascript", "python", "rust", "terraform"),
            first.ecosystems,
        )
        self.assertEqual(("Cargo.toml", "package-lock.json"), first.dependency_manifests)
        self.assertEqual((".github/workflows/ci.yml",), first.ci_paths)
        self.assertEqual(("infra/main.tf",), first.iac_paths)
        self.assertEqual(("routes/api.ts", "src/server.py"), first.web_paths)
        self.assertEqual(
            ("SEC-CI", "SEC-DEPS", "SEC-IAC", "SEC-NATIVE", "SEC-REPO", "SEC-WEB"),
            first.required_control_ids,
        )
        self.assertRegex(first.snapshot_digest, r"^[0-9a-f]{64}$")

    def test_inventory_digest_binds_path_mode_size_and_blob_digest(self) -> None:
        baseline = build_audit_surface(
            (_entry("src/app.py", digest="1" * 64),),
            frozenset({AuditCategory.security}),
        )

        changed = build_audit_surface(
            (_entry("src/app.py", digest="2" * 64),),
            frozenset({AuditCategory.security}),
        )

        self.assertNotEqual(baseline.snapshot_digest, changed.snapshot_digest)

    def test_zeus_http_modules_require_web_security_coverage(self) -> None:
        entries = (
            _entry("zeus/api.py"),
            _entry("zeus/api_errors.py"),
            _entry("zeus/api_logging.py"),
            _entry("zeus/api_request.py"),
            _entry("zeus/api_server.py"),
            _entry("zeus/worker.py"),
        )

        surface = build_audit_surface(entries, frozenset({AuditCategory.security}))

        self.assertEqual(
            (
                "zeus/api.py",
                "zeus/api_errors.py",
                "zeus/api_logging.py",
                "zeus/api_request.py",
                "zeus/api_server.py",
            ),
            surface.web_paths,
        )
        self.assertEqual(5, surface.web_path_count)
        self.assertIn("SEC-WEB", surface.required_control_ids)

    def test_non_security_audit_records_surface_without_security_requirements(self) -> None:
        surface = build_audit_surface(
            (_entry("src/app.py"), _entry("requirements.txt")),
            frozenset({AuditCategory.correctness}),
        )

        self.assertEqual(("python",), surface.ecosystems)
        self.assertEqual((), surface.required_control_ids)

    def test_relevant_path_samples_are_bounded(self) -> None:
        entries = tuple(_entry(f"packages/p{index}/package.json") for index in range(100))

        surface = build_audit_surface(entries, frozenset({AuditCategory.security}))

        self.assertEqual(32, len(surface.dependency_manifests))
        self.assertEqual(100, surface.dependency_manifest_count)

    def test_relevant_path_samples_have_a_deterministic_byte_budget(self) -> None:
        entries = tuple(_entry(f"routes/{'a' * 240}-{index}.py") for index in range(40))

        surface = build_audit_surface(entries, frozenset({AuditCategory.security}))

        self.assertLessEqual(
            sum(len(path.encode("utf-8")) for path in surface.web_paths),
            1024,
        )
        self.assertGreater(surface.web_path_count, len(surface.web_paths))


if __name__ == "__main__":
    unittest.main()
