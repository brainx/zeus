from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from subprocess import DEVNULL, run


class AuditServiceContractTests(unittest.TestCase):
    def test_public_service_interface_is_available(self) -> None:
        from zeus.audit import AuditService

        self.assertTrue(callable(AuditService.from_cwd))
        for name in ("doctor", "run", "list_reports", "show", "show_markdown"):
            self.assertTrue(callable(getattr(AuditService, name)))

    def test_default_state_dir_is_repository_local_after_discovery(self) -> None:
        from zeus.audit import AuditService

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run(("git", "init", "-q", str(root)), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "config", "user.email", "test@example.invalid"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "config", "user.name", "Test"), check=True, stdin=DEVNULL)
            (root / "README").write_text("test\n", encoding="utf-8")
            run(("git", "-C", str(root), "add", "README"), check=True, stdin=DEVNULL)
            run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True, stdin=DEVNULL)
            service = AuditService.from_cwd(cwd=root, env={})
            self.assertEqual(root / ".zeus", service.settings.state_dir)

    def test_run_blocks_after_lock_and_persists_a_report_when_preflight_fails(self) -> None:
        from zeus.audit import AuditService
        from zeus.audit_models import AuditStatus

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run(("git", "init", "-q", str(root)), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "config", "user.email", "test@example.invalid"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "config", "user.name", "Test"), check=True, stdin=DEVNULL)
            (root / ".gitignore").write_text(".zeus/\n", encoding="utf-8")
            (root / "README").write_text("test\n", encoding="utf-8")
            run(("git", "-C", str(root), "add", ".gitignore", "README"), check=True, stdin=DEVNULL)
            run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True, stdin=DEVNULL)

            report = AuditService.from_cwd(
                cwd=root,
                env={"ZEUS_HERMES_BIN": "missing-hermes-for-test"},
            ).run()

            self.assertEqual(AuditStatus.blocked, report.status)
            self.assertTrue((root / ".zeus" / "audits" / report.run_id / "report.json").is_file())
            self.assertFalse((root / ".zeus" / "zeus.db").exists())

    def test_run_rejects_tracked_in_repository_state_before_creating_a_report(self) -> None:
        from zeus.audit import AuditService, AuditServiceError

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            run(("git", "init", "-q", str(root)), check=True, stdin=DEVNULL)
            run(
                ("git", "-C", str(root), "config", "user.email", "test@example.invalid"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "config", "user.name", "Test"), check=True, stdin=DEVNULL)
            config = root / ".zeus" / "audit" / "config.json"
            config.parent.mkdir(parents=True)
            config.write_text('{"schema_version":1}\n', encoding="utf-8")
            run(
                ("git", "-C", str(root), "add", ".zeus/audit/config.json"),
                check=True,
                stdin=DEVNULL,
            )
            run(("git", "-C", str(root), "commit", "-qm", "initial"), check=True, stdin=DEVNULL)

            with self.assertRaisesRegex(AuditServiceError, "tracked"):
                AuditService.from_cwd(cwd=root, env={}).run()

            self.assertFalse((root / ".zeus" / "audits").exists())


if __name__ == "__main__":
    unittest.main()
