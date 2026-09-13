from __future__ import annotations

import ast
import io
import json
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.test_audit_store import _report
from zeus.audit import AuditService
from zeus.audit_store import AuditStore
from zeus.cli import main

ROOT = Path(__file__).resolve().parents[1]


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
    return names


class SubsystemBoundaryTests(unittest.TestCase):
    def test_runtime_and_audit_have_no_lifecycle_storage_dependencies(self) -> None:
        forbidden = {"sqlite3", "zeus.sqlite_db", "zeus.schema", "zeus.state"}
        paths = [*ROOT.glob("zeus/gateway_runtime*.py"), *ROOT.glob("zeus/audit*.py")]
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(module=path.name):
                imports = _imports(path)
                self.assertFalse(imports & forbidden, imports & forbidden)
                if path.name.startswith("audit"):
                    self.assertNotIn("zeus.supervisor", imports)

    def test_profile_transactions_do_not_signal_processes(self) -> None:
        path = ROOT / "zeus/profile_manager.py"
        self.assertNotIn("subprocess", _imports(path))
        forbidden = {"kill", "killpg", "pidfd_send_signal", "Popen"}
        calls = {
            node.func.attr
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(calls & forbidden, calls & forbidden)

    def test_stored_audit_cli_works_without_runtime_or_lifecycle_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary).resolve() / "state"
            service = AuditService.from_cwd(cwd=ROOT, env={"ZEUS_STATE_DIR": str(state)})
            report = _report("a" * 32)
            report = replace(
                report,
                repository_id=service.location.repository_id,
                metadata=replace(report.metadata, target_commit=service.location.head),
            )
            artifacts = AuditStore(state).install(report)
            database = state / "zeus.db"
            database.write_bytes(b"unavailable lifecycle database")
            before = {
                p: p.read_bytes() for p in (artifacts.json_path, artifacts.markdown_path, database)
            }
            real_popen = subprocess.Popen

            def only_git(command, *args, **kwargs):
                self.assertIsInstance(command, (list, tuple))
                self.assertEqual("git", Path(command[0]).name)
                return real_popen(command, *args, **kwargs)

            with ExitStack() as stack:
                for target in (
                    "zeus.cli._services",
                    "zeus.state.StateStore.init",
                    "zeus.state.StateStore.migrate",
                    "zeus.audit.AuditContainerRuntime.__init__",
                    "zeus.audit.AuditRunner.__init__",
                    "zeus.audit.run_audit_doctor",
                ):
                    stack.enter_context(patch(target, side_effect=AssertionError(target)))
                stack.enter_context(
                    patch.object(sqlite3, "connect", side_effect=AssertionError("SQL"))
                )
                stack.enter_context(patch("subprocess.Popen", side_effect=only_git))
                stack.enter_context(patch.object(AuditService, "from_cwd", return_value=service))
                for action in ("list", "show", "gate"):
                    with self.subTest(action=action), redirect_stdout(io.StringIO()) as output:
                        args = ["audit", action]
                        if action != "list":
                            args.append(report.run_id)
                        result = main([*args, "--json"])
                        payload = json.loads(output.getvalue())
                        if action == "gate":
                            self.assertEqual(1, result)
                            self.assertFalse(payload["passed"])
                        else:
                            self.assertEqual(0, result)
                            item = payload[0] if action == "list" else payload
                            self.assertEqual(report.run_id, item["run_id"])
            self.assertEqual(before, {p: p.read_bytes() for p in before})
            self.assertFalse((state / "audit").exists())
