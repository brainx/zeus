from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from zeus.audit_models import HARD_LIMITS
from zeus.audit_workspace import (
    GIT_HARDENING_ARGUMENTS,
    AuditWorkspace,
    AuditWorkspaceError,
    RepositoryInspection,
)


def _deadline() -> float:
    return time.monotonic() + 15


class GitIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.temp_root = Path(self.temporary_directory.name).resolve()
        self.repository = self.temp_root / "repository"
        self.repository.mkdir(mode=0o700)
        self.git("init", "--quiet", "--object-format=sha1")
        self.git("config", "user.name", "Audit Test")
        self.git("config", "user.email", "audit@example.invalid")
        (self.repository / "tracked.txt").write_bytes(b"committed source\n")
        self.git("add", "tracked.txt")
        self.git("commit", "--quiet", "-m", "initial")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def git(
        self,
        *arguments: str,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            ["git", "-C", str(self.repository if cwd is None else cwd), *arguments],
            capture_output=True,
            check=False,
            shell=False,
            timeout=10,
        )
        if completed.returncode != 0:
            self.fail(
                f"git {' '.join(arguments)} failed with {completed.returncode}: "
                f"{completed.stderr.decode('utf-8', errors='replace')}"
            )
        return completed

    def _inspection(self, workspace: AuditWorkspace) -> RepositoryInspection:
        location = workspace.discover(self.repository, deadline=_deadline())
        return workspace.inspect(location, deadline=_deadline())

    def test_linked_worktree_discovers_distinct_git_and_common_directories(self) -> None:
        linked = self.temp_root / "linked"
        self.git("worktree", "add", "--quiet", "--detach", str(linked))
        workspace = AuditWorkspace()

        location = workspace.discover(linked, deadline=_deadline())

        self.assertEqual(linked, location.root)
        self.assertNotEqual(location.git_dir, location.common_git_dir)
        self.assertEqual(self.repository / ".git", location.common_git_dir)
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=linked).stdout.decode("ascii").strip(),
            location.head,
        )

    def test_every_git_process_uses_exact_hardening_and_a_minimal_environment(self) -> None:
        resolved_git = shutil.which("git")
        self.assertIsNotNone(resolved_git)
        assert resolved_git is not None
        git_path = str(Path(resolved_git).resolve(strict=True))
        wrapper = self.temp_root / "git-wrapper"
        log_path = wrapper.with_suffix(".jsonl")
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, subprocess, sys\n"
            f"log = pathlib.Path({str(log_path)!r})\n"
            "with log.open('a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps({'argv': sys.argv[1:], "
            "'env': dict(os.environ)}, sort_keys=True) + '\\n')\n"
            f"raise SystemExit(subprocess.run([{git_path!r}, *sys.argv[1:]], "
            "env=dict(os.environ), check=False).returncode)\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        workspace = AuditWorkspace(git_executable=wrapper)
        injected = {
            "GIT_DIR": "/caller/git",
            "GIT_WORK_TREE": "/caller/worktree",
            "GIT_INDEX_FILE": "/caller/index",
            "GIT_OBJECT_DIRECTORY": "/caller/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/caller/alternates",
            "GIT_ASKPASS": "/caller/askpass",
            "SSH_AUTH_SOCK": "/caller/ssh",
            "HTTPS_PROXY": "http://caller-proxy.invalid",
            "DOCKER_HOST": "unix:///caller/docker.sock",
            "OPENAI_API_KEY": "provider-secret-sentinel",
        }
        with patch.dict(os.environ, injected, clear=False):
            inspection = self._inspection(workspace)
            snapshot = workspace.materialize(
                inspection,
                self.temp_root / "snapshot",
                exclude_paths=(),
                limits=HARD_LIMITS,
                deadline=_deadline(),
            )
        workspace.validate_snapshot(snapshot)

        invocations = [
            json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertGreaterEqual(len(invocations), 1)
        expected_prefix = list(GIT_HARDENING_ARGUMENTS)
        forbidden_names = set(injected) - {"GIT_ASKPASS"}
        allowed_git_names = {
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_ATTR_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "GIT_ASKPASS",
            "GIT_SSH_COMMAND",
            "GIT_OPTIONAL_LOCKS",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_PAGER",
        }
        for invocation in invocations:
            argv = invocation["argv"]
            self.assertEqual(expected_prefix, argv[: len(expected_prefix)])
            environment = invocation["env"]
            self.assertTrue(forbidden_names.isdisjoint(environment))
            self.assertEqual("C", environment["LC_ALL"])
            self.assertEqual("C", environment["LANG"])
            self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])
            self.assertEqual(os.devnull, environment["GIT_ASKPASS"])
            self.assertNotEqual(injected["GIT_ASKPASS"], environment["GIT_ASKPASS"])
            self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])
            self.assertEqual("1", environment["GIT_NO_REPLACE_OBJECTS"])
            self.assertTrue(
                {name for name in environment if name.startswith("GIT_")}.issubset(
                    allowed_git_names
                )
            )

        commands = [
            next(
                command
                for command in ("rev-parse", "status", "for-each-ref", "ls-tree", "cat-file")
                if command in invocation["argv"]
            )
            for invocation in invocations
        ]
        self.assertEqual(1, commands.count("cat-file"))
        self.assertNotIn(
            True,
            [
                forbidden in invocation["argv"]
                for invocation in invocations
                for forbidden in ("checkout", "archive", "submodule", "fetch", "diff")
            ],
        )

    def test_success_and_failure_leave_real_worktree_status_and_contents_unchanged(
        self,
    ) -> None:
        workspace = AuditWorkspace()
        dirty = b"dirty source sentinel\n"
        untracked = b"untracked source sentinel\n"
        (self.repository / "tracked.txt").write_bytes(dirty)
        (self.repository / "untracked.txt").write_bytes(untracked)
        status_before = self.git(
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
        ).stdout
        inspection = self._inspection(workspace)

        snapshot = workspace.materialize(
            inspection,
            self.temp_root / "successful",
            exclude_paths=(),
            limits=HARD_LIMITS,
            deadline=_deadline(),
        )
        self.assertEqual(b"committed source\n", (snapshot.root / "tracked.txt").read_bytes())
        with self.assertRaises(AuditWorkspaceError):
            workspace.materialize(
                inspection,
                self.temp_root / "failed",
                exclude_paths=(),
                limits=HARD_LIMITS,
                deadline=time.monotonic() - 1,
            )

        status_after = self.git(
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
        ).stdout
        self.assertEqual(status_before, status_after)
        self.assertEqual(dirty, (self.repository / "tracked.txt").read_bytes())
        self.assertEqual(untracked, (self.repository / "untracked.txt").read_bytes())
        self.assertFalse((self.temp_root / "failed").exists())

    def test_materialized_host_permissions_are_private_and_preserve_executable_bit(
        self,
    ) -> None:
        executable = self.repository / "run"
        executable.write_bytes(b"#!/bin/sh\n")
        executable.chmod(0o755)
        self.git("add", "run")
        self.git("commit", "--quiet", "-m", "executable")
        workspace = AuditWorkspace()

        snapshot = workspace.materialize(
            self._inspection(workspace),
            self.temp_root / "snapshot",
            exclude_paths=(),
            limits=HARD_LIMITS,
            deadline=_deadline(),
        )

        self.assertEqual(0o700, stat.S_IMODE(snapshot.root.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((snapshot.root / "tracked.txt").stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE((snapshot.root / "run").stat().st_mode))
