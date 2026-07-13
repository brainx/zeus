from __future__ import annotations

import http.client
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.api import main as api_main
from zeus.api import make_handler
from zeus.cli import _services, build_parser
from zeus.cli import main as cli_main
from zeus.config import Settings
from zeus.doctor import _check_runtime_paths, run_doctor
from zeus.errors import BotArchiveError, BotDeleteError
from zeus.hermes_adapter import HermesAdapter
from zeus.lifecycle import LifecycleEventInput
from zeus.logging_utils import redact_secrets
from zeus.models import BotRecord, BotStatus, BotStatusResponse, DesiredState, RestartPolicy
from zeus.process_lock import LockTimeoutError
from zeus.readiness import ReadinessResult
from zeus.reconciliation import BotReconcileResult, ReconcileOutcome, ReconcileRunSummary
from zeus.state import StateStore
from zeus.supervisor import (
    Supervisor,
    _read_darwin_process_start_fingerprint,
    _read_linux_cmdline,
    _read_linux_process_start_fingerprint,
    _read_process_cmdline,
    _verify_gateway_command,
)


class FakePopen:
    returncode: int | None = None
    launch_count = 0

    def __init__(self, argv, env, stdout, stderr, **kwargs):
        FakePopen.launch_count += 1
        self.argv = argv
        self.env = env
        self.stdout = stdout
        self.stderr = stderr
        self.kwargs = kwargs
        self.pid = 4321
        _emulate_launcher_handshake(argv, self.pid)

    def poll(self) -> int | None:
        return self.returncode


def _emulate_launcher_handshake(argv: list[str], pid: int) -> None:
    payload_fd = os.dup(int(argv[-2]))
    ack_fd = os.dup(int(argv[-1]))

    def publish() -> None:
        try:
            chunks: list[bytes] = []
            while chunk := os.read(payload_fd, 65536):
                chunks.append(chunk)
            payload = json.loads(b"".join(chunks))
            marker = dict(payload["marker"])
            marker.update(
                {
                    "pid": pid,
                    "started_at": time.time(),
                    "proc_start_fingerprint": f"test-process-start:{pid}",
                }
            )
            marker_path = Path(payload["marker_path"])
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.write_text(json.dumps(marker), encoding="utf-8")
            os.write(ack_fd, b"1")
        finally:
            os.close(payload_fd)
            os.close(ack_fd)

    threading.Thread(target=publish, daemon=True).start()


class ExitedPopen(FakePopen):
    returncode = 7


class MissingHermesPopen:
    def __init__(self, argv, env, stdout, stderr, **kwargs):
        raise FileNotFoundError("missing hermes")


class PermissionDeniedPopen:
    def __init__(self, argv, env, stdout, stderr, **kwargs):
        raise PermissionError("permission denied")


class SupervisorCliApiTests(unittest.TestCase):
    def setUp(self) -> None:
        FakePopen.launch_count = 0

    def _run_cli(self, argv: list[str]) -> str:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, cli_main(argv))
        return stdout.getvalue()

    def _run_cli_failure(self, argv: list[str]) -> str:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(1, cli_main(argv))
        return stdout.getvalue()

    def _fake_hermes_path(self, root: Path) -> str:
        hermes = root / "bin" / "hermes"
        hermes.parent.mkdir(parents=True, exist_ok=True)
        hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        hermes.chmod(0o755)
        return str(hermes.resolve())

    def _gateway_argv(self, hermes_bin: str, bot_id: str = "coder") -> list[str]:
        return [hermes_bin, "-p", bot_id, "gateway", "run"]

    def _supervisor_for_profile_path(
        self,
        root: Path,
        profile_path: Path,
        *,
        bot_id: str = "coder",
    ) -> tuple[StateStore, Supervisor]:
        store = StateStore(root / "zeus.db")
        store.init()
        store.upsert_bot(
            BotRecord(
                bot_id=bot_id,
                template_id="coding-bot",
                display_name=bot_id,
                profile_path=str(profile_path),
            )
        )
        return store, Supervisor(store, "hermes", root / ".zeus" / "hermes")

    def _assert_delete_refuses_profile_path(self, root: Path, profile_path: Path) -> None:
        profile_path.mkdir(parents=True, exist_ok=True)
        sentinel = profile_path / "sentinel.txt"
        sentinel.write_text("keep\n", encoding="utf-8")
        store, supervisor = self._supervisor_for_profile_path(root, profile_path)

        with self.assertRaises(BotDeleteError):
            supervisor.delete_bot("coder", remove_profile=True)

        self.assertTrue(sentinel.is_file())
        self.assertIsNotNone(store.get_bot("coder"))

    def _assert_archive_refuses_profile_path(self, root: Path, profile_path: Path) -> None:
        profile_path.mkdir(parents=True, exist_ok=True)
        sentinel = profile_path / "sentinel.txt"
        sentinel.write_text("keep\n", encoding="utf-8")
        store, supervisor = self._supervisor_for_profile_path(root, profile_path)

        with self.assertRaises(BotArchiveError):
            supervisor.archive_bot("coder")

        self.assertTrue(sentinel.is_file())
        self.assertIsNotNone(store.get_bot("coder"))

    def _write_legacy_pid_marker(
        self,
        supervisor: Supervisor,
        profile_path: Path,
        *,
        pid: int,
        argv: list[str],
        proc_start_fingerprint: str | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "pid": pid,
            "argv": argv,
            "started_at": 1_780_000_000.0,
        }
        if proc_start_fingerprint:
            payload["proc_start_fingerprint"] = proc_start_fingerprint
        marker_path = supervisor.pid_marker_path(str(profile_path))
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def _write_schema_v2_pid_marker(
        self,
        supervisor: Supervisor,
        profile_path: Path,
        *,
        pid: int,
        bot_id: str,
        argv: list[str],
        proc_start_fingerprint: str | None = None,
    ) -> None:
        resolved_hermes_bin = supervisor._resolved_hermes_bin()
        self.assertIsNotNone(resolved_hermes_bin)
        assert resolved_hermes_bin is not None
        marker_argv = list(argv)
        marker_argv[0] = resolved_hermes_bin
        payload: dict[str, object] = {
            "schema": 2,
            "pid": pid,
            "bot_id": bot_id,
            "component": "gateway",
            "action": "run",
            "argv": marker_argv,
            "resolved_hermes_bin": resolved_hermes_bin,
            "started_at": 1_780_000_000.0,
        }
        if proc_start_fingerprint is not None:
            payload["proc_start_fingerprint"] = proc_start_fingerprint
        marker_path = supervisor.pid_marker_path(str(profile_path))
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def _write_schema_v3_pid_marker(
        self,
        supervisor: Supervisor,
        profile_path: Path,
        pid: int,
        bot_id: str,
        argv: list[str],
    ) -> None:
        payload = supervisor.adapter.launcher_payload(
            bot_id,
            operation_id="a" * 32,
            desired_revision=1,
            readiness_probe=None,
        )
        marker = dict(payload["marker"])
        marker.update({"pid": pid, "started_at": 1_780_000_000.0})
        marker["proc_start_fingerprint"] = f"test-process-start:{pid}"
        supervisor.proc_start_fingerprint_reader = lambda observed_pid: (
            f"test-process-start:{observed_pid}"
        )
        marker_path = supervisor.pid_marker_path(str(profile_path))
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")

    def test_adapter_builds_profile_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            (profile / ".env").write_text(
                "# OPENROUTER_API_KEY=\nDEEPSEEK_API_KEY=test-key\nexport CUSTOM_FLAG='enabled'\n",
                encoding="utf-8",
            )
            adapter = HermesAdapter("hermes", hermes_root)
            argv, env = adapter.command("coder", "gateway", "run")
            self.assertEqual(["hermes", "-p", "coder", "gateway", "run"], argv)
            self.assertEqual(str(Path(tmp) / ".zeus" / "hermes"), env["HERMES_HOME"])
            self.assertEqual("test-key", env["DEEPSEEK_API_KEY"])
            self.assertEqual("enabled", env["CUSTOM_FLAG"])

    def test_adapter_round_trips_quoted_env_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            (profile / ".env").write_text(
                'OPENROUTER_API_KEY="line one\\nline two # not comment"\n',
                encoding="utf-8",
            )

            _, env = HermesAdapter("hermes", hermes_root).command("coder", "gateway", "run")

            self.assertEqual("line one\nline two # not comment", env["OPENROUTER_API_KEY"])

    def test_adapter_does_not_allow_profile_env_to_override_hermes_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            (profile / ".env").write_text(
                "HERMES_HOME=/tmp/different-hermes\nCUSTOM_FLAG=enabled\n",
                encoding="utf-8",
            )

            _, env = HermesAdapter("hermes", hermes_root).command("coder", "gateway", "run")

            self.assertEqual(str(hermes_root), env["HERMES_HOME"])
            self.assertEqual("enabled", env["CUSTOM_FLAG"])

    def test_adapter_does_not_leak_parent_secrets_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            (profile / ".env").write_text("OPENROUTER_API_KEY=profile-key\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "ZEUS_API_KEY": "zeus-secret",
                    "GITHUB_TOKEN": "github-secret",
                    "PATH": "/usr/bin",
                },
                clear=True,
            ):
                _, env = HermesAdapter("hermes", hermes_root).command("coder", "gateway", "run")

            self.assertEqual("profile-key", env["OPENROUTER_API_KEY"])
            self.assertEqual("/usr/bin", env["PATH"])
            self.assertNotIn("ZEUS_API_KEY", env)
            self.assertNotIn("GITHUB_TOKEN", env)

    def test_adapter_allows_explicit_env_passthrough(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_root = Path(tmp) / ".zeus" / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            (profile / ".env").write_text("", encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "ZEUS_ENV_PASSTHROUGH": "CUSTOM_ALLOWED",
                    "CUSTOM_ALLOWED": "yes",
                    "CUSTOM_BLOCKED": "no",
                },
                clear=True,
            ):
                _, env = HermesAdapter("hermes", hermes_root).command("coder", "gateway", "run")

            self.assertEqual("yes", env["CUSTOM_ALLOWED"])
            self.assertNotIn("CUSTOM_BLOCKED", env)

    def test_adapter_builds_secret_safe_launcher_command_and_private_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / ".zeus" / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            (profile / ".env").write_text(
                "OPENROUTER_API_KEY=private-launch-secret\n",
                encoding="utf-8",
            )
            adapter = HermesAdapter(hermes_bin, hermes_root)

            command = adapter.launcher_command(7, 8)
            payload = adapter.launcher_payload(
                "coder",
                operation_id="a" * 32,
                desired_revision=4,
                readiness_probe=None,
            )

            self.assertEqual(
                [sys.executable, "-m", "zeus.gateway_launcher", "7", "8"],
                command,
            )
            self.assertNotIn("private-launch-secret", "\0".join(command))
            self.assertEqual("private-launch-secret", payload["env"]["OPENROUTER_API_KEY"])
            self.assertEqual("a" * 32, payload["marker"]["operation_id"])
            self.assertEqual(4, payload["marker"]["desired_revision"])
            self.assertEqual(
                payload["argv"],
                payload["marker"]["argv"],
            )
            self.assertEqual(
                str(profile / "logs" / "zeus-gateway.pid.json"),
                payload["marker_path"],
            )

    def test_linux_cmdline_reader_uses_proc_cmdline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "4321"
            pid_dir.mkdir(parents=True)
            (pid_dir / "cmdline").write_bytes(b"hermes\0-p\0coder\0gateway\0run\0")

            argv = _read_linux_cmdline(4321, proc_root=proc_root)

            self.assertEqual(["hermes", "-p", "coder", "gateway", "run"], argv)
            self.assertEqual([], _read_linux_cmdline(9999, proc_root=proc_root))

    def test_linux_process_start_fingerprint_uses_proc_stat_starttime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "4321"
            pid_dir.mkdir(parents=True)
            fields = ["S", *["0"] * 18, "987654321", "0"]
            (pid_dir / "stat").write_text(
                f"4321 (hermes gateway) {' '.join(fields)}\n",
                encoding="utf-8",
            )

            fingerprint = _read_linux_process_start_fingerprint(4321, proc_root=proc_root)

            self.assertEqual("linux:/proc-starttime:987654321", fingerprint)
            self.assertIsNone(_read_linux_process_start_fingerprint(9999, proc_root=proc_root))

    def test_darwin_cmdline_reader_uses_ps_command(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout='"/Applications/Hermes CLI/hermes" -p coder gateway run\n',
        )
        with (
            patch("zeus.supervisor.platform.system", return_value="Darwin"),
            patch("zeus.supervisor.subprocess.run", return_value=completed),
        ):
            argv = _read_process_cmdline(4321)

        self.assertEqual(
            ["/Applications/Hermes CLI/hermes", "-p", "coder", "gateway", "run"],
            argv,
        )

    def test_darwin_process_start_fingerprint_uses_ps_lstart(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="Mon Jun 29 16:54:50 2026\n",
        )
        with patch("zeus.supervisor.subprocess.run", return_value=completed):
            fingerprint = _read_darwin_process_start_fingerprint(4321)

        self.assertEqual("darwin:ps-lstart:Mon Jun 29 16:54:50 2026", fingerprint)

    def test_gateway_command_classifier_accepts_and_rejects_expected_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            fake_hermes = root / "bin" / "fake-hermes"
            fake_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_hermes.chmod(0o755)
            cases = [
                (["hermes", "-p", "coder", "gateway", "run"], True, "direct-hermes", "ok"),
                (self._gateway_argv(hermes_bin), True, "direct-hermes", "ok"),
                (
                    [sys.executable, *self._gateway_argv(hermes_bin)],
                    True,
                    "python-script-wrapper",
                    "ok",
                ),
                (
                    [sys.executable, str(fake_hermes.resolve()), "-p", "coder", "gateway", "run"],
                    False,
                    "python-script-wrapper",
                    "untrusted-executable",
                ),
                (
                    [sys.executable, hermes_bin, "-p", "other", "gateway", "run"],
                    False,
                    "python-script-wrapper",
                    "wrong-bot-id",
                ),
                (
                    [sys.executable, hermes_bin, "-p", "coder", "doctor"],
                    False,
                    "python-script-wrapper",
                    "wrong-command-intent",
                ),
                (
                    ["python", "-c", "sleep", "-p", "coder", "gateway", "run"],
                    False,
                    "python-script-wrapper",
                    "wrong-command-intent",
                ),
                (["sleep", "60"], False, "direct-hermes", "wrong-command-intent"),
                ([hermes_bin, "gateway", "run"], False, "direct-hermes", "wrong-command-intent"),
                (
                    [hermes_bin, "-p", "coder", "-p", "other", "gateway", "run"],
                    False,
                    "direct-hermes",
                    "wrong-command-intent",
                ),
            ]
            with patch.dict(os.environ, {"PATH": str(root / "bin")}):
                for argv, verified, classification, reason in cases:
                    with self.subTest(argv=argv):
                        check = _verify_gateway_command(
                            argv, "coder", hermes_bin, require_trusted_path=True
                        )
                        self.assertEqual(verified, check.verified)
                        self.assertEqual(classification, check.classification)
                        self.assertEqual(reason, check.reason)

    def test_supervisor_marks_start_failed_when_gateway_exits_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=ExitedPopen,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                startup_grace_seconds=0,
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            status = supervisor.start("coder")

            self.assertEqual(BotStatus.failed, status.status)
            self.assertIsNone(status.pid)
            self.assertIn("exited during startup grace period", status.message)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.failed, loaded.status)
            self.assertIsNone(loaded.pid)
            audit = [
                json.loads(line)
                for line in store.audit_log_path().read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual("bot.start_failed", audit[-1]["event"])
            self.assertEqual(4321, audit[-1]["pid"])
            self.assertEqual(7, audit[-1]["returncode"])

    def test_supervisor_start_wait_promotes_running_when_health_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            (profile_path / ".env").write_text(
                "API_SERVER_ENABLED=1\nAPI_SERVER_PORT=4312\n",
                encoding="utf-8",
            )
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                startup_grace_seconds=0,
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            with patch(
                "zeus.supervisor.probe_once",
                return_value=ReadinessResult(True, "ready", {"status": "ok"}),
            ):
                status = supervisor.start("coder", wait=True, timeout_seconds=0.1)

            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual("gateway ready", status.message)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.running, loaded.status)

    def test_supervisor_start_no_wait_returns_starting_when_probe_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            (profile_path / ".env").write_text(
                "API_SERVER_ENABLED=1\nAPI_SERVER_PORT=4312\n",
                encoding="utf-8",
            )
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                self._fake_hermes_path(root),
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(self._fake_hermes_path(root)),
                startup_grace_seconds=0,
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            status = supervisor.start("coder")

            self.assertEqual(BotStatus.starting, status.status)
            self.assertIn("readiness probe pending", status.message)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.starting, loaded.status)

    def test_status_promotes_starting_to_running_when_health_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            (profile_path / ".env").write_text(
                "API_SERVER_ENABLED=1\nAPI_SERVER_PORT=4312\n",
                encoding="utf-8",
            )
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.starting,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
            )
            supervisor._write_pid_marker(
                str(profile_path), 4321, "coder", self._gateway_argv(hermes_bin)
            )

            with patch(
                "zeus.supervisor.probe_once",
                return_value=ReadinessResult(True, "ready", {"status": "ok"}),
            ):
                status = supervisor.status("coder")

            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual("gateway ready", status.message)

    def test_status_keeps_starting_when_health_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            (profile_path / ".env").write_text(
                "API_SERVER_ENABLED=1\nAPI_SERVER_PORT=4312\n",
                encoding="utf-8",
            )
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.starting,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
            )
            supervisor._write_pid_marker(
                str(profile_path), 4321, "coder", self._gateway_argv(hermes_bin)
            )

            with patch(
                "zeus.supervisor.probe_once",
                return_value=ReadinessResult(False, "connection refused"),
            ):
                status = supervisor.status("coder")

            self.assertEqual(BotStatus.starting, status.status)
            self.assertEqual("connection refused", status.message)

    def test_status_marks_failed_when_starting_process_exited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.starting,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: False,
            )

            status = supervisor.status("coder")

            self.assertEqual(BotStatus.failed, status.status)
            self.assertIsNone(status.pid)
            self.assertIn("not running", status.message)

    def test_supervisor_detaches_gateway_process_on_start(self) -> None:
        launches = []

        class CapturingPopen(FakePopen):
            def __init__(self, argv, env, stdout, stderr, **kwargs):
                super().__init__(argv, env, stdout, stderr, **kwargs)
                launches.append(self)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=CapturingPopen,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                startup_grace_seconds=0,
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            status = supervisor.start("coder")

            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual(1, len(launches))
            if os.name == "posix":
                self.assertIs(True, launches[0].kwargs.get("start_new_session"))
            elif getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0):
                self.assertEqual(
                    subprocess.CREATE_NEW_PROCESS_GROUP,
                    launches[0].kwargs.get("creationflags"),
                )

    def test_supervisor_accepts_configured_launcher_delegated_hermes_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outer = root / "bin" / "hermes"
            inner = root / "venv" / "bin" / "hermes"
            outer.parent.mkdir(parents=True)
            inner.parent.mkdir(parents=True)
            inner.write_text("#!/bin/sh\n", encoding="utf-8")
            inner.chmod(0o755)
            outer.write_text(f'#!/bin/sh\nexec "{inner}" "$@"\n', encoding="utf-8")
            outer.chmod(0o755)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                str(outer),
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: [
                    sys.executable,
                    str(inner.resolve()),
                    "-p",
                    "coder",
                    "gateway",
                    "run",
                ],
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
                startup_grace_seconds=0,
            )

            supervisor.start("coder")
            status = supervisor.status("coder")
            inspected = supervisor.inspect("coder")

            self.assertEqual(BotStatus.running, status.status)
            self.assertTrue(inspected["ownership"]["verified"])
            self.assertEqual("python-script-wrapper", inspected["ownership"]["classification"])

    def test_supervisor_marks_start_failed_when_popen_raises_file_not_found(self) -> None:
        self._assert_supervisor_start_oserror(MissingHermesPopen, "FileNotFoundError")

    def test_supervisor_marks_start_failed_when_popen_raises_permission_error(self) -> None:
        self._assert_supervisor_start_oserror(PermissionDeniedPopen, "PermissionError")

    def _assert_supervisor_start_oserror(
        self,
        popen_factory: type[MissingHermesPopen] | type[PermissionDeniedPopen],
        expected_error: str,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes = root / "missing-hermes"
            hermes.write_text("#!/bin/sh\n", encoding="utf-8")
            hermes.chmod(0o755)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                str(hermes),
                root / ".zeus" / "hermes",
                popen_factory=popen_factory,
                startup_grace_seconds=0,
            )

            status = supervisor.start("coder")

            self.assertEqual(BotStatus.failed, status.status)
            self.assertIsNone(status.pid)
            self.assertIn("failed to start gateway", status.message)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())
            self.assertNotIn("coder", supervisor._processes)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.failed, loaded.status)
            self.assertIsNone(loaded.pid)
            audit = [
                json.loads(line)
                for line in store.audit_log_path().read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual("bot.start_failed", audit[-1]["event"])
            self.assertEqual(expected_error, audit[-1]["error"])

    def test_supervisor_stop_waits_for_graceful_gateway_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            alive_checks = iter([True, True, True, False])
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: next(alive_checks, False),
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
            )
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )
            status = supervisor.stop("coder")
            self.assertEqual([(4321, "SIGTERM")], sent)
            self.assertEqual(BotStatus.stopped, status.status)
            self.assertIn("gateway shutdown completed", status.message)

    def test_supervisor_stop_does_not_kill_after_timeout_by_default(self) -> None:
        class AlwaysTimeoutProcess:
            pid = 4321

            def poll(self) -> int | None:
                return None

            def wait(self, timeout: float) -> None:
                raise subprocess.TimeoutExpired("hermes", timeout)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
            )
            supervisor._processes["coder"] = AlwaysTimeoutProcess()
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")

            self.assertEqual([(4321, "SIGTERM")], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("did not stop before grace period expired", status.message)

    def test_supervisor_stop_can_escalate_to_sigkill_after_timeout(self) -> None:
        class TimeoutThenExitProcess:
            pid = 4321

            def __init__(self) -> None:
                self.wait_calls = 0

            def poll(self) -> int | None:
                return None

            def wait(self, timeout: float) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("hermes", timeout)
                return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
                kill_after_timeout=True,
            )
            supervisor._processes["coder"] = TimeoutThenExitProcess()
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")

            self.assertEqual([(4321, "SIGTERM"), (4321, "SIGKILL")], sent)
            self.assertEqual(BotStatus.stopped, status.status)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())
            audit = [
                json.loads(line)
                for line in store.audit_log_path().read_text(encoding="utf-8").splitlines()
            ]
            kill_events = [entry for entry in audit if entry["event"] == "bot.stop_kill"]
            self.assertEqual(1, len(kill_events))
            self.assertTrue(kill_events[0]["succeeded"])

    def test_supervisor_restart_stops_then_starts_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            alive_checks = iter([True, True, True, False])
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: (
                    True if FakePopen.launch_count else next(alive_checks, False)
                ),
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.restart("coder")

            self.assertEqual([(4321, "SIGTERM")], sent)
            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual(4321, status.pid)
            self.assertEqual("restarted", status.message)

    def test_supervisor_serializes_same_bot_start_and_stop(self) -> None:
        startup_entered = threading.Event()
        release_startup = threading.Event()
        stop_finished = threading.Event()

        class SlowStartupPopen(FakePopen):
            pid = 4321

            def __init__(self, argv, env, stdout, stderr, **kwargs):
                super().__init__(argv, env, stdout, stderr, **kwargs)

            def poll(self) -> int | None:
                startup_entered.set()
                release_startup.wait(timeout=5)
                return None

            def wait(self, timeout: float) -> int:
                return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=SlowStartupPopen,
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
                startup_grace_seconds=0.0,
                stop_grace_seconds=0.01,
            )
            start_result: list[BotStatusResponse] = []
            stop_result: list[BotStatusResponse] = []

            def start_bot() -> None:
                start_result.append(supervisor.start("coder"))

            def stop_bot() -> None:
                stop_result.append(supervisor.stop("coder"))
                stop_finished.set()

            start_thread = threading.Thread(target=start_bot)
            start_thread.start()
            self.assertTrue(startup_entered.wait(timeout=2))

            stop_thread = threading.Thread(target=stop_bot)
            stop_thread.start()
            self.assertFalse(stop_finished.wait(timeout=0.1))
            self.assertEqual([], sent)

            release_startup.set()
            start_thread.join(timeout=2)
            stop_thread.join(timeout=2)

            self.assertFalse(start_thread.is_alive())
            self.assertFalse(stop_thread.is_alive())
            self.assertEqual(BotStatus.running, start_result[0].status)
            self.assertEqual(BotStatus.stopped, stop_result[0].status)
            self.assertEqual([(4321, "SIGTERM")], sent)

    def test_supervisor_restart_aborts_when_pid_ownership_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
            )

            status = supervisor.restart("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("restart aborted", status.message)

    def test_supervisor_refuses_unverified_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                stop_grace_seconds=0.01,
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_supervisor_refuses_pid_marker_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
            )
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                9999,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_supervisor_refuses_marker_when_live_command_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: None,
                stop_grace_seconds=0.01,
            )
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_supervisor_refuses_live_command_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: ["sleep", "60"],
                stop_grace_seconds=0.01,
            )
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_supervisor_schema_v2_python_wrapper_stop_requires_manual_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            alive_checks = iter([True, False])
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: next(alive_checks, False),
                cmdline_reader=lambda pid: [sys.executable, *self._gateway_argv(hermes_bin)],
                stop_grace_seconds=0.01,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("manual process resolution", status.message)
            self.assertTrue(supervisor.pid_marker_path(str(profile_path)).exists())

    def test_supervisor_rejects_python_wrapper_with_untrusted_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            fake_hermes = root / "bin" / "fake-hermes"
            fake_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_hermes.chmod(0o755)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: [
                    sys.executable,
                    str(fake_hermes.resolve()),
                    "-p",
                    "coder",
                    "gateway",
                    "run",
                ],
                stop_grace_seconds=0.01,
            )
            self._write_schema_v3_pid_marker(
                supervisor,
                profile_path,
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")
            inspected = supervisor.inspect("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertEqual(
                "live gateway command does not match",
                inspected["ownership"]["reason"],
            )

    def test_supervisor_legacy_python_wrapper_stop_requires_manual_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            alive_checks = iter([True, False])
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: next(alive_checks, False),
                cmdline_reader=lambda pid: [sys.executable, *self._gateway_argv(hermes_bin)],
                stop_grace_seconds=0.01,
            )
            self._write_legacy_pid_marker(
                supervisor,
                profile_path,
                pid=4321,
                argv=["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("manual process resolution", status.message)
            self.assertTrue(supervisor.pid_marker_path(str(profile_path)).exists())

    def test_supervisor_audits_accepted_legacy_pid_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
            )
            self._write_legacy_pid_marker(
                supervisor,
                profile_path,
                pid=4321,
                argv=["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.status("coder")
            inspected = supervisor.inspect("coder")

            self.assertEqual(BotStatus.running, status.status)
            self.assertTrue(inspected["pid_marker"]["deprecated"])
            audit = [
                json.loads(line)
                for line in store.audit_log_path().read_text(encoding="utf-8").splitlines()
            ]
            self.assertIn("bot.pid_marker_legacy_accepted", [entry["event"] for entry in audit])

    def test_supervisor_rejects_legacy_pid_marker_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                allow_legacy_pid_markers=False,
            )
            self._write_legacy_pid_marker(
                supervisor,
                profile_path,
                pid=4321,
                argv=["hermes", "-p", "coder", "gateway", "run"],
            )

            ownership = supervisor._verify_gateway_pid_ownership(str(profile_path), 4321, "coder")

            self.assertFalse(ownership.verified)
            self.assertEqual("legacy-marker-disabled", ownership.reason)

    def test_supervisor_rejects_legacy_marker_with_wrong_live_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            fake_hermes = root / "bin" / "fake-hermes"
            fake_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_hermes.chmod(0o755)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: [
                    sys.executable,
                    str(fake_hermes.resolve()),
                    "-p",
                    "coder",
                    "gateway",
                    "run",
                ],
                stop_grace_seconds=0.01,
            )
            self._write_legacy_pid_marker(
                supervisor,
                profile_path,
                pid=4321,
                argv=["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)

    def test_supervisor_rejects_schema_v2_process_start_fingerprint_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            fingerprints = ["linux:/proc-starttime:123"]

            def read_fingerprint(pid: int) -> str:
                if fingerprints:
                    return fingerprints.pop(0)
                return "linux:/proc-starttime:456"

            sent = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                stop_grace_seconds=0.01,
                proc_start_fingerprint_reader=read_fingerprint,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            status = supervisor.stop("coder")
            inspected = supervisor.inspect("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertEqual("pid-start-time-mismatch", inspected["ownership"]["reason"])

    def test_supervisor_schema_v2_process_start_fingerprint_cases_for_linux_and_darwin(
        self,
    ) -> None:
        platforms = (
            ("linux", "linux:/proc-starttime:123"),
            ("darwin", "darwin:ps-lstart:Mon Jun 29 16:54:50 2026"),
        )
        marker_cases = (
            ("present", "same", True, "ok"),
            ("missing", None, False, "pid-start-time-missing"),
            ("mismatch", "stale", False, "pid-start-time-mismatch"),
        )
        for platform_name, live_fingerprint in platforms:
            for case_name, marker_value, expected_verified, expected_reason in marker_cases:
                with (
                    self.subTest(platform=platform_name, case=case_name),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    hermes_bin = self._fake_hermes_path(root)
                    profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
                    store = StateStore(root / "zeus.db")
                    store.init()
                    supervisor = Supervisor(
                        store,
                        hermes_bin,
                        root / ".zeus" / "hermes",
                        pid_alive_fn=lambda pid: True,
                        cmdline_reader=lambda pid, bin_path=hermes_bin: self._gateway_argv(
                            bin_path
                        ),
                        proc_start_fingerprint_reader=(
                            lambda pid, fingerprint=live_fingerprint: fingerprint
                        ),
                    )
                    if marker_value == "same":
                        marker_fingerprint = live_fingerprint
                    elif marker_value == "stale":
                        marker_fingerprint = f"{live_fingerprint}:stale"
                    else:
                        marker_fingerprint = None
                    self._write_schema_v2_pid_marker(
                        supervisor,
                        profile_path,
                        pid=4321,
                        bot_id="coder",
                        argv=self._gateway_argv(hermes_bin),
                        proc_start_fingerprint=marker_fingerprint,
                    )

                    ownership = supervisor._verify_gateway_pid_ownership(
                        str(profile_path),
                        4321,
                        "coder",
                    )

                    self.assertEqual(expected_verified, ownership.verified)
                    self.assertEqual(expected_reason, ownership.reason)

    def test_supervisor_status_flags_unverified_live_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
            )

            status = supervisor.status("coder")

            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_reconcile_schedules_and_restarts_with_backoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                    restart_policy=RestartPolicy.on_failure,
                    restart_backoff_seconds=10.0,
                    restart_max_attempts=2,
                    desired_state=DesiredState.running,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: bool(FakePopen.launch_count),
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            now = datetime(2026, 1, 1, tzinfo=UTC)

            scheduled = supervisor.reconcile("coder", now=now)[0]

            self.assertEqual(BotStatus.failed, scheduled.status)
            self.assertIn("restart scheduled: attempt 1/2 in 10s", scheduled.message)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(1, loaded.restart_attempts)
            self.assertEqual(now + timedelta(seconds=10), loaded.next_restart_at)

            pending = supervisor.reconcile("coder", now=now + timedelta(seconds=5))[0]

            self.assertEqual(BotStatus.failed, pending.status)
            self.assertIn("restart pending: attempt 1/2 due at", pending.message)

            restarted = supervisor.reconcile("coder", now=now + timedelta(seconds=10))[0]

            self.assertEqual(BotStatus.running, restarted.status)
            self.assertEqual(4321, restarted.pid)
            self.assertEqual("restarted by reconcile: attempt 1/2", restarted.message)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(1, loaded.restart_attempts)
            self.assertIsNone(loaded.next_restart_at)

    def test_reconcile_honors_restart_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                    status=BotStatus.failed,
                    pid=None,
                    restart_policy=RestartPolicy.on_failure,
                    restart_max_attempts=2,
                    restart_attempts=2,
                    desired_state=DesiredState.running,
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: False,
            )

            status = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("restart limit reached: 2/2", status.message)

    def test_reconcile_does_not_restart_manual_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                    status=BotStatus.running,
                    pid=4321,
                    desired_state=DesiredState.running,
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: False,
            )

            status = supervisor.reconcile("coder")[0]

            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("manual policy: not restarting", status.message)

    def test_reconcile_force_and_reset_restart_attempts_now(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            due_later = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.failed,
                    restart_policy=RestartPolicy.on_failure,
                    restart_max_attempts=1,
                    restart_attempts=1,
                    next_restart_at=due_later,
                    desired_state=DesiredState.running,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: bool(FakePopen.launch_count),
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            limited = supervisor.reconcile("coder", now=datetime(2026, 1, 1, tzinfo=UTC))[0]
            self.assertEqual(BotStatus.failed, limited.status)
            self.assertIn("restart limit reached: 1/1", limited.message)

            restarted = supervisor.reconcile(
                "coder",
                now=datetime(2026, 1, 1, tzinfo=UTC),
                force=True,
                reset_restart=True,
            )[0]

            self.assertEqual(BotStatus.running, restarted.status)
            self.assertEqual("restarted by reconcile: attempt 1/1", restarted.message)

    def test_redacts_secret_lines(self) -> None:
        text = """
OPENAI_API_KEY=plain-secret-value
SERVICE_TOKEN=plain-token-value
api_key: plain-api-key
"token": "plain-token-json"
Authorization: Bearer bearer-secret
password = "plain-password"
"""
        redacted = redact_secrets(text)
        self.assertNotIn("plain-secret-value", redacted)
        self.assertNotIn("plain-token-value", redacted)
        self.assertNotIn("plain-api-key", redacted)
        self.assertNotIn("plain-token-json", redacted)
        self.assertNotIn("bearer-secret", redacted)
        self.assertNotIn("plain-password", redacted)
        self.assertIn("[redacted]", redacted)

    def test_cli_creates_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                (root / "templates").mkdir()
                source = old_cwd / "templates" / "coding-bot.toml"
                (root / "templates" / "coding-bot.toml").write_text(
                    source.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                with patch.dict(os.environ, {"ZEUS_STATE_DIR": str(root / ".zeus")}):
                    self.assertEqual(
                        0, cli_main(["bot", "create", "coder", "--template", "coding-bot"])
                    )
                self.assertTrue((root / ".zeus" / "hermes" / "profiles" / "coder").exists())
            finally:
                os.chdir(old_cwd)

    def test_cli_lifecycle_failures_return_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / ".zeus"
            env = {
                "ZEUS_STATE_DIR": str(state_dir),
                "ZEUS_HERMES_BIN": str(Path(tmp) / "missing-hermes"),
            }
            with patch.dict(os.environ, env):
                self._run_cli(["bot", "create", "coder", "--template", "coding-bot"])
                started = json.loads(self._run_cli_failure(["bot", "start", "coder"]))
                status = json.loads(self._run_cli_failure(["bot", "status", "coder"]))

            self.assertEqual(BotStatus.failed, started["status"])
            self.assertEqual(BotStatus.failed, status["status"])

    def test_cli_wait_timeout_returns_nonzero_but_async_starting_is_successful(self) -> None:
        response = BotStatusResponse(
            bot_id="coder",
            status=BotStatus.starting,
            pid=123,
            profile_path="/tmp/coder",
            message="readiness timeout; gateway process still alive",
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(Path(tmp) / ".zeus")}),
            patch.object(Supervisor, "start", return_value=response),
        ):
            self._run_cli(["bot", "start", "coder"])
            self._run_cli_failure(["bot", "start", "coder", "--wait"])

    def test_cli_reconcile_pending_is_success_but_terminal_failure_is_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / ".zeus"
            env = {
                "ZEUS_STATE_DIR": str(state_dir),
                "ZEUS_HERMES_BIN": str(Path(tmp) / "missing-hermes"),
            }
            with patch.dict(os.environ, env):
                self._run_cli(
                    [
                        "bot",
                        "create",
                        "pending-bot",
                        "--template",
                        "coding-bot",
                        "--restart-policy",
                        "on-failure",
                    ]
                )
                store = StateStore(state_dir / "zeus.db")
                intent = store.begin_lifecycle_intent(
                    "pending-bot",
                    action="start",
                    operation_id="a" * 32,
                    source="cli",
                )
                store.complete_lifecycle_intent(
                    "pending-bot",
                    action="start",
                    operation_id="a" * 32,
                    desired_revision=intent.desired_revision,
                    status=BotStatus.failed,
                    pid=None,
                    source="cli",
                    outcome="failure",
                    error_code="test_failure",
                    error_message="test failure",
                )
                pending = json.loads(self._run_cli(["bot", "reconcile", "pending-bot"]))
                self.assertIn("restart scheduled:", pending[0]["message"])

                self._run_cli(
                    [
                        "bot",
                        "create",
                        "limited-bot",
                        "--template",
                        "coding-bot",
                        "--restart-policy",
                        "on-failure",
                        "--restart-max-attempts",
                        "0",
                    ]
                )
                limited_intent = store.begin_lifecycle_intent(
                    "limited-bot",
                    action="start",
                    operation_id="b" * 32,
                    source="cli",
                )
                store.complete_lifecycle_intent(
                    "limited-bot",
                    action="start",
                    operation_id="b" * 32,
                    desired_revision=limited_intent.desired_revision,
                    status=BotStatus.failed,
                    pid=None,
                    source="cli",
                    outcome="failure",
                    error_code="test_failure",
                    error_message="test failure",
                )
                limited = json.loads(self._run_cli_failure(["bot", "reconcile", "limited-bot"]))
                self.assertIn("restart limit reached:", limited[0]["message"])

    def test_cli_reconcile_summary_json_runs_once_and_human_output_is_deterministic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / ".zeus"
            env = {
                "ZEUS_STATE_DIR": str(state_dir),
                "ZEUS_HERMES_BIN": str(Path(tmp) / "missing-hermes"),
            }
            with patch.dict(os.environ, env):
                self._run_cli(["bot", "create", "coder", "--template", "coding-bot"])
                payload = json.loads(self._run_cli(["bot", "reconcile", "--summary", "--json"]))

            self.assertEqual("fleet", payload["scope"])
            self.assertEqual("succeeded", payload["outcome"])
            self.assertTrue(payload["ok"])
            self.assertEqual(1, payload["total"])
            self.assertEqual("coder", payload["results"][0]["bot_id"])
            self.assertEqual(
                {
                    "healthy": 1,
                    "changed": 0,
                    "pending": 0,
                    "action_required": 0,
                    "error": 0,
                    "skipped": 0,
                },
                payload["counts"],
            )
            with sqlite3.connect(state_dir / "zeus.db") as conn:
                self.assertEqual(
                    1,
                    conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                )

            started_at = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)
            result = BotReconcileResult(
                bot_id="coder",
                outcome=ReconcileOutcome.pending,
                desired_state="running",
                observed_status="failed",
                pid=None,
                action="wait",
                message="restart scheduled",
                error_code=None,
                event_id=7,
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
            )
            counts = {outcome.value: 0 for outcome in ReconcileOutcome}
            counts[ReconcileOutcome.pending.value] = 1
            summary = ReconcileRunSummary(
                run_id="run-pending",
                scope="bot",
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
                outcome="succeeded",
                total=1,
                counts=counts,
                results=(result,),
            )
            with (
                patch.dict(os.environ, {"ZEUS_STATE_DIR": str(state_dir)}),
                patch.object(Supervisor, "reconcile_summary", return_value=summary),
            ):
                human = self._run_cli(["bot", "reconcile", "coder", "--summary"])

            self.assertEqual(
                "run_id: run-pending\n"
                "scope: bot\n"
                "started_at: 2026-07-13T10:00:00+00:00\n"
                "finished_at: 2026-07-13T10:00:01+00:00\n"
                "outcome: succeeded\n"
                "counts: healthy=0 changed=0 pending=1 action_required=0 error=0 skipped=0\n"
                "total: 1\n"
                "results:\n"
                "coder\tpending\twait\tfailed\trestart scheduled\n",
                human,
            )

    def test_cli_reconcile_summary_exit_fails_only_for_terminal_counts(self) -> None:
        started_at = datetime(2026, 7, 13, 10, 0, tzinfo=UTC)

        def summary_for(outcome: ReconcileOutcome) -> ReconcileRunSummary:
            counts = {item.value: 0 for item in ReconcileOutcome}
            counts[outcome.value] = 1
            result = BotReconcileResult(
                bot_id="coder",
                outcome=outcome,
                desired_state="running",
                observed_status="failed",
                pid=None,
                action="reconcile",
                message=outcome.value,
                error_code=(outcome.value if outcome is ReconcileOutcome.error else None),
                event_id=None,
                started_at=started_at,
                finished_at=started_at,
            )
            return ReconcileRunSummary(
                run_id=f"run-{outcome.value}",
                scope="bot",
                started_at=started_at,
                finished_at=started_at,
                outcome=(
                    "completed_with_errors"
                    if outcome in {ReconcileOutcome.action_required, ReconcileOutcome.error}
                    else "succeeded"
                ),
                total=1,
                counts=counts,
                results=(result,),
            )

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(Path(tmp) / ".zeus")}),
            patch.object(
                Supervisor,
                "reconcile_summary",
                side_effect=[
                    summary_for(ReconcileOutcome.pending),
                    summary_for(ReconcileOutcome.skipped),
                    summary_for(ReconcileOutcome.action_required),
                    summary_for(ReconcileOutcome.error),
                ],
            ),
        ):
            self._run_cli(["bot", "reconcile", "coder", "--summary", "--json"])
            self._run_cli(["bot", "reconcile", "coder", "--summary", "--json"])
            action_required = json.loads(
                self._run_cli_failure(["bot", "reconcile", "coder", "--summary", "--json"])
            )
            error = json.loads(
                self._run_cli_failure(["bot", "reconcile", "coder", "--summary", "--json"])
            )

        self.assertEqual("completed_with_errors", action_required["outcome"])
        self.assertEqual("completed_with_errors", error["outcome"])

    def test_cli_reconcile_summary_inner_lock_timeout_is_controlled(self) -> None:
        lock_error = LockTimeoutError(Path("/tmp/bots/coder.lock"), 0.1)
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(Path(tmp) / ".zeus")}),
            patch.object(Supervisor, "reconcile_summary", side_effect=lock_error),
        ):
            json_error = json.loads(
                self._run_cli_failure(["bot", "reconcile", "coder", "--summary", "--json"])
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(
                    1,
                    cli_main(["bot", "reconcile", "coder", "--summary"]),
                )

        self.assertEqual(
            {
                "error": {
                    "code": "bot_locked",
                    "message": "bot lifecycle operation is already in progress",
                }
            },
            json_error,
        )
        self.assertEqual(
            "bot lifecycle operation is already in progress\n",
            stderr.getvalue(),
        )

    def test_cli_create_requires_replace_for_existing_stopped_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                (root / "templates").mkdir()
                source = old_cwd / "templates" / "coding-bot.toml"
                (root / "templates" / "coding-bot.toml").write_text(
                    source.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                with patch.dict(os.environ, {"ZEUS_STATE_DIR": str(root / ".zeus")}):
                    self._run_cli(["bot", "create", "coder", "--template", "coding-bot"])
                    failed = json.loads(
                        self._run_cli_failure(
                            [
                                "bot",
                                "create",
                                "coder",
                                "--template",
                                "coding-bot",
                                "--json",
                            ]
                        )
                    )
                    self.assertEqual("bot_exists", failed["error"]["code"])
                    replaced = json.loads(
                        self._run_cli(
                            [
                                "bot",
                                "create",
                                "coder",
                                "--template",
                                "coding-bot",
                                "--replace",
                                "--json",
                            ]
                        )
                    )
                self.assertEqual("coder", replaced["bot_id"])
            finally:
                os.chdir(old_cwd)

    def test_delete_refuses_profile_path_equal_to_hermes_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_delete_refuses_profile_path(root, root / ".zeus" / "hermes")

    def test_delete_refuses_profile_path_equal_to_profiles_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_delete_refuses_profile_path(root, root / ".zeus" / "hermes" / "profiles")

    def test_delete_refuses_profile_path_for_other_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_delete_refuses_profile_path(
                root,
                root / ".zeus" / "hermes" / "profiles" / "other-bot",
            )

    def test_delete_refuses_nested_profile_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_delete_refuses_profile_path(
                root,
                root / ".zeus" / "hermes" / "profiles" / "coder" / "nested",
            )

    def test_delete_refuses_profile_path_outside_profiles_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_delete_refuses_profile_path(root, root / "outside")

    def test_delete_allows_exact_hermes_profiles_bot_id_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            (profile_path / "sentinel.txt").write_text("remove\n", encoding="utf-8")
            store, supervisor = self._supervisor_for_profile_path(root, profile_path)

            response = supervisor.delete_bot("coder", remove_profile=True)

            self.assertEqual("deleted", response.message)
            self.assertFalse(profile_path.exists())
            self.assertIsNone(store.get_bot("coder"))

    def test_archive_refuses_profile_path_equal_to_hermes_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_archive_refuses_profile_path(root, root / ".zeus" / "hermes")

    def test_archive_refuses_profile_path_equal_to_profiles_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_archive_refuses_profile_path(root, root / ".zeus" / "hermes" / "profiles")

    def test_archive_refuses_profile_path_for_other_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_archive_refuses_profile_path(
                root,
                root / ".zeus" / "hermes" / "profiles" / "other-bot",
            )

    def test_archive_refuses_nested_profile_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_archive_refuses_profile_path(
                root,
                root / ".zeus" / "hermes" / "profiles" / "coder" / "nested",
            )

    def test_archive_refuses_profile_path_outside_profiles_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._assert_archive_refuses_profile_path(root, root / "outside")

    def test_cli_delete_and_archive_remove_registry_entries_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                (root / "templates").mkdir()
                source = old_cwd / "templates" / "coding-bot.toml"
                (root / "templates" / "coding-bot.toml").write_text(
                    source.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                env = {"ZEUS_STATE_DIR": str(root / ".zeus")}
                with patch.dict(os.environ, env):
                    self._run_cli(["bot", "create", "coder", "--template", "coding-bot"])
                    deleted = json.loads(
                        self._run_cli(["bot", "delete", "coder", "--remove-profile", "--json"])
                    )
                    self.assertEqual("deleted", deleted["message"])
                    self.assertFalse((root / ".zeus" / "hermes" / "profiles" / "coder").exists())
                    self.assertEqual([], json.loads(self._run_cli(["bot", "list", "--json"])))

                    self._run_cli(["bot", "create", "coder", "--template", "coding-bot"])
                    archived = json.loads(self._run_cli(["bot", "archive", "coder", "--json"]))
                    self.assertEqual("archived", archived["message"])
                    self.assertTrue(Path(archived["archive_path"]).is_dir())
                    self.assertEqual([], json.loads(self._run_cli(["bot", "list", "--json"])))
            finally:
                os.chdir(old_cwd)

    def test_history_payload_paginates_deleted_bot_without_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            record = BotRecord(
                bot_id="coder",
                template_id="coding-bot",
                display_name="Coder",
                profile_path=str(root / "profiles" / "coder"),
            )
            store.upsert_bot_with_event(
                record,
                event=LifecycleEventInput(
                    bot_id="coder",
                    operation_id=uuid.uuid4().hex,
                    source="cli",
                    action="bot.create",
                    outcome="succeeded",
                ),
            )
            for action, status in (
                ("bot.start", BotStatus.starting),
                ("bot.ready", BotStatus.running),
                ("bot.stop", BotStatus.stopped),
            ):
                store.update_lifecycle_with_event(
                    "coder",
                    status,
                    event=LifecycleEventInput(
                        bot_id="coder",
                        operation_id=uuid.uuid4().hex,
                        source="cli",
                        action=action,
                        outcome="succeeded",
                    ),
                )
            store.delete_bot_with_event(
                "coder",
                event=LifecycleEventInput(
                    bot_id="coder",
                    operation_id=uuid.uuid4().hex,
                    source="cli",
                    action="bot.delete",
                    outcome="succeeded",
                ),
            )

            first = store.history_payload("coder", limit=2, before=None)
            second = store.history_payload("coder", limit=2, before=first["next_before"])
            third = store.history_payload("coder", limit=2, before=second["next_before"])
            exhausted = store.history_payload(
                "coder", limit=2, before=third["events"][-1]["event_id"]
            )

            self.assertEqual("coder", first["bot_id"])
            self.assertIsNotNone(first["next_before"])
            self.assertIsNotNone(second["next_before"])
            self.assertIsNone(third["next_before"])
            self.assertEqual([], exhausted["events"])
            self.assertIsNone(exhausted["next_before"])
            pages = [first["events"], second["events"], third["events"]]
            event_ids = [event["event_id"] for page in pages for event in page]
            self.assertEqual(sorted(event_ids, reverse=True), event_ids)
            self.assertEqual(len(event_ids), len(set(event_ids)))
            self.assertEqual(5, len(event_ids))
            self.assertIsNone(store.get_bot("coder"))

    def test_history_payload_distinguishes_empty_projection_from_unknown_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="legacy",
                    template_id="coding-bot",
                    display_name="Legacy",
                    profile_path=str(root / "profiles" / "legacy"),
                )
            )

            self.assertEqual(
                {"bot_id": "legacy", "events": [], "next_before": None},
                store.history_payload("legacy", limit=50, before=None),
            )
            with self.assertRaisesRegex(KeyError, "unknown bot: never-seen"):
                store.history_payload("never-seen", limit=50, before=None)

    def test_cli_history_supports_json_text_and_cursors_after_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / ".zeus"
            store = StateStore(state_dir / "zeus.db")
            store.init()
            record = BotRecord(
                bot_id="coder",
                template_id="coding-bot",
                display_name="Coder",
                profile_path=str(state_dir / "hermes" / "profiles" / "coder"),
            )
            store.upsert_bot_with_event(
                record,
                event=LifecycleEventInput(
                    bot_id="coder",
                    operation_id=uuid.uuid4().hex,
                    source="cli",
                    action="bot.create",
                    outcome="succeeded",
                ),
            )
            store.delete_bot_with_event(
                "coder",
                event=LifecycleEventInput(
                    bot_id="coder",
                    operation_id=uuid.uuid4().hex,
                    source="cli",
                    action="bot.delete",
                    outcome="succeeded",
                ),
            )

            with patch.dict(os.environ, {"ZEUS_STATE_DIR": str(state_dir)}):
                first = json.loads(
                    self._run_cli(["bot", "history", "coder", "--limit", "1", "--json"])
                )
                text = self._run_cli(
                    [
                        "bot",
                        "history",
                        "coder",
                        "--limit",
                        "1",
                        "--before",
                        str(first["next_before"]),
                    ]
                )
                unknown = json.loads(
                    self._run_cli_failure(["bot", "history", "never-seen", "--json"])
                )

            self.assertEqual("bot.delete", first["events"][0]["action"])
            self.assertIn("bot.create", text)
            self.assertEqual("unknown_bot", unknown["error"]["code"])

    def test_cli_history_rejects_invalid_limit_and_before_values(self) -> None:
        parser = build_parser()
        for argv in (
            ["bot", "history", "coder", "--limit", "0"],
            ["bot", "history", "coder", "--limit", "1001"],
            ["bot", "history", "coder", "--before", "0"],
        ):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as raised:
                parser.parse_args(argv)
            self.assertEqual(2, raised.exception.code)

    def test_cli_json_outputs_parse_for_automation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                (root / "templates").mkdir()
                source = old_cwd / "templates" / "coding-bot.toml"
                (root / "templates" / "coding-bot.toml").write_text(
                    source.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                env = {"ZEUS_STATE_DIR": str(root / ".zeus")}
                with patch.dict(os.environ, env):
                    templates = json.loads(self._run_cli(["template", "list", "--json"]))
                    self.assertIsInstance(templates, list)
                    self.assertEqual("coding-bot", templates[0]["id"])

                    created = json.loads(
                        self._run_cli(
                            [
                                "bot",
                                "create",
                                "coder",
                                "--template",
                                "coding-bot",
                                "--restart-policy",
                                "on-failure",
                                "--json",
                            ]
                        )
                    )
                    self.assertEqual("coder", created["bot_id"])
                    self.assertEqual("coding-bot", created["template_id"])
                    self.assertEqual("on-failure", created["restart_policy"])

                    bots = json.loads(self._run_cli(["bot", "list", "--json"]))
                    self.assertEqual("coder", bots[0]["bot_id"])

                    logs = json.loads(self._run_cli(["bot", "logs", "coder", "--json"]))
                    self.assertEqual({"bot_id": "coder", "logs": ""}, logs)

                    inspected = json.loads(self._run_cli(["bot", "inspect", "coder", "--json"]))
                    self.assertEqual("coder", inspected["bot"]["bot_id"])
                    self.assertEqual(
                        {
                            "started_at": None,
                            "ready_at": None,
                            "stopped_at": None,
                            "last_exit_code": None,
                            "last_error": None,
                            "last_transition_reason": None,
                        },
                        inspected["lifecycle"],
                    )
                    self.assertTrue(inspected["profile_files"]["config.yaml"])
                    self.assertTrue(inspected["profile_files"]["SOUL.md"])
                    self.assertTrue(inspected["profile_files"][".env"])
                    self.assertEqual({"exists": False}, inspected["pid_marker"])
                    self.assertFalse(inspected["live_cmdline_verified"])
                    self.assertEqual("", inspected["recent_logs"])
                    self.assertNotIn("OPENROUTER_API_KEY", json.dumps(inspected))

                    reconciled = json.loads(self._run_cli(["bot", "reconcile", "--json"]))
                    self.assertIsInstance(reconciled, list)
                    self.assertEqual("coder", reconciled[0]["bot_id"])

                audit = [
                    json.loads(line)
                    for line in (root / ".zeus" / "logs" / "audit.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()
                ]
                self.assertEqual("bot.create", audit[0]["event"])
                self.assertNotIn("env", audit[0])
            finally:
                os.chdir(old_cwd)

    def test_cli_demo_up_status_down_uses_fake_hermes_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {"ZEUS_STATE_DIR": str(root / ".zeus")}
            run_env = {**os.environ, **env}
            command = [sys.executable, "-B", "-m", "zeus.cli"]

            def run_demo(*args: str) -> dict[str, object]:
                completed = subprocess.run(
                    [*command, "demo", *args, "--json"],
                    check=True,
                    env=run_env,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            try:
                started = run_demo("up")
                status = run_demo("status")
                stopped = run_demo("down")
            finally:
                subprocess.run(
                    [*command, "demo", "down", "--json"],
                    env=run_env,
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertEqual("demo-coder", started["bot"]["bot_id"])
            self.assertEqual(BotStatus.running, started["start"]["status"])
            self.assertTrue(Path(started["fake_hermes_bin"]).is_file())
            self.assertEqual(BotStatus.running, status["status"]["status"])
            self.assertEqual(BotStatus.stopped, stopped["stop"]["status"])

    def test_audit_log_records_lifecycle_and_redacts_secret_like_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    restart_policy=RestartPolicy.on_failure,
                )
            )
            store.append_audit_event("bot.create", bot_id="coder", api_key="plain-secret")
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: bool(FakePopen.launch_count),
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            supervisor.start("coder")
            supervisor.stop("coder")
            failed = store.get_bot("coder")
            self.assertIsNotNone(failed)
            assert failed is not None
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id=failed.template_id,
                    display_name=failed.display_name,
                    profile_path=failed.profile_path,
                    status=BotStatus.failed,
                    restart_policy=RestartPolicy.on_failure,
                    desired_state=DesiredState.running,
                )
            )
            supervisor.reconcile("coder", now=datetime(2026, 1, 1, tzinfo=UTC))

            audit = [
                json.loads(line)
                for line in store.audit_log_path().read_text(encoding="utf-8").splitlines()
            ]
            events = [entry["event"] for entry in audit]
            self.assertIn("bot.create", events)
            self.assertIn("bot.start", events)
            self.assertIn("bot.stop", events)
            self.assertIn("bot.reconcile.restart_scheduled", events)
            self.assertNotIn("plain-secret", store.audit_log_path().read_text(encoding="utf-8"))
            self.assertIn("[redacted]", store.audit_log_path().read_text(encoding="utf-8"))

    def test_audit_write_failure_does_not_break_lifecycle_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            audit_path = store.audit_log_path()
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            audit_path.mkdir()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: bool(FakePopen.launch_count),
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            status = supervisor.start("coder")

            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual(4321, status.pid)
            events = store.list_lifecycle_events("coder", limit=50, before=None)
            self.assertEqual(2, len(events))
            self.assertEqual(["running", "stopped"], [event.status_after for event in events])

    def test_supervisor_inspect_reports_metadata_without_env_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes_path(root)
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            (profile_path / "cron").mkdir(parents=True)
            (profile_path / "logs").mkdir()
            (profile_path / "config.yaml").write_text("model: test\n", encoding="utf-8")
            (profile_path / "SOUL.md").write_text("soul\n", encoding="utf-8")
            (profile_path / ".env").write_text(
                "OPENROUTER_API_KEY=plain-secret\n", encoding="utf-8"
            )
            (profile_path / "mcp.json").write_text("{}", encoding="utf-8")
            (profile_path / "cron" / "jobs.json").write_text("[]", encoding="utf-8")
            (profile_path / "logs" / "zeus-gateway.log").write_text(
                "OPENAI_API_KEY=plain-log-secret\nready\n",
                encoding="utf-8",
            )
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                    status=BotStatus.running,
                    pid=4321,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            inspected = supervisor.inspect("coder")

            self.assertEqual("coder", inspected["bot"]["bot_id"])
            self.assertTrue(inspected["profile_files"]["config.yaml"])
            self.assertTrue(inspected["profile_files"]["cron/jobs.json"])
            self.assertTrue(inspected["pid_marker"]["exists"])
            self.assertTrue(inspected["pid_marker"]["valid"])
            self.assertEqual("0600", inspected["pid_marker"]["mode"])
            self.assertFalse(inspected["pid_marker"]["deprecated"])
            self.assertEqual(
                "direct-hermes hermes -p <bot> gateway run", inspected["pid_marker"]["argv_shape"]
            )
            self.assertTrue(inspected["live_cmdline_verified"])
            self.assertEqual(True, inspected["ownership"]["verified"])
            self.assertEqual("ok", inspected["ownership"]["reason"])
            self.assertEqual("direct-hermes", inspected["ownership"]["classification"])
            self.assertIn("ready", inspected["recent_logs"])
            serialized = json.dumps(inspected)
            self.assertNotIn("plain-secret", serialized)
            self.assertNotIn("plain-log-secret", serialized)
            self.assertNotIn("OPENROUTER_API_KEY", serialized)
            self.assertNotIn(hermes_bin, serialized)

    def test_settings_parses_stop_kill_after_timeout_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            disabled = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / "disabled"),
                    "ZEUS_STOP_KILL_AFTER_TIMEOUT": "0",
                }
            )
            enabled = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / "enabled"),
                    "ZEUS_STOP_KILL_AFTER_TIMEOUT": "1",
                }
            )

        self.assertFalse(disabled.stop_kill_after_timeout)
        self.assertTrue(enabled.stop_kill_after_timeout)

    def test_settings_parses_lock_readiness_and_legacy_marker_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_LOCK_TIMEOUT_SECONDS": "2.5",
                    "ZEUS_READINESS_TIMEOUT_SECONDS": "3.5",
                    "ZEUS_READINESS_INTERVAL_SECONDS": "0.25",
                    "ZEUS_ALLOW_LEGACY_PID_MARKERS": "0",
                }
            )

        self.assertEqual(2.5, settings.lock_timeout_seconds)
        self.assertEqual(3.5, settings.readiness_timeout_seconds)
        self.assertEqual(0.25, settings.readiness_interval_seconds)
        self.assertFalse(settings.allow_legacy_pid_markers)

    def test_settings_rejects_invalid_lock_timeout(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            self.assertRaisesRegex(
                ValueError,
                "ZEUS_LOCK_TIMEOUT_SECONDS must be between 0.1 and 300",
            ),
        ):
            Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_LOCK_TIMEOUT_SECONDS": "0",
                }
            )

    def test_settings_rejects_invalid_port(self) -> None:
        with self.assertRaisesRegex(ValueError, "ZEUS_PORT must be between 0 and 65535"):
            Settings.from_env({"ZEUS_PORT": "70000"})

    def test_settings_empty_state_directory_uses_safe_default(self) -> None:
        settings = Settings.from_env({"ZEUS_STATE_DIR": ""})

        self.assertEqual((Path.cwd() / ".zeus").resolve(), settings.state_dir)

    def test_cli_serve_forwards_explicit_ephemeral_port(self) -> None:
        settings = Settings.from_env({})
        with (
            patch("zeus.cli.Settings.from_env", return_value=settings),
            patch("zeus.cli.serve") as serve,
        ):
            result = cli_main(["serve", "--port", "0"])

        self.assertEqual(0, result)
        self.assertEqual(0, serve.call_args.kwargs["port"])

    def test_api_main_forwards_explicit_ephemeral_port(self) -> None:
        settings = Settings.from_env({})
        with (
            patch("zeus.api.Settings.from_env", return_value=settings),
            patch("zeus.api.serve") as serve,
        ):
            result = api_main(["--port", "0"])

        self.assertEqual(0, result)
        self.assertEqual(0, serve.call_args.kwargs["port"])

    def test_cli_services_wire_stop_kill_after_timeout_setting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_STOP_KILL_AFTER_TIMEOUT": "1",
                }
            )

            _, supervisor = _services(settings)

        self.assertTrue(supervisor.kill_after_timeout)

    def test_cli_services_wire_lifecycle_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_LOCK_TIMEOUT_SECONDS": "2",
                    "ZEUS_READINESS_TIMEOUT_SECONDS": "3",
                    "ZEUS_READINESS_INTERVAL_SECONDS": "0.25",
                    "ZEUS_ALLOW_LEGACY_PID_MARKERS": "0",
                }
            )

            _, supervisor = _services(settings)

        self.assertEqual(2, supervisor.lock_timeout_seconds)
        self.assertEqual(3, supervisor.readiness_timeout_seconds)
        self.assertEqual(0.25, supervisor.readiness_interval_seconds)
        self.assertFalse(supervisor.allow_legacy_pid_markers)

    def test_doctor_reports_templates_and_missing_hermes_as_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_HERMES_BIN": "definitely-missing-hermes",
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "4311",
                }
            )

            report = run_doctor(settings)
            statuses = {check.name: check.status for check in report.checks}

            self.assertEqual("warn", statuses["hermes"])
            self.assertEqual("pass", statuses["templates"])
            self.assertTrue(report.ok)

            strict_report = run_doctor(settings, strict=True)
            self.assertFalse(strict_report.ok)

    def test_doctor_allows_installed_package_without_checkout_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                settings = Settings.from_env(
                    {
                        "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                        "ZEUS_HERMES_BIN": "definitely-missing-hermes",
                        "ZEUS_HOST": "127.0.0.1",
                        "ZEUS_PORT": "4311",
                    }
                )

                report = run_doctor(settings)
            finally:
                os.chdir(old_cwd)

        statuses = {check.name: check.status for check in report.checks}
        self.assertTrue(report.ok)
        self.assertEqual("pass", statuses["templates"])
        self.assertEqual("warn", statuses["runtime_paths"])
        self.assertEqual("warn", statuses["scripts"])

    def test_doctor_fails_public_bind_without_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_HOST": "0.0.0.0",
                    "ZEUS_PORT": "4311",
                }
            )

            report = run_doctor(settings)

        statuses = {check.name: check.status for check in report.checks}
        self.assertEqual("fail", statuses["api_auth"])
        self.assertFalse(report.ok)

    def test_doctor_fails_public_bind_with_unauthenticated_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(Path(tmp) / ".zeus"),
                    "ZEUS_HOST": "0.0.0.0",
                    "ZEUS_PORT": "4311",
                    "ZEUS_API_KEY": "a-strong-api-key-value",
                    "ZEUS_ALLOW_UNAUTH_READS": "1",
                }
            )

            report = run_doctor(settings)

        statuses = {check.name: check.status for check in report.checks}
        self.assertEqual("fail", statuses["api_auth"])
        self.assertFalse(report.ok)

    def test_doctor_checks_actual_workspace_state_path_ignore(self) -> None:
        settings = Settings.from_env({"ZEUS_STATE_DIR": "custom-runtime"})
        ignored = subprocess.CompletedProcess([], 0)
        not_ignored = subprocess.CompletedProcess([], 1)

        with patch("zeus.doctor.subprocess.run", return_value=ignored) as run:
            self.assertEqual("pass", _check_runtime_paths(settings).status)
            self.assertEqual("custom-runtime/", run.call_args.args[0][-1])
        with patch("zeus.doctor.subprocess.run", return_value=not_ignored):
            self.assertEqual("fail", _check_runtime_paths(settings).status)

    def test_doctor_rejects_state_path_that_is_not_a_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state"
            state_path.write_text("not a directory\n", encoding="utf-8")
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_path)})

            check = _check_runtime_paths(settings)

        self.assertEqual("fail", check.status)
        self.assertIn("must be a directory", check.message)

    def test_doctor_rejects_world_accessible_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o755)
            state_dir.chmod(0o755)
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                check = _check_runtime_paths(settings)
            finally:
                os.chdir(old_cwd)

        self.assertEqual("fail", check.status)
        self.assertIn("must not be accessible to other users", check.message)

    def test_api_health_and_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(root / ".zeus"),
                    "ZEUS_API_KEY": "secret",
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "0",
                }
            )
            handler = make_handler(settings)
            from http.server import ThreadingHTTPServer

            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/health")
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                self.assertEqual("no-store", response.getheader("cache-control"))
                self.assertEqual({"status": "ok"}, json.loads(response.read()))

                conn.request("GET", "/bots")
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                body = json.loads(response.read())
                self.assertEqual("invalid_api_key", body["error"]["code"])

                conn.request(
                    "POST", "/bots", body=b"{}", headers={"content-type": "application/json"}
                )
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                body = json.loads(response.read())
                self.assertEqual("invalid_api_key", body["error"]["code"])

                invalid_body = json.dumps(
                    {"bot_id": "coder", "template_id": "coding-bot", "env": ["bad"]}
                ).encode("utf-8")
                conn.request(
                    "POST",
                    "/bots",
                    body=invalid_body,
                    headers={"content-type": "application/json", "x-zeus-api-key": "secret"},
                )
                response = conn.getresponse()
                self.assertEqual(400, response.status)
                body = json.loads(response.read())
                self.assertEqual("invalid_request", body["error"]["code"])

                create_body = json.dumps({"bot_id": "coder", "template_id": "coding-bot"}).encode(
                    "utf-8"
                )
                conn.request(
                    "POST",
                    "/bots",
                    body=create_body,
                    headers={"content-type": "application/json", "x-zeus-api-key": "secret"},
                )
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                created = json.loads(response.read())
                self.assertEqual("coder", created["bot_id"])
                self.assertEqual("manual", created["restart_policy"])

                conn.request("GET", "/bots/coder/logs")
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                body = json.loads(response.read())
                self.assertEqual("invalid_api_key", body["error"]["code"])

                conn.request("GET", "/doctor")
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                body = json.loads(response.read())
                self.assertEqual("invalid_api_key", body["error"]["code"])

                conn.request("GET", "/doctor", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                doctor = json.loads(response.read())
                self.assertIn("checks", doctor)

                conn.request("GET", "/bots/Bad/status", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(400, response.status)
                body = json.loads(response.read())
                self.assertEqual("invalid_bot_id", body["error"]["code"])

                conn.request("POST", "/bots/reconcile", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                reconciled = json.loads(response.read())
                self.assertEqual("coder", reconciled[0]["bot_id"])

                conn.request(
                    "POST",
                    "/bots",
                    body=b"{}",
                    headers={"content-type": "text/plain", "x-zeus-api-key": "secret"},
                )
                response = conn.getresponse()
                self.assertEqual(415, response.status)
                body = json.loads(response.read())
                self.assertEqual("unsupported_media_type", body["error"]["code"])

                conn.request("PUT", "/bots", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(405, response.status)
                body = json.loads(response.read())
                self.assertEqual("method_not_allowed", body["error"]["code"])
            finally:
                server.shutdown()
                server.server_close()

    def test_api_reuses_single_supervisor_instance(self) -> None:
        created = []

        class CountingSupervisor:
            def __init__(self, *args, **kwargs) -> None:
                created.append(self)

            def status(
                self,
                bot_id: str,
                *,
                source: str = "cli",
                request_id: str | None = None,
            ) -> BotStatusResponse:
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.stopped,
                    pid=None,
                    profile_path="/tmp/profile",
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(root / ".zeus"),
                    "ZEUS_API_KEY": "secret",
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "0",
                }
            )
            store = StateStore(settings.database_path)
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path="/tmp/profile",
                )
            )
            with patch("zeus.api.Supervisor", CountingSupervisor):
                handler = make_handler(settings)
            from http.server import ThreadingHTTPServer

            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                for _ in range(2):
                    conn.request("GET", "/bots/coder/status", headers={"x-zeus-api-key": "secret"})
                    response = conn.getresponse()
                    self.assertEqual(200, response.status)
                    response.read()
            finally:
                server.shutdown()
                server.server_close()

        self.assertEqual(1, len(created))

    def test_api_non_health_endpoints_require_configured_api_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(root / ".zeus"),
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "0",
                }
            )
            handler = make_handler(settings)
            from http.server import ThreadingHTTPServer

            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/health")
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                response.read()

                conn.request("GET", "/bots")
                response = conn.getresponse()
                self.assertEqual(503, response.status)
                body = json.loads(response.read())
                self.assertEqual("missing_api_key", body["error"]["code"])
                self.assertIn("ZEUS_API_KEY", body["error"]["message"])

                conn.request(
                    "POST",
                    "/bots",
                    body=b"{}",
                    headers={"content-type": "application/json", "x-zeus-api-key": "anything"},
                )
                response = conn.getresponse()
                self.assertEqual(503, response.status)
                body = json.loads(response.read())
                self.assertEqual("missing_api_key", body["error"]["code"])
                self.assertIn("ZEUS_API_KEY", body["error"]["message"])
            finally:
                server.shutdown()
                server.server_close()

    def test_api_allow_unauth_reads_keeps_mutations_locked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = Settings.from_env(
                {
                    "ZEUS_STATE_DIR": str(root / ".zeus"),
                    "ZEUS_ALLOW_UNAUTH_READS": "1",
                    "ZEUS_HOST": "127.0.0.1",
                    "ZEUS_PORT": "0",
                }
            )
            handler = make_handler(settings)
            from http.server import ThreadingHTTPServer

            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/templates")
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                templates = json.loads(response.read())
                self.assertTrue(templates)

                conn.request(
                    "POST",
                    "/bots",
                    body=b"{}",
                    headers={"content-type": "application/json"},
                )
                response = conn.getresponse()
                self.assertEqual(503, response.status)
                response.read()
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
