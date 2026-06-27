from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.api import make_handler
from zeus.cli import _services
from zeus.cli import main as cli_main
from zeus.config import Settings
from zeus.doctor import run_doctor
from zeus.hermes_adapter import HermesAdapter
from zeus.logging_utils import redact_secrets
from zeus.models import BotRecord, BotStatus, BotStatusResponse, RestartPolicy
from zeus.state import StateStore
from zeus.supervisor import Supervisor, _read_linux_cmdline, _read_process_cmdline


class FakePopen:
    returncode: int | None = None

    def __init__(self, argv, env, stdout, stderr):
        self.argv = argv
        self.env = env
        self.stdout = stdout
        self.stderr = stderr
        self.pid = 4321

    def poll(self) -> int | None:
        return self.returncode


class ExitedPopen(FakePopen):
    returncode = 7


class SupervisorCliApiTests(unittest.TestCase):
    def _run_cli(self, argv: list[str]) -> str:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, cli_main(argv))
        return stdout.getvalue()

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

    def test_linux_cmdline_reader_uses_proc_cmdline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "4321"
            pid_dir.mkdir(parents=True)
            (pid_dir / "cmdline").write_bytes(b"hermes\0-p\0coder\0gateway\0run\0")

            argv = _read_linux_cmdline(4321, proc_root=proc_root)

            self.assertEqual(["hermes", "-p", "coder", "gateway", "run"], argv)
            self.assertEqual([], _read_linux_cmdline(9999, proc_root=proc_root))

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

    def test_supervisor_marks_start_failed_when_gateway_exits_immediately(self) -> None:
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
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=ExitedPopen,
                startup_grace_seconds=0,
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

    def test_supervisor_stop_waits_for_graceful_gateway_shutdown(self) -> None:
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
            alive_checks = iter([True, False])
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: next(alive_checks, False),
                cmdline_reader=lambda pid: ["hermes", "-p", "coder", "gateway", "run"],
                stop_grace_seconds=0.01,
            )
            supervisor._write_pid_marker(
                str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
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
                "hermes",
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: ["hermes", "-p", "coder", "gateway", "run"],
                stop_grace_seconds=0.01,
            )
            supervisor._processes["coder"] = AlwaysTimeoutProcess()
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
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
                "hermes",
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: ["hermes", "-p", "coder", "gateway", "run"],
                stop_grace_seconds=0.01,
                kill_after_timeout=True,
            )
            supervisor._processes["coder"] = TimeoutThenExitProcess()
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
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
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: next(alive_checks, False),
                cmdline_reader=lambda pid: ["hermes", "-p", "coder", "gateway", "run"],
                stop_grace_seconds=0.01,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.restart("coder")

            self.assertEqual([(4321, "SIGTERM")], sent)
            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual(4321, status.pid)
            self.assertEqual("restarted", status.message)

    def test_supervisor_restart_aborts_when_pid_ownership_is_unverified(self) -> None:
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
                popen_factory=FakePopen,
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
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
                "hermes",
                root / ".zeus" / "hermes",
                kill_fn=lambda pid, sig: sent.append((pid, sig.name)),
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: ["hermes", "-p", "coder", "gateway", "run"],
                stop_grace_seconds=0.01,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                9999,
                ["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_supervisor_refuses_marker_when_live_command_is_missing(self) -> None:
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
                cmdline_reader=lambda pid: None,
                stop_grace_seconds=0.01,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

    def test_supervisor_refuses_live_command_mismatch(self) -> None:
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
                cmdline_reader=lambda pid: ["sleep", "60"],
                stop_grace_seconds=0.01,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
            )

            status = supervisor.stop("coder")

            self.assertEqual([], sent)
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIn("ownership", status.message)

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
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: False,
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
            store = StateStore(root / "zeus.db")
            store.init()
            due_later = datetime(2026, 1, 1, 0, 1, tzinfo=UTC)
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                    status=BotStatus.failed,
                    restart_policy=RestartPolicy.on_failure,
                    restart_max_attempts=1,
                    restart_attempts=1,
                    next_restart_at=due_later,
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: False,
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

    def test_audit_log_records_lifecycle_and_redacts_secret_like_fields(self) -> None:
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
                    restart_policy=RestartPolicy.on_failure,
                )
            )
            store.append_audit_event("bot.create", bot_id="coder", api_key="plain-secret")
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: False,
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
                    profile_path=str(root / ".zeus" / "hermes" / "profiles" / "coder"),
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / ".zeus" / "hermes",
                popen_factory=FakePopen,
                pid_alive_fn=lambda pid: False,
            )

            status = supervisor.start("coder")

            self.assertEqual(BotStatus.running, status.status)
            self.assertEqual(4321, status.pid)

    def test_supervisor_inspect_reports_metadata_without_env_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
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
                "hermes",
                root / ".zeus" / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: ["hermes", "-p", "coder", "gateway", "run"],
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                ["hermes", "-p", "coder", "gateway", "run"],
            )

            inspected = supervisor.inspect("coder")

            self.assertEqual("coder", inspected["bot"]["bot_id"])
            self.assertTrue(inspected["profile_files"]["config.yaml"])
            self.assertTrue(inspected["profile_files"]["cron/jobs.json"])
            self.assertTrue(inspected["pid_marker"]["exists"])
            self.assertTrue(inspected["pid_marker"]["valid"])
            self.assertTrue(inspected["live_cmdline_verified"])
            self.assertIn("ready", inspected["recent_logs"])
            serialized = json.dumps(inspected)
            self.assertNotIn("plain-secret", serialized)
            self.assertNotIn("plain-log-secret", serialized)
            self.assertNotIn("OPENROUTER_API_KEY", serialized)

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

            def status(self, bot_id: str) -> BotStatusResponse:
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
