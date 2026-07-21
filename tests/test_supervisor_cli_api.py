from __future__ import annotations

import hashlib
import hmac
import http.client
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.api import main as api_main
from zeus.api import make_handler
from zeus.cli import _parse_env, _services, build_parser
from zeus.cli import main as cli_main
from zeus.config import Settings
from zeus.doctor import _check_runtime_paths, run_doctor
from zeus.envfile import parse_env_text
from zeus.errors import BotArchiveError, BotDeleteError, BotExistsError
from zeus.hermes_adapter import HermesAdapter
from zeus.lifecycle import LifecycleEventInput
from zeus.logging_utils import redact_secrets
from zeus.models import BotRecord, BotStatus, BotStatusResponse, DesiredState, RestartPolicy
from zeus.private_io import UnsafeFileError
from zeus.process_lock import LockTimeoutError
from zeus.readiness import ReadinessResult
from zeus.reconciliation import (
    BotReconcileResult,
    ReconcileOutcome,
    ReconcileRunStart,
    ReconcileRunSummary,
)
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

    def _run_cli_result(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli_main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _copy_cli_template(self, root: Path, template_id: str = "coding-bot") -> None:
        templates = root / "templates"
        templates.mkdir()
        source = Path(__file__).resolve().parents[1] / "templates" / f"{template_id}.toml"
        (templates / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

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

    def test_strict_runtime_contract_accepts_schema3_and_rejects_compat_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "zeus.db")
            store.init()
            running = BotRecord(
                bot_id="coder",
                template_id="coding-bot",
                display_name="Coder",
                profile_path=str(profile),
                status=BotStatus.running,
                pid=4321,
                desired_state=DesiredState.running,
                desired_revision=1,
            )
            store.upsert_bot(running)
            signals: list[tuple[int, object]] = []
            supervisor = Supervisor(
                store,
                hermes_bin,
                hermes_root,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: "test-process-start:4321",
                kill_fn=lambda pid, sent_signal: signals.append((pid, sent_signal)),
            )
            argv = self._gateway_argv(hermes_bin)
            command_fingerprint = hashlib.sha256(
                json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            schema3 = {
                "schema": 3,
                "bot_id": "coder",
                "component": "gateway",
                "action": "run",
                "operation_id": "a" * 32,
                "desired_revision": 1,
                "argv": argv,
                "resolved_hermes_bin": hermes_bin,
                "command_fingerprint": command_fingerprint,
                "readiness_probe": None,
                "pid": 4321,
                "started_at": 1_780_000_000.0,
                "proc_start_fingerprint": "test-process-start:4321",
            }
            schema2 = {
                "schema": 2,
                "pid": 4321,
                "bot_id": "coder",
                "component": "gateway",
                "action": "run",
                "argv": self._gateway_argv(hermes_bin),
                "resolved_hermes_bin": hermes_bin,
                "started_at": 1_780_000_000.0,
                "proc_start_fingerprint": "test-process-start:4321",
            }
            legacy = {
                "pid": 4321,
                "argv": self._gateway_argv(hermes_bin),
                "started_at": 1_780_000_000.0,
                "proc_start_fingerprint": "test-process-start:4321",
            }
            marker_path = supervisor.pid_marker_path(str(profile))
            marker_path.parent.mkdir(parents=True)

            self.assertEqual(3, schema3["schema"])
            marker_path.write_text(json.dumps(schema3, sort_keys=True), encoding="utf-8")
            inspected = supervisor.inspect("coder")

            self.assertEqual(3, inspected["pid_marker"]["schema"])
            self.assertIs(True, inspected["live_cmdline_verified"])
            self.assertEqual(
                {
                    "verified": True,
                    "reason": "ok",
                    "classification": "direct-hermes",
                    "expected": {
                        "bot_id": "coder",
                        "component": "gateway",
                        "action": "run",
                    },
                },
                inspected["ownership"],
            )

            for name, marker in (("schema2", schema2), ("legacy", legacy)):
                with self.subTest(name=name):
                    store.upsert_bot(running)
                    marker_path.write_text(
                        json.dumps(marker, sort_keys=True),
                        encoding="utf-8",
                    )
                    result = supervisor.stop("coder")

                    self.assertEqual(BotStatus.failed, result.status)
                    self.assertEqual(
                        "action required: schema-v2 or legacy gateway stop "
                        "requires manual process resolution",
                        result.message,
                    )
                    self.assertEqual(marker, json.loads(marker_path.read_text(encoding="utf-8")))
                    self.assertEqual([], signals)

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

    def test_cli_create_help_recommends_env_from_and_warns_legacy_env_is_unsafe(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(["bot", "create", "--help"])

        self.assertEqual(0, raised.exception.code)
        help_text = stdout.getvalue()
        self.assertIn("--env-from", help_text)
        self.assertIn("process environment", help_text)
        self.assertIn("unsafe for secrets", help_text)

    def test_cli_env_from_process_value_wins_without_entering_parser_namespace_or_output(
        self,
    ) -> None:
        process_secret = "process-precedence-sentinel"
        dotenv_secret = "dotenv-precedence-sentinel"
        parsed = build_parser().parse_args(
            [
                "bot",
                "create",
                "coder",
                "--template",
                "coding-bot",
                "--env-from",
                "OPENROUTER_API_KEY",
            ]
        )
        self.assertEqual(["OPENROUTER_API_KEY"], parsed.env_from)
        self.assertFalse(process_secret in repr(vars(parsed)))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_cli_template(root)
            (root / ".env").write_text(f"OPENROUTER_API_KEY={dotenv_secret}\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(
                    os.environ,
                    {
                        "ZEUS_STATE_DIR": str(root / ".zeus"),
                        "OPENROUTER_API_KEY": process_secret,
                    },
                    clear=True,
                ):
                    exit_code, stdout, stderr = self._run_cli_result(
                        [
                            "bot",
                            "create",
                            "coder",
                            "--template",
                            "coding-bot",
                            "--env-from",
                            "OPENROUTER_API_KEY",
                        ]
                    )
            finally:
                os.chdir(old_cwd)

            self.assertEqual(0, exit_code)
            profile_env = (root / ".zeus" / "hermes" / "profiles" / "coder" / ".env").read_text(
                encoding="utf-8"
            )
            parsed_profile_env = parse_env_text(profile_env)
            self.assertTrue(
                hmac.compare_digest(parsed_profile_env["OPENROUTER_API_KEY"], process_secret)
            )
            self.assertFalse(dotenv_secret in profile_env)
            self.assertFalse(process_secret in stdout + stderr)
            self.assertFalse(dotenv_secret in stdout + stderr)
            audit_text = (root / ".zeus" / "logs" / "audit.jsonl").read_text(encoding="utf-8")
            self.assertFalse(process_secret in audit_text)
            self.assertFalse(dotenv_secret in audit_text)
            database_bytes = (root / ".zeus" / "zeus.db").read_bytes()
            self.assertFalse(process_secret.encode() in database_bytes)
            self.assertFalse(dotenv_secret.encode() in database_bytes)

    def test_cli_env_from_uses_trusted_dotenv_fallback_without_echoing_value(self) -> None:
        dotenv_secret = "trusted-dotenv-fallback-sentinel"
        unrequested_secret = "unrequested-dotenv-sentinel"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_cli_template(root)
            (root / ".env").write_text(
                f"OPENROUTER_API_KEY={dotenv_secret}\nOPENAI_API_KEY={unrequested_secret}\n",
                encoding="utf-8",
            )
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(
                    os.environ,
                    {"ZEUS_STATE_DIR": str(root / ".zeus")},
                    clear=True,
                ):
                    exit_code, stdout, stderr = self._run_cli_result(
                        [
                            "bot",
                            "create",
                            "coder",
                            "--template",
                            "coding-bot",
                            "--env-from",
                            "OPENROUTER_API_KEY",
                        ]
                    )
            finally:
                os.chdir(old_cwd)

            self.assertEqual(0, exit_code)
            profile_env = (root / ".zeus" / "hermes" / "profiles" / "coder" / ".env").read_text(
                encoding="utf-8"
            )
            parsed_profile_env = parse_env_text(profile_env)
            self.assertTrue(
                hmac.compare_digest(parsed_profile_env["OPENROUTER_API_KEY"], dotenv_secret)
            )
            self.assertFalse(dotenv_secret in stdout + stderr)
            self.assertFalse(unrequested_secret in profile_env)
            self.assertFalse(unrequested_secret in stdout + stderr)
            profile_env_path = root / ".zeus" / "hermes" / "profiles" / "coder" / ".env"
            self.assertEqual(0o600, stat.S_IMODE(profile_env_path.stat().st_mode))

    def test_cli_env_from_missing_and_empty_values_fail_before_service_creation(self) -> None:
        fallback_secret = "must-not-fall-back-sentinel"
        for value_state in ("missing", "empty"):
            for as_json in (False, True):
                with (
                    self.subTest(value_state=value_state, as_json=as_json),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    self._copy_cli_template(root)
                    if value_state == "empty":
                        (root / ".env").write_text(
                            f"OPENROUTER_API_KEY={fallback_secret}\n", encoding="utf-8"
                        )
                    env = {"ZEUS_STATE_DIR": str(root / ".zeus")}
                    if value_state == "empty":
                        env["OPENROUTER_API_KEY"] = ""
                    argv = [
                        "bot",
                        "create",
                        "coder",
                        "--template",
                        "coding-bot",
                        "--env-from",
                        "OPENROUTER_API_KEY",
                    ]
                    if as_json:
                        argv.append("--json")
                    old_cwd = Path.cwd()
                    try:
                        os.chdir(root)
                        with patch.dict(os.environ, env, clear=True):
                            exit_code, stdout, stderr = self._run_cli_result(argv)
                    finally:
                        os.chdir(old_cwd)

                    self.assertEqual(1, exit_code)
                    output = stdout + stderr
                    self.assertIn("OPENROUTER_API_KEY", output)
                    self.assertIn("missing or empty", output)
                    self.assertFalse(fallback_secret in output)
                    self.assertFalse((root / ".zeus").exists())
                    if as_json:
                        payload = json.loads(stdout)
                        self.assertEqual("invalid_request", payload["error"]["code"])
                        self.assertEqual("", stderr)
                    else:
                        self.assertEqual("", stdout)

    def test_cli_env_from_rejects_duplicate_and_invalid_names_without_values(self) -> None:
        imported_secret = "imported-duplicate-sentinel"
        legacy_secret = "legacy-duplicate-sentinel"
        invalid_name = "invalid-name\ninjected-control-text"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_cli_template(root)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(
                    os.environ,
                    {
                        "ZEUS_STATE_DIR": str(root / ".zeus"),
                        "OPENROUTER_API_KEY": imported_secret,
                    },
                    clear=True,
                ):
                    duplicate = self._run_cli_result(
                        [
                            "bot",
                            "create",
                            "coder",
                            "--template",
                            "coding-bot",
                            "--env",
                            f"OPENROUTER_API_KEY={legacy_secret}",
                            "--env-from",
                            "OPENROUTER_API_KEY",
                        ]
                    )
                    invalid_import = self._run_cli_result(
                        [
                            "bot",
                            "create",
                            "coder",
                            "--template",
                            "coding-bot",
                            "--env-from",
                            invalid_name,
                        ]
                    )
            finally:
                os.chdir(old_cwd)

            for exit_code, stdout, stderr in (duplicate, invalid_import):
                self.assertEqual(1, exit_code)
                self.assertFalse(imported_secret in stdout + stderr)
                self.assertFalse(legacy_secret in stdout + stderr)
            self.assertIn("provided by both --env and --env-from", duplicate[2])
            self.assertIn("valid environment variable name", invalid_import[2])
            self.assertFalse(invalid_name in invalid_import[2])
            self.assertNotIn("injected-control-text", invalid_import[2])
            self.assertFalse((root / ".zeus").exists())

    def test_cli_env_from_value_is_not_disclosed_when_template_rejects_key(self) -> None:
        secret = "controlled-failure-sentinel"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_cli_template(root)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(
                    os.environ,
                    {
                        "ZEUS_STATE_DIR": str(root / ".zeus"),
                        "OPENAI_API_KEY": secret,
                    },
                    clear=True,
                ):
                    exit_code, stdout, stderr = self._run_cli_result(
                        [
                            "bot",
                            "create",
                            "coder",
                            "--template",
                            "coding-bot",
                            "--env-from",
                            "OPENAI_API_KEY",
                            "--json",
                        ]
                    )
            finally:
                os.chdir(old_cwd)

            self.assertEqual(1, exit_code)
            payload = json.loads(stdout)
            self.assertEqual("invalid_request", payload["error"]["code"])
            self.assertIn("OPENAI_API_KEY", payload["error"]["message"])
            self.assertFalse(secret in stdout + stderr)
            self.assertFalse((root / ".zeus" / "hermes" / "profiles" / "coder").exists())

    def test_cli_legacy_env_syntax_remains_compatible(self) -> None:
        legacy_value = "legacy-compatible-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._copy_cli_template(root)
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(
                    os.environ,
                    {"ZEUS_STATE_DIR": str(root / ".zeus")},
                    clear=True,
                ):
                    exit_code, _stdout, _stderr = self._run_cli_result(
                        [
                            "bot",
                            "create",
                            "coder",
                            "--template",
                            "coding-bot",
                            "--env",
                            f"OPENROUTER_API_KEY={legacy_value}",
                        ]
                    )
            finally:
                os.chdir(old_cwd)

            self.assertEqual(0, exit_code)
            profile_env = (root / ".zeus" / "hermes" / "profiles" / "coder" / ".env").read_text(
                encoding="utf-8"
            )
            parsed_profile_env = parse_env_text(profile_env)
            self.assertTrue(
                hmac.compare_digest(parsed_profile_env["OPENROUTER_API_KEY"], legacy_value)
            )

    def test_cli_legacy_env_parser_keeps_historical_permissive_and_error_contract(self) -> None:
        self.assertEqual({"legacy-key": "value"}, _parse_env(["legacy-key=value"]))

        malformed = "legacy-key"
        with self.assertRaises(SystemExit) as raised:
            _parse_env([malformed])
        self.assertEqual(f"--env must be NAME=VALUE, got {malformed!r}", str(raised.exception))

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

    def test_cli_create_start_stop_and_reconcile_json_exit_contracts(self) -> None:
        timestamp = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
        created = BotRecord(
            bot_id="coder",
            template_id="coding-bot",
            display_name="Coder",
            profile_path="/profiles/coder",
            created_at=timestamp,
            updated_at=timestamp,
        )
        started = BotStatusResponse(
            bot_id="start-failed",
            status=BotStatus.failed,
            pid=None,
            profile_path="/profiles/start-failed",
            message="failed to start gateway: missing hermes",
        )
        stopped = BotStatusResponse(
            bot_id="coder",
            status=BotStatus.stopped,
            pid=None,
            profile_path="/profiles/coder",
            message="gateway shutdown completed",
        )
        pending = BotStatusResponse(
            bot_id="pending-bot",
            status=BotStatus.failed,
            pid=None,
            profile_path="/profiles/pending-bot",
            message="restart scheduled: attempt 1/5 in 5s",
        )
        terminal = BotStatusResponse(
            bot_id="broken-bot",
            status=BotStatus.failed,
            pid=None,
            profile_path="/profiles/broken-bot",
            message="manual policy: not restarting",
        )

        class CliContractSupervisor:
            def create_bot(self, request, template, **kwargs):
                if request.bot_id == "existing":
                    raise BotExistsError("bot already exists: existing")
                return created

            def start(self, bot_id: str, **kwargs) -> BotStatusResponse:
                return started

            def stop(self, bot_id: str, **kwargs) -> BotStatusResponse:
                return stopped

            def reconcile(self, bot_id: str | None, **kwargs) -> list[BotStatusResponse]:
                return [pending if bot_id == "pending-bot" else terminal]

        def run(argv: list[str]) -> tuple[int, str, str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli_main(argv)
            return exit_code, stdout.getvalue(), stderr.getvalue()

        created_json = {
            "bot_id": "coder",
            "template_id": "coding-bot",
            "display_name": "Coder",
            "profile_path": "/profiles/coder",
            "status": "stopped",
            "pid": None,
            "restart_policy": "manual",
            "restart_backoff_seconds": 5.0,
            "restart_max_attempts": 5,
            "restart_attempts": 0,
            "next_restart_at": None,
            "started_at": None,
            "ready_at": None,
            "stopped_at": None,
            "last_exit_code": None,
            "last_error": None,
            "last_transition_reason": None,
            "desired_state": "stopped",
            "converged": True,
            "created_at": "2026-07-21T12:00:00+00:00",
            "updated_at": "2026-07-21T12:00:00+00:00",
        }
        start_json = {
            "bot_id": "start-failed",
            "status": "failed",
            "pid": None,
            "profile_path": "/profiles/start-failed",
            "message": "failed to start gateway: missing hermes",
        }
        stop_json = {
            "bot_id": "coder",
            "status": "stopped",
            "pid": None,
            "profile_path": "/profiles/coder",
            "message": "gateway shutdown completed",
        }
        pending_json = {
            "bot_id": "pending-bot",
            "status": "failed",
            "pid": None,
            "profile_path": "/profiles/pending-bot",
            "message": "restart scheduled: attempt 1/5 in 5s",
        }
        terminal_json = {
            "bot_id": "broken-bot",
            "status": "failed",
            "pid": None,
            "profile_path": "/profiles/broken-bot",
            "message": "manual policy: not restarting",
        }

        cases = (
            (
                "create_success",
                ["bot", "create", "coder", "--template", "coding-bot", "--json"],
                0,
                created_json,
            ),
            (
                "create_conflict",
                ["bot", "create", "existing", "--template", "coding-bot", "--json"],
                1,
                {
                    "error": {
                        "code": "bot_exists",
                        "message": "bot already exists: existing",
                    }
                },
            ),
            ("start_failure", ["bot", "start", "start-failed"], 1, start_json),
            ("stop_success", ["bot", "stop", "coder"], 0, stop_json),
            (
                "reconcile_pending",
                ["bot", "reconcile", "pending-bot", "--json"],
                0,
                [pending_json],
            ),
            (
                "reconcile_terminal",
                ["bot", "reconcile", "broken-bot", "--json"],
                1,
                [terminal_json],
            ),
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(Path(tmp) / ".zeus")}),
            patch("zeus.cli._services", return_value=(object(), CliContractSupervisor())),
        ):
            for name, argv, expected_exit, expected_payload in cases:
                with self.subTest(name=name):
                    exit_code, output, error_output = run(argv)
                    self.assertEqual(expected_exit, exit_code)
                    self.assertEqual(
                        json.dumps(expected_payload, sort_keys=True) + "\n",
                        output,
                    )
                    self.assertEqual("", error_output)

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

    def test_audit_sanitization_is_bounded_recursive_and_best_effort(self) -> None:
        secret = "audit-sentinel-71b4"

        class Hostile:
            def __str__(self) -> str:
                raise AssertionError("string conversion invoked")

            def __repr__(self) -> str:
                raise AssertionError("representation invoked")

        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.append_audit_event(
                "bot.start_registration_failed",
                cleanup_errors=[
                    f"cleanup failed: API_KEY={secret}",
                    {"message": f"authorization=Bearer {secret}"},
                ],
                readiness_message=f"probe returned Bearer {secret}",
                nonfinite=float("nan"),
                hostile=Hostile(),
            )
            store.append_audit_event("bot.oversized", oversized="Δ" * 20_000)
            store.append_audit_event(
                "e" * 2_048,
                first="x" * 1_800,
                second="x" * 1_800,
                third="x" * 1_800,
                fourth="x" * 1_800,
            )

            raw = store.audit_log_path().read_bytes()
            lines = raw.splitlines()
            payload = json.loads(lines[0])
            self.assertFalse(secret.encode("utf-8") in raw)
            self.assertNotIn(b"NaN", raw)
            self.assertTrue(all(len(line) <= 8192 for line in lines))
            self.assertEqual("bot.start_registration_failed", payload["event"])
            self.assertEqual("[unsupported]", payload["hostile"])
            self.assertIsNone(payload["nonfinite"])
            self.assertTrue(json.loads(lines[1])["truncated"])
            self.assertTrue(json.loads(lines[2])["truncated"])

    def test_projection_and_reconcile_messages_are_sanitized_before_persistence(self) -> None:
        secret = "projection-sentinel-2f96"
        started_at = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / "profiles" / "coder"),
                    last_error=f"readiness API_KEY={secret}",
                    last_transition_reason=f"cleanup Bearer {secret}",
                )
            )
            initial_record = store.get_bot("coder")
            assert initial_record is not None
            self.assertFalse(secret in (initial_record.last_error or ""))
            self.assertFalse(secret in (initial_record.last_transition_reason or ""))
            store.update_lifecycle_state(
                "coder",
                BotStatus.failed,
                last_error=f"updated readiness API_KEY={secret}",
                last_transition_reason=f"updated cleanup Bearer {secret}",
            )
            run = ReconcileRunStart(
                run_id="security-sanitization",
                scope="fleet",
                requested_bot_id=None,
                source="cli",
                force=False,
                reset_restart=False,
                started_at=started_at,
            )
            result = BotReconcileResult(
                bot_id="coder",
                outcome=ReconcileOutcome.error,
                desired_state="running",
                observed_status="failed",
                pid=None,
                action="inspect",
                message=f"readiness API_KEY={secret}; cleanup Bearer {secret}",
                error_code="readiness_failed",
                event_id=None,
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
            )
            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)

            loaded_record = store.get_bot("coder")
            loaded_run = store.get_reconcile_run(run.run_id)
            assert loaded_record is not None
            assert loaded_run is not None
            self.assertFalse(secret in (loaded_record.last_error or ""))
            self.assertFalse(secret in (loaded_record.last_transition_reason or ""))
            self.assertFalse(secret in result.message)
            self.assertFalse(secret in loaded_run.results[0].message)
            self.assertEqual(result, loaded_run.results[0])
            with closing(sqlite3.connect(store.database_path)) as conn:
                bot_row = conn.execute(
                    "SELECT last_error, last_transition_reason FROM bots WHERE bot_id = 'coder'"
                ).fetchone()
                reconcile_row = conn.execute(
                    "SELECT message FROM reconcile_results WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()
            assert bot_row is not None
            assert reconcile_row is not None
            persisted = "\n".join((*bot_row, *reconcile_row))
            self.assertFalse(secret in persisted)

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

    def test_audit_append_delegates_exact_utf8_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            store = StateStore(root / "state" / "zeus.db")
            fixed_now = datetime(2026, 7, 21, 12, 34, 56, tzinfo=UTC)

            with (
                patch("zeus.state.datetime") as clock,
                patch("zeus.state.append_private_bytes") as append,
            ):
                clock.now.return_value = fixed_now
                store.append_audit_event(
                    "bot.test",
                    label="Δ",
                    api_key="secret",
                )

            append.assert_called_once_with(
                root / "state" / "logs" / "audit.jsonl",
                b'{"api_key": "[redacted]", "event": "bot.test", "label": "\\u0394", '
                b'"ts": "2026-07-21T12:34:56+00:00"}\n',
            )

    def test_audit_parent_symlink_is_fail_open_without_mutating_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            store = StateStore(state_dir / "zeus.db")
            store.init()
            external_logs = root / "external-audit-target"
            external_logs.mkdir(mode=0o755)
            sentinel = external_logs / "sentinel.txt"
            sentinel.write_text("external audit target\n", encoding="utf-8")
            external_mode = external_logs.stat().st_mode & 0o777
            (state_dir / "logs").symlink_to(external_logs, target_is_directory=True)

            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            hermes_bin = self._fake_hermes_path(root)
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
            self.assertEqual("external audit target\n", sentinel.read_text(encoding="utf-8"))
            self.assertEqual(external_mode, external_logs.stat().st_mode & 0o777)
            self.assertEqual(
                ["sentinel.txt"], sorted(path.name for path in external_logs.iterdir())
            )

    def test_unsafe_gateway_log_prevents_pipe_and_process_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs_path = profile_path / "logs"
            logs_path.mkdir(parents=True, mode=0o700)
            target_log = root / "external-gateway-target.log"
            target_log.write_text("external gateway target\n", encoding="utf-8")
            target_mode = target_log.stat().st_mode & 0o777
            (logs_path / "zeus-gateway.log").symlink_to(target_log)
            hermes_bin = self._fake_hermes_path(root)
            store = StateStore(root / "state" / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )

            def forbidden_popen(*args: object, **kwargs: object) -> FakePopen:
                self.fail("process factory must not be called for an unsafe gateway log")

            supervisor = Supervisor(
                store,
                hermes_bin,
                root / ".zeus" / "hermes",
                popen_factory=forbidden_popen,
                startup_grace_seconds=0,
            )

            with patch(
                "zeus.supervisor.os.pipe",
                side_effect=AssertionError("pipe allocated before gateway log validation"),
            ) as pipe:
                status = supervisor.start("coder")

            pipe.assert_not_called()
            self.assertEqual(BotStatus.failed, status.status)
            self.assertIsNone(status.pid)
            self.assertEqual("external gateway target\n", target_log.read_text(encoding="utf-8"))
            self.assertEqual(target_mode, target_log.stat().st_mode & 0o777)

    def test_direct_logs_and_inspect_reject_gateway_log_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            external_logs = root / "external-log-target"
            external_logs.mkdir(mode=0o755)
            target_log = external_logs / "zeus-gateway.log"
            target_log.write_text("TARGET-SENTINEL\n", encoding="utf-8")
            target_mode = target_log.stat().st_mode & 0o777
            (profile_path / "logs").symlink_to(external_logs, target_is_directory=True)
            store = StateStore(root / "state" / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(store, "hermes", root / ".zeus" / "hermes")

            for operation in (supervisor.logs, supervisor.inspect):
                with self.subTest(operation=operation.__name__):
                    with self.assertRaises(UnsafeFileError) as raised:
                        operation("coder")
                    self.assertNotIn("TARGET-SENTINEL", str(raised.exception))

            self.assertEqual("TARGET-SENTINEL\n", target_log.read_text(encoding="utf-8"))
            self.assertEqual(target_mode, target_log.stat().st_mode & 0o777)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_direct_inspect_rejects_linked_pid_marker_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            external_logs = root / "external-logs"
            external_logs.mkdir(mode=0o755)
            fifo = external_logs / "zeus-gateway.pid.json"
            os.mkfifo(fifo, mode=0o600)
            sentinel = external_logs / "sentinel.txt"
            sentinel.write_text("external marker target\n", encoding="utf-8")
            (profile_path / "logs").symlink_to(external_logs, target_is_directory=True)
            store = StateStore(root / "state" / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            script = """
import sys
from pathlib import Path
from zeus.private_io import UnsafeFileError
from zeus.state import StateStore
from zeus.supervisor import Supervisor

root = Path(sys.argv[1])
store = StateStore(root / "state" / "zeus.db")
supervisor = Supervisor(store, "hermes", root / ".zeus" / "hermes")
try:
    supervisor.inspect("coder")
except UnsafeFileError:
    raise SystemExit(0)
raise SystemExit(2)
"""

            try:
                completed = subprocess.run(
                    [sys.executable, "-c", script, str(root)],
                    check=False,
                    capture_output=True,
                    timeout=2,
                )
            except subprocess.TimeoutExpired:
                self.fail("direct inspect blocked on a linked PID-marker FIFO")

            self.assertEqual(0, completed.returncode, completed.stderr.decode("utf-8", "replace"))
            self.assertEqual("external marker target\n", sentinel.read_text(encoding="utf-8"))
            self.assertTrue(stat.S_ISFIFO(fifo.stat().st_mode))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_api_inspect_returns_generic_500_for_linked_pid_marker_fifo_without_blocking(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            profile_path.mkdir(parents=True)
            external_logs = root / "external-logs"
            external_logs.mkdir(mode=0o755)
            fifo = external_logs / "zeus-gateway.pid.json"
            os.mkfifo(fifo, mode=0o600)
            sentinel = external_logs / "sentinel.txt"
            sentinel.write_text("external API marker target\n", encoding="utf-8")
            (profile_path / "logs").symlink_to(external_logs, target_is_directory=True)
            store = StateStore(state_dir / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            script = """
import http.client
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from zeus.api import make_handler
from zeus.config import Settings

root = Path(sys.argv[1])
settings = Settings.from_env({
    "ZEUS_STATE_DIR": str(root / "state"),
    "ZEUS_API_KEY": "inspect-test-key",
    "ZEUS_HOST": "127.0.0.1",
    "ZEUS_PORT": "0",
})
server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(settings))
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=1)
    connection.request(
        "GET",
        "/bots/coder/inspect",
        headers={"x-zeus-api-key": "inspect-test-key"},
    )
    response = connection.getresponse()
    body = json.loads(response.read())
    expected = {
        "error": {
            "code": "internal_error",
            "message": "internal server error",
            "status": 500,
        }
    }
    if response.status != 500 or body != expected:
        raise SystemExit(2)
finally:
    server.shutdown()
    server.server_close()
raise SystemExit(0)
"""

            try:
                completed = subprocess.run(
                    [sys.executable, "-c", script, str(root)],
                    check=False,
                    capture_output=True,
                    timeout=4,
                )
            except subprocess.TimeoutExpired:
                self.fail("API inspect blocked on a linked PID-marker FIFO")

            self.assertEqual(0, completed.returncode, completed.stderr.decode("utf-8", "replace"))
            self.assertEqual("external API marker target\n", sentinel.read_text(encoding="utf-8"))
            self.assertTrue(stat.S_ISFIFO(fifo.stat().st_mode))

    def test_pid_marker_read_rejects_profile_ancestry_replacement_during_read(self) -> None:
        from zeus.supervisor import _read_bounded_file

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / "zeus-gateway.pid.json"
            marker.write_text('{"pid":4321}', encoding="utf-8")
            displaced = root / "displaced-profile"
            external = root / "external-profile"
            external_logs = external / "logs"
            external_logs.mkdir(parents=True)
            (external_logs / marker.name).write_text('{"pid":9876}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            real_open = os.open
            opened: set[int] = set()
            swapped = False

            def tracking_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                opened.add(descriptor)
                return descriptor

            def racing_read(fd: int, limit: int = 64 * 1024) -> bytes:
                nonlocal swapped
                result = _read_bounded_file(fd, limit)
                profile.rename(displaced)
                profile.symlink_to(external, target_is_directory=True)
                swapped = True
                return result

            with (
                patch("zeus.gateway_launcher.os.open", side_effect=tracking_open),
                patch("zeus.supervisor._read_bounded_file", side_effect=racing_read),
                self.assertRaises(UnsafeFileError),
            ):
                supervisor._read_pid_marker(str(profile))

            self.assertTrue(swapped)
            self.assertTrue(profile.is_symlink())
            for descriptor in opened:
                with self.subTest(descriptor=descriptor), self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_strict_marker_read_rejects_profile_ancestry_replacement_during_read(self) -> None:
        from zeus.supervisor import _read_bounded_file

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / "zeus-gateway.pid.json"
            marker.write_text('{"pid":4321}', encoding="utf-8")
            displaced = root / "displaced-profile"
            external = root / "external-profile"
            external_logs = external / "logs"
            external_logs.mkdir(parents=True)
            (external_logs / marker.name).write_text('{"pid":9876}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            real_open = os.open
            opened: set[int] = set()
            swapped = False

            def tracking_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                opened.add(descriptor)
                return descriptor

            def racing_read(fd: int, limit: int = 64 * 1024) -> bytes:
                nonlocal swapped
                result = _read_bounded_file(fd, limit)
                profile.rename(displaced)
                profile.symlink_to(external, target_is_directory=True)
                swapped = True
                return result

            with (
                patch("zeus.gateway_launcher.os.open", side_effect=tracking_open),
                patch("zeus.supervisor._read_bounded_file", side_effect=racing_read),
            ):
                observation = supervisor._read_strict_runtime_marker("coder", str(profile))

            self.assertTrue(swapped)
            self.assertEqual("untrusted", observation.kind)
            self.assertTrue(profile.is_symlink())
            for descriptor in opened:
                with self.subTest(descriptor=descriptor), self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_pid_marker_read_revalidates_ancestry_after_read_failure(self) -> None:
        from zeus.gateway_launcher import LaunchPayloadError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / "zeus-gateway.pid.json"
            marker.write_text('{"pid":4321}', encoding="utf-8")
            displaced = root / "displaced-profile"
            external = root / "external-profile"
            (external / "logs").mkdir(parents=True)
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            swapped = False

            def failing_read(_fd: int, _limit: int = 64 * 1024) -> bytes:
                nonlocal swapped
                profile.rename(displaced)
                profile.symlink_to(external, target_is_directory=True)
                swapped = True
                raise LaunchPayloadError("injected bounded read failure")

            with (
                patch("zeus.supervisor._read_bounded_file", side_effect=failing_read),
                self.assertRaises(UnsafeFileError),
            ):
                supervisor._read_pid_marker(str(profile))

            self.assertTrue(swapped)
            self.assertTrue(profile.is_symlink())

    def test_strict_marker_read_closes_all_descriptors_when_one_close_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / "zeus-gateway.pid.json"
            marker.write_text('{"pid":4321}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            real_open = os.open
            real_close = os.close
            opened: set[int] = set()
            close_failed = False

            def tracking_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                opened.add(descriptor)
                return descriptor

            def noisy_close(fd: int) -> None:
                nonlocal close_failed
                real_close(fd)
                if not close_failed:
                    close_failed = True
                    raise OSError("injected close failure")

            with (
                patch("zeus.gateway_launcher.os.open", side_effect=tracking_open),
                patch("zeus.supervisor.os.close", side_effect=noisy_close),
            ):
                observation = supervisor._read_strict_runtime_marker("coder", str(profile))

            self.assertTrue(close_failed)
            self.assertEqual("present", observation.kind)
            for descriptor in opened:
                with self.subTest(descriptor=descriptor), self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_strict_marker_read_rejects_current_owner_mismatch(self) -> None:
        from zeus.gateway_launcher import MARKER_NAME

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / MARKER_NAME
            marker.write_text('{"pid":4321}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            real_stat = os.stat
            marker_stats = 0

            def mismatched_owner_stat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                nonlocal marker_stats
                result = real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
                if path == MARKER_NAME and dir_fd is not None:
                    marker_stats += 1
                    if marker_stats == 2:
                        fields = list(result)
                        fields[4] = result.st_uid + 1
                        return os.stat_result(fields)
                return result

            with patch("zeus.gateway_launcher.os.stat", side_effect=mismatched_owner_stat):
                observation = supervisor._read_strict_runtime_marker("coder", str(profile))

            self.assertGreaterEqual(marker_stats, 2)
            self.assertEqual("untrusted", observation.kind)

    def test_strict_marker_read_rechecks_leaf_after_final_directory_validation(self) -> None:
        from zeus.gateway_launcher import _validate_open_directory_binding

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / "zeus-gateway.pid.json"
            marker.write_text('{"pid":4321}', encoding="utf-8")
            displaced = logs / "displaced-marker.json"
            target = root / "external-marker.json"
            target.write_text('{"pid":9876}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            logs_validations = 0
            swapped = False

            def racing_directory_validation(
                parent_fd: int,
                name: str,
                directory_fd: int,
                description: str,
            ) -> os.stat_result:
                nonlocal logs_validations, swapped
                result = _validate_open_directory_binding(
                    parent_fd,
                    name,
                    directory_fd,
                    description,
                )
                if name == "logs":
                    logs_validations += 1
                    if logs_validations == 2:
                        marker.rename(displaced)
                        marker.symlink_to(target)
                        swapped = True
                return result

            with patch(
                "zeus.gateway_launcher._validate_open_directory_binding",
                side_effect=racing_directory_validation,
            ):
                observation = supervisor._read_strict_runtime_marker("coder", str(profile))

            self.assertTrue(swapped)
            self.assertEqual(2, logs_validations)
            self.assertEqual("untrusted", observation.kind)
            self.assertTrue(marker.is_symlink())

    def test_pid_marker_read_rejects_symlink_appearing_during_missing_lookup(self) -> None:
        from zeus.gateway_launcher import MARKER_NAME

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / MARKER_NAME
            target = root / "external-marker.json"
            target.write_text('{"pid":9876}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            real_stat = os.stat
            appeared = False

            def racing_stat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                nonlocal appeared
                if path == MARKER_NAME and dir_fd is not None and not appeared:
                    try:
                        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
                    except FileNotFoundError:
                        marker.symlink_to(target)
                        appeared = True
                        raise
                return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

            with (
                patch("zeus.gateway_launcher.os.stat", side_effect=racing_stat),
                self.assertRaises(UnsafeFileError),
            ):
                supervisor._read_pid_marker(str(profile))

            self.assertTrue(appeared)
            self.assertTrue(marker.is_symlink())
            self.assertEqual('{"pid":9876}', target.read_text(encoding="utf-8"))

    def test_strict_marker_read_rejects_symlink_appearing_during_missing_lookup(self) -> None:
        from zeus.gateway_launcher import MARKER_NAME

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs = profile / "logs"
            logs.mkdir(parents=True, mode=0o700)
            marker = logs / MARKER_NAME
            target = root / "external-marker.json"
            target.write_text('{"pid":9876}', encoding="utf-8")
            _store, supervisor = self._supervisor_for_profile_path(root, profile)
            real_stat = os.stat
            appeared = False

            def racing_stat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                nonlocal appeared
                if path == MARKER_NAME and dir_fd is not None and not appeared:
                    try:
                        return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
                    except FileNotFoundError:
                        marker.symlink_to(target)
                        appeared = True
                        raise
                return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

            with patch("zeus.gateway_launcher.os.stat", side_effect=racing_stat):
                observation = supervisor._read_strict_runtime_marker("coder", str(profile))

            self.assertTrue(appeared)
            self.assertEqual("untrusted", observation.kind)
            self.assertTrue(marker.is_symlink())
            self.assertEqual('{"pid":9876}', target.read_text(encoding="utf-8"))

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

    def test_supervisor_inspect_preserves_invalid_pid_marker_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            profile_path = root / ".zeus" / "hermes" / "profiles" / "coder"
            logs_path = profile_path / "logs"
            logs_path.mkdir(parents=True, mode=0o700)
            marker = logs_path / "zeus-gateway.pid.json"
            marker.write_text("{invalid json\n", encoding="utf-8")
            marker.chmod(0o640)
            store = StateStore(root / "state" / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(profile_path),
                )
            )
            supervisor = Supervisor(store, "hermes", root / ".zeus" / "hermes")

            inspected = supervisor.inspect("coder")

            self.assertEqual(True, inspected["pid_marker"]["exists"])
            self.assertEqual(False, inspected["pid_marker"]["valid"])
            self.assertEqual("0640", inspected["pid_marker"]["mode"])
            self.assertIn("error", inspected["pid_marker"])
            self.assertEqual("", inspected["recent_logs"])

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
                mode_after = state_dir.stat().st_mode & 0o777
            finally:
                os.chdir(old_cwd)

        self.assertEqual("fail", check.status)
        self.assertIn("must not be accessible to other users", check.message)
        self.assertEqual(0o755, mode_after)

    def test_doctor_rejects_real_and_broken_logs_symlinks_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            state_dir.chmod(0o700)
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})
            external_logs = root / "external-doctor-target"
            external_logs.mkdir(mode=0o755)
            sentinel = external_logs / "sentinel.txt"
            sentinel.write_text("doctor target\n", encoding="utf-8")
            target_mode = external_logs.stat().st_mode & 0o777
            logs_link = state_dir / "logs"

            logs_link.symlink_to(external_logs, target_is_directory=True)
            real_check = _check_runtime_paths(settings)
            logs_link.unlink()
            logs_link.symlink_to(root / "missing-doctor-target", target_is_directory=True)
            broken_check = _check_runtime_paths(settings)

            self.assertEqual("fail", real_check.status)
            self.assertEqual("fail", broken_check.status)
            self.assertIn("logs", real_check.message.lower())
            self.assertIn("logs", broken_check.message.lower())
            self.assertNotIn(str(external_logs), real_check.message)
            self.assertEqual("doctor target\n", sentinel.read_text(encoding="utf-8"))
            self.assertEqual(target_mode, external_logs.stat().st_mode & 0o777)

    def test_doctor_rejects_permissive_logs_directory_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            logs_dir = state_dir / "logs"
            logs_dir.mkdir(parents=True, mode=0o755)
            state_dir.chmod(0o700)
            logs_dir.chmod(0o755)
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})

            check = _check_runtime_paths(settings)

            self.assertEqual("fail", check.status)
            self.assertIn("logs", check.message.lower())
            self.assertEqual(0o755, logs_dir.stat().st_mode & 0o777)

    def test_doctor_rejects_runtime_directory_owned_by_another_user(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})
            real_lstat = os.lstat

            def foreign_owner(path: Path) -> os.stat_result:
                metadata = real_lstat(path)
                fields = list(metadata)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)

            with patch("zeus.doctor.os.lstat", side_effect=foreign_owner):
                check = _check_runtime_paths(settings)

            self.assertEqual("fail", check.status)
            self.assertIn("owned by the current user", check.message)
            self.assertEqual(0o700, state_dir.stat().st_mode & 0o777)

    def test_doctor_rejects_state_symlink_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            external_state = root / "external-state-target"
            external_state.mkdir(mode=0o700)
            external_state.chmod(0o700)
            sentinel = external_state / "sentinel.txt"
            sentinel.write_text("state target\n", encoding="utf-8")
            target_mode = external_state.stat().st_mode & 0o777
            state_dir.symlink_to(external_state, target_is_directory=True)
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})

            check = _check_runtime_paths(settings)

            self.assertEqual(state_dir, settings.state_dir)
            self.assertEqual("fail", check.status)
            self.assertNotIn(str(external_state), check.message)
            self.assertEqual("state target\n", sentinel.read_text(encoding="utf-8"))
            self.assertEqual(target_mode, external_state.stat().st_mode & 0o777)

    def test_doctor_does_not_repair_state_replaced_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            displaced = root / "state-displaced"
            replacement = root / "state-replacement"
            replacement.mkdir(mode=0o777)
            replacement.chmod(0o777)
            sentinel = replacement / "sentinel.txt"
            sentinel.write_text("replacement state\n", encoding="utf-8")
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})
            real_lstat = os.lstat
            swapped = False

            def racing_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> os.stat_result:
                nonlocal swapped
                metadata = real_lstat(path, dir_fd=dir_fd)
                if not swapped and dir_fd is None and Path(path) == state_dir:
                    state_dir.rename(displaced)
                    replacement.rename(state_dir)
                    swapped = True
                return metadata

            with patch("zeus.doctor.os.lstat", side_effect=racing_lstat):
                check = _check_runtime_paths(settings)

            self.assertTrue(swapped)
            self.assertEqual("fail", check.status)
            self.assertEqual(
                "replacement state\n",
                (state_dir / sentinel.name).read_text(encoding="utf-8"),
            )
            self.assertEqual(0o777, state_dir.stat().st_mode & 0o777)

    def test_doctor_does_not_repair_logs_replaced_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            logs_dir = state_dir / "logs"
            logs_dir.mkdir(parents=True, mode=0o700)
            state_dir.chmod(0o700)
            logs_dir.chmod(0o700)
            displaced = state_dir / "logs-displaced"
            replacement = state_dir / "logs-replacement"
            replacement.mkdir(mode=0o777)
            replacement.chmod(0o777)
            sentinel = replacement / "sentinel.txt"
            sentinel.write_text("replacement logs\n", encoding="utf-8")
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})
            real_lstat = os.lstat
            swapped = False

            def racing_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> os.stat_result:
                nonlocal swapped
                metadata = real_lstat(path, dir_fd=dir_fd)
                if not swapped and dir_fd is None and Path(path) == logs_dir:
                    logs_dir.rename(displaced)
                    replacement.rename(logs_dir)
                    swapped = True
                return metadata

            with patch("zeus.doctor.os.lstat", side_effect=racing_lstat):
                check = _check_runtime_paths(settings)

            self.assertTrue(swapped)
            self.assertEqual("fail", check.status)
            self.assertIn("logs", check.message.lower())
            self.assertEqual(
                "replacement logs\n",
                (logs_dir / sentinel.name).read_text(encoding="utf-8"),
            )
            self.assertEqual(0o777, logs_dir.stat().st_mode & 0o777)

    def test_doctor_rejects_same_inode_mode_drift_at_final_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            state_dir.chmod(0o700)
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})
            real_lstat = os.lstat
            state_lstats = 0

            def racing_lstat(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> os.stat_result:
                nonlocal state_lstats
                if path == state_dir.name and dir_fd is not None:
                    state_lstats += 1
                    if state_lstats == 3:
                        state_dir.chmod(0o777)
                return real_lstat(path, dir_fd=dir_fd)

            with patch("zeus.doctor.os.lstat", side_effect=racing_lstat):
                check = _check_runtime_paths(settings)

            self.assertEqual("fail", check.status)
            self.assertEqual(3, state_lstats)
            self.assertEqual(0o777, state_dir.stat().st_mode & 0o777)

    def test_settings_ensure_dirs_creates_missing_private_runtime_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env({"ZEUS_STATE_DIR": str(Path(tmp) / "state")})

            settings.ensure_dirs()

            for path in (
                settings.state_dir,
                settings.hermes_root,
                settings.state_dir / "logs",
                settings.state_dir / "locks",
                settings.state_dir / "locks" / "bots",
            ):
                with self.subTest(path=path):
                    self.assertTrue(path.is_dir())
                    self.assertEqual(0o700, path.stat().st_mode & 0o777)

    def test_runtime_entrypoints_reject_real_and_dangling_state_links(self) -> None:
        for dangling in (False, True):
            with self.subTest(dangling=dangling), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                state_dir = root / "state"
                external_state = root / "external-state"
                if not dangling:
                    external_state.mkdir(mode=0o755)
                    external_state.chmod(0o755)
                    (external_state / "sentinel.txt").write_text(
                        "external state\n", encoding="utf-8"
                    )
                state_dir.symlink_to(external_state, target_is_directory=True)
                settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})

                check = _check_runtime_paths(settings)
                with self.assertRaises(UnsafeFileError):
                    settings.ensure_dirs()
                StateStore(settings.database_path).append_audit_event("link.proof")
                with self.assertRaises(UnsafeFileError):
                    make_handler(settings)

                self.assertEqual("fail", check.status)
                self.assertEqual(state_dir, settings.state_dir)
                if dangling:
                    self.assertFalse(external_state.exists())
                else:
                    self.assertEqual(
                        ["sentinel.txt"], sorted(path.name for path in external_state.iterdir())
                    )
                    self.assertEqual(0o755, external_state.stat().st_mode & 0o777)

    def test_runtime_entrypoints_reject_real_and_dangling_state_ancestor_links(self) -> None:
        for dangling in (False, True):
            with self.subTest(dangling=dangling), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                linked_parent = root / "linked-parent"
                external_parent = root / "external-parent"
                external_state = external_parent / "state"
                if not dangling:
                    external_state.mkdir(parents=True, mode=0o700)
                    external_state.chmod(0o700)
                    (external_state / "sentinel.txt").write_text(
                        "external ancestor state\n", encoding="utf-8"
                    )
                linked_parent.symlink_to(external_parent, target_is_directory=True)
                state_dir = linked_parent / "state"
                settings = Settings.from_env({"ZEUS_STATE_DIR": str(state_dir)})

                check = _check_runtime_paths(settings)
                with self.assertRaises(UnsafeFileError):
                    settings.ensure_dirs()
                StateStore(settings.database_path).append_audit_event("ancestor-link.proof")
                with self.assertRaises(UnsafeFileError):
                    make_handler(settings)

                self.assertEqual("fail", check.status)
                self.assertEqual(state_dir, settings.state_dir)
                if dangling:
                    self.assertFalse(external_parent.exists())
                else:
                    self.assertEqual(
                        ["sentinel.txt"], sorted(path.name for path in external_state.iterdir())
                    )
                    self.assertEqual(0o700, external_state.stat().st_mode & 0o777)

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
