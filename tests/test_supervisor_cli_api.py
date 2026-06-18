from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeus.api import make_handler
from zeus.cli import main as cli_main
from zeus.config import Settings
from zeus.doctor import run_doctor
from zeus.hermes_adapter import HermesAdapter
from zeus.logging_utils import redact_secrets
from zeus.models import BotRecord, BotStatus, RestartPolicy
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class FakePopen:
    def __init__(self, argv, env, stdout, stderr):
        self.argv = argv
        self.env = env
        self.stdout = stdout
        self.stderr = stderr
        self.pid = 4321


class SupervisorCliApiTests(unittest.TestCase):
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
            self.assertIn("restart scheduled", scheduled.message)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(1, loaded.restart_attempts)
            self.assertEqual(now + timedelta(seconds=10), loaded.next_restart_at)

            pending = supervisor.reconcile("coder", now=now + timedelta(seconds=5))[0]

            self.assertEqual(BotStatus.failed, pending.status)
            self.assertIn("restart pending", pending.message)

            restarted = supervisor.reconcile("coder", now=now + timedelta(seconds=10))[0]

            self.assertEqual(BotStatus.running, restarted.status)
            self.assertEqual(4321, restarted.pid)
            self.assertEqual("restarted by reconcile", restarted.message)
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
            self.assertIn("restart limit reached", status.message)

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
            self.assertIn("restart policy is manual", status.message)

    def test_redacts_secret_lines(self) -> None:
        text = "OPENAI_API_KEY=plain-secret-value\nSERVICE_TOKEN=plain-token-value"
        redacted = redact_secrets(text)
        self.assertNotIn("plain-secret-value", redacted)
        self.assertNotIn("plain-token-value", redacted)

    def test_cli_creates_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                (root / "templates").mkdir()
                source = old_cwd / "templates" / "coding-bot.toml"
                (root / "templates" / "coding-bot.toml").write_text(
                    source.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                self.assertEqual(
                    0, cli_main(["bot", "create", "coder", "--template", "coding-bot"])
                )
                self.assertTrue((root / ".zeus" / "hermes" / "profiles" / "coder").exists())
            finally:
                os.chdir(old_cwd)

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
                self.assertEqual({"status": "ok"}, json.loads(response.read()))

                conn.request("GET", "/bots")
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                response.read()

                conn.request(
                    "POST", "/bots", body=b"{}", headers={"content-type": "application/json"}
                )
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                response.read()

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
                response.read()

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
                response.read()

                conn.request("GET", "/doctor")
                response = conn.getresponse()
                self.assertEqual(401, response.status)
                response.read()

                conn.request("GET", "/doctor", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                doctor = json.loads(response.read())
                self.assertIn("checks", doctor)

                conn.request("GET", "/bots/Bad/status", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(400, response.status)
                response.read()

                conn.request("POST", "/bots/reconcile", headers={"x-zeus-api-key": "secret"})
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                reconciled = json.loads(response.read())
                self.assertEqual("coder", reconciled[0]["bot_id"])
            finally:
                server.shutdown()
                server.server_close()

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
                self.assertIn("ZEUS_API_KEY", body["error"])

                conn.request(
                    "POST",
                    "/bots",
                    body=b"{}",
                    headers={"content-type": "application/json", "x-zeus-api-key": "anything"},
                )
                response = conn.getresponse()
                self.assertEqual(503, response.status)
                body = json.loads(response.read())
                self.assertIn("ZEUS_API_KEY", body["error"])
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
