from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from unittest import mock

from tests.test_api import api_server, request_json
from zeus.api_logging import ApiLogWriter
from zeus.api_server import ThreadingHTTPServer
from zeus.audit_runner import AuditRunnerError, _validate_hermes_executable
from zeus.audit_workspace_core import (
    _MAX_RELATIVE_PATH_COMPONENTS,
    AuditWorkspaceError,
    _validate_relative_path_text,
)
from zeus.gateway_runtime_core import _GatewayRuntimeCore
from zeus.hermes_adapter import HermesAdapter
from zeus.hermes_profile_environment import (
    HermesProfileEnvironmentError,
    load_hermes_profile_environment,
)
from zeus.logging_utils import tail_file
from zeus.models import TemplateError, validate_id
from zeus.sanitization import sanitize_text
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class ProfileEnvBlocklistTests(unittest.TestCase):
    """Regression: profile .env must never steer executable/interpreter lookup."""

    def _write_profile_env(self, root: Path, text: str) -> Path:
        profile = root / "profiles" / "coder"
        profile.mkdir(parents=True)
        env_path = profile / ".env"
        env_path.write_text(text, encoding="utf-8")
        os.chmod(env_path, 0o600)
        return env_path

    def test_secret_keys_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = self._write_profile_env(
                Path(tmp), "OPENROUTER_API_KEY=abc123\nTELEGRAM_BOT_TOKEN=x:y\n"
            )
            values = load_hermes_profile_environment(env_path)
            self.assertEqual("abc123", values["OPENROUTER_API_KEY"])
            self.assertEqual("x:y", values["TELEGRAM_BOT_TOKEN"])

    def test_path_assignment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = self._write_profile_env(Path(tmp), "PATH=/tmp/pwn\n")
            with self.assertRaises(HermesProfileEnvironmentError):
                load_hermes_profile_environment(env_path)

    def test_dynamic_linker_and_interpreter_keys_are_rejected(self) -> None:
        blocked_assignments = [
            "LD_PRELOAD=/tmp/evil.so",
            "LD_LIBRARY_PATH=/tmp",
            "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
            "PYTHONPATH=/tmp",
            "PYTHONHOME=/tmp",
            "GIT_SSH_COMMAND=/tmp/x",
            "HOME=/tmp",
            "SSL_CERT_FILE=/tmp/ca.pem",
            "REQUESTS_CA_BUNDLE=/tmp/ca.pem",
            "BASH_ENV=/tmp/x",
        ]
        for assignment in blocked_assignments:
            with self.subTest(assignment=assignment), tempfile.TemporaryDirectory() as tmp:
                env_path = self._write_profile_env(Path(tmp), f"{assignment}\n")
                with self.assertRaises(HermesProfileEnvironmentError):
                    load_hermes_profile_environment(env_path)

    def test_quoted_and_exported_blocked_keys_are_rejected(self) -> None:
        for line in ('"PATH"=/tmp/pwn', "export PATH=/tmp/pwn", "'PATH'=/tmp/pwn"):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as tmp:
                env_path = self._write_profile_env(Path(tmp), f"{line}\n")
                with self.assertRaises(HermesProfileEnvironmentError):
                    load_hermes_profile_environment(env_path)

    def test_relative_hermes_bin_ignores_profile_path_entry(self) -> None:
        """Even if a PATH entry arrives via passthrough env, resolution uses base env."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good_bin = root / "good"
            good_bin.mkdir()
            hermes = good_bin / "hermes"
            hermes.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            hermes.chmod(0o755)
            adapter = HermesAdapter("hermes", root / "profiles-root")
            with mock.patch.dict(os.environ, {"PATH": str(good_bin)}, clear=True):
                resolved = adapter._resolved_hermes_bin({"PATH": "/nonexistent"})
            self.assertEqual(str(hermes.resolve()), resolved)


class LauncherEnvironmentTests(unittest.TestCase):
    def test_launch_payload_env_is_minimal(self) -> None:
        from zeus.gateway_runtime_launch import _launcher_subprocess_env

        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin:/bin",
                "HOME": "/home/test",
                "ZEUS_API_KEY": "very-secret",
                "AWS_SECRET_ACCESS_KEY": "also-secret",
                "PYTHONPATH": "/tmp/injected",
            },
            clear=True,
        ):
            env = _launcher_subprocess_env()
        self.assertNotIn("ZEUS_API_KEY", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("PYTHONPATH", env)
        self.assertEqual("/usr/bin:/bin", env["PATH"])
        self.assertEqual("/home/test", env["HOME"])


class ApiKeyEncodingTests(unittest.TestCase):
    def test_non_ascii_api_key_returns_401_not_500(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            status, body = request_json(
                port,
                "GET",
                "/bots",
                headers={"x-zeus-api-key": "clé"},
            )
            self.assertEqual(401, status)
            self.assertEqual("invalid_api_key", body["error"]["code"])

    def test_non_ascii_api_key_consumes_auth_failure_budget(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret"}) as port:
            for _ in range(20):
                status, body = request_json(
                    port,
                    "GET",
                    "/bots",
                    headers={"x-zeus-api-key": "kéy"},
                )
            self.assertEqual(429, status)
            self.assertEqual("auth_rate_limited", body["error"]["code"])


class UnknownBotLockHygieneTests(unittest.TestCase):
    """Requests for nonexistent bots must not create lock state (disk/memory DoS)."""

    def _make_supervisor(self, root: Path) -> Supervisor:
        store = StateStore(root / "zeus.db")
        store.init()
        return Supervisor(store, "hermes", root / "hermes")

    def test_status_unknown_bot_creates_no_lock_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supervisor = self._make_supervisor(root)
            with self.assertRaises(KeyError):
                supervisor.status("missing")
            self.assertEqual({}, supervisor._bot_locks)
            self.assertFalse((root / "locks" / "bots" / "missing.lock").exists())

    def test_logs_unknown_bot_creates_no_lock_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supervisor = self._make_supervisor(root)
            with self.assertRaises(KeyError):
                supervisor.logs("missing")
            self.assertEqual({}, supervisor._bot_locks)

    def test_status_invalid_id_still_rejected_before_any_io(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supervisor = self._make_supervisor(root)
            with self.assertRaises(TemplateError):
                supervisor.status("../../bad")
            self.assertEqual({}, supervisor._bot_locks)


class PerClientConnectionLimitTests(unittest.TestCase):
    def test_second_connection_from_same_client_is_limited(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class LimitedHandler(BaseHTTPRequestHandler):
            api_max_concurrent_requests = 8
            api_max_connections_per_client = 1
            api_request_timeout_seconds = 2.0

            def do_GET(self) -> None:
                entered.set()
                release.wait(timeout=3)
                data = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), LimitedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            first = socket.create_connection(("127.0.0.1", server.server_port), timeout=3)
            try:
                first.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                self.assertTrue(entered.wait(timeout=2))
                second = socket.create_connection(("127.0.0.1", server.server_port), timeout=3)
                try:
                    second.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                    second.settimeout(3)
                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = second.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    self.assertIn(b"503", response.split(b"\r\n", 1)[0])
                    self.assertIn(b"client_connection_limited", response)
                finally:
                    second.close()
            finally:
                release.set()
                first.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class ApiLogRotationTests(unittest.TestCase):
    def test_log_rotates_instead_of_growing_unbounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # resolve(): private-IO rejects paths through symlinked components
            # (macOS /var -> /private/var).
            log_path = Path(tmp).resolve() / "logs" / "api.jsonl"
            log_path.parent.mkdir(parents=True)
            writer = ApiLogWriter(log_path, enabled=True)
            with mock.patch("zeus.api_logging.MAX_API_LOG_BYTES", 2048):
                for _ in range(40):
                    writer.error("a" * 32, ValueError("boom"))
            rotated = log_path.with_name("api.jsonl.1")
            self.assertTrue(rotated.exists())
            self.assertLessEqual(log_path.stat().st_size, 2048 + 512)
            self.assertGreater(rotated.stat().st_size, 0)

    def test_small_log_is_not_rotated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp).resolve() / "logs" / "api.jsonl"
            log_path.parent.mkdir(parents=True)
            writer = ApiLogWriter(log_path, enabled=True)
            writer.error("b" * 32, ValueError("boom"))
            self.assertFalse(log_path.with_name("api.jsonl.1").exists())


class ControlCharacterSanitizationTests(unittest.TestCase):
    def test_sanitize_text_escapes_terminal_controls(self) -> None:
        payload = "ok\n\x1b]8;;https://evil.example\x07click\x1b]8;;\x07\x00\x9b done"
        result = sanitize_text(payload)
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\x00", result)
        self.assertNotIn("\x9b", result)
        self.assertIn("\\u001b", result)
        self.assertIn("\\u009b", result)
        self.assertIn("ok\n", result)

    def test_tail_file_escapes_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from zeus.private_io import nofollow_absolute_path, open_private_append

            log_path = Path(tmp).resolve() / "gateway.log"
            with open_private_append(nofollow_absolute_path(log_path)) as handle:
                handle.write(b"line one\n\x1b[2J\x1b[31mred\x1b[0m\n")
            text = tail_file(log_path)
            self.assertNotIn("\x1b", text)
            self.assertIn("\\u001b[2J", text)
            self.assertIn("line one\n", text)


class IdAndPathValidationTests(unittest.TestCase):
    def test_validate_id_rejects_trailing_newline(self) -> None:
        with self.assertRaises(TemplateError):
            validate_id("ab\n", "bot_id")

    def test_adapter_command_rejects_trailing_newline(self) -> None:
        adapter = HermesAdapter("hermes", Path("/nonexistent-root"))
        with self.assertRaises(ValueError):
            adapter.command("ab\n", "gateway", "run")

    def test_workspace_paths_reject_control_characters(self) -> None:
        with self.assertRaises(AuditWorkspaceError):
            _validate_relative_path_text("a/\x1b[2J/b", "tree path")

    def test_workspace_paths_reject_excessive_depth(self) -> None:
        deep = "/".join(["dir"] * _MAX_RELATIVE_PATH_COMPONENTS) + "/file.txt"
        with self.assertRaises(AuditWorkspaceError):
            _validate_relative_path_text(deep, "tree path")
        shallow = "/".join(["dir"] * (_MAX_RELATIVE_PATH_COMPONENTS - 1)) + "/file.txt"
        self.assertEqual(shallow, _validate_relative_path_text(shallow, "tree path"))


class HermesExecutableOwnershipTests(unittest.TestCase):
    def _fake_executable(self, root: Path) -> Path:
        path = root / "hermes"
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_executable_owned_by_euid_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._fake_executable(Path(tmp))
            self.assertEqual(path, _validate_hermes_executable(path))

    def test_executable_owned_by_another_user_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._fake_executable(Path(tmp))
            with (
                mock.patch("zeus.audit_runner.os.geteuid", return_value=os.geteuid() + 1),
                self.assertRaises(AuditRunnerError),
            ):
                _validate_hermes_executable(path)


class ProcessGroupGuardTests(unittest.TestCase):
    """killpg must not fire when the pid's pgid no longer matches (pid reissue)."""

    def _core(self) -> _GatewayRuntimeCore:
        return _GatewayRuntimeCore(
            store=None,  # type: ignore[arg-type]
            stop_grace_seconds=0.1,
            kill_after_timeout=False,
            lock_timeout_seconds=1.0,
            readiness_timeout_seconds=1.0,
            readiness_interval_seconds=0.05,
            allow_legacy_pid_markers=False,
        )

    def test_group_reissue_is_detected(self) -> None:
        # The current process is not a process-group leader, so pgid != pid.
        fake_process = mock.Mock()
        fake_process.pid = os.getpid()
        self.assertTrue(_GatewayRuntimeCore._spawned_group_reissued(fake_process, "killpg", []))

    def test_own_session_child_is_not_flagged_as_reissued(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            start_new_session=True,
        )
        try:
            fake_process = mock.Mock()
            fake_process.pid = child.pid
            self.assertFalse(
                _GatewayRuntimeCore._spawned_group_reissued(fake_process, "killpg", [])
            )
        finally:
            child.kill()
            child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
