from __future__ import annotations

import errno
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from zeus import audit_runner
from zeus.audit_config import parse_audit_config
from zeus.audit_runner import (
    AuditRunner,
    AuditRunnerError,
    AuditRunnerOutcome,
)

PROFILE = "audit-" + "1" * 32
PROMPT = "Return one bounded JSON object."
PROVIDER = "test-provider"
MODEL = "test-model"
SECRET = "very-secret-provider-value"


def _deadline(seconds: float = 5.0) -> float:
    return time.monotonic() + seconds


class _BrokerHarness:
    def __init__(
        self,
        *,
        breach_after: int | None = None,
        cleanup_returncode: int = 0,
        cleanup_interrupts: int = 0,
    ) -> None:
        self.breach_after = breach_after
        self.cleanup_returncode = cleanup_returncode
        self.cleanup_interrupts = cleanup_interrupts
        self.reads = 0
        self.cleanup_paths: list[Path] = []

    def read(self, state_path: Path) -> SimpleNamespace:
        self.reads += 1
        breached = self.breach_after is not None and self.reads >= self.breach_after
        return SimpleNamespace(
            limit_breach=breached,
            breach_reason="terminal output limit" if breached else None,
            phase="breached" if breached else "closed",
            cleanup_state="complete",
        )

    def cleanup(self, state_path: Path) -> SimpleNamespace:
        self.cleanup_paths.append(state_path)
        if self.cleanup_interrupts:
            self.cleanup_interrupts -= 1
            raise KeyboardInterrupt
        return SimpleNamespace(
            returncode=self.cleanup_returncode,
            stdout=b"",
            stderr=b"cleanup failed\n" if self.cleanup_returncode else b"",
        )


class _InterruptingCloseStream:
    def __init__(self, stream) -> None:
        self._stream = stream
        self._interrupted = False

    def fileno(self) -> int:
        return self._stream.fileno()

    def close(self) -> None:
        if not self._interrupted:
            self._interrupted = True
            raise KeyboardInterrupt
        self._stream.close()


class _ProcessWithInterruptingClose:
    def __init__(self, process) -> None:
        self._process = process
        self.stdout = _InterruptingCloseStream(process.stdout)
        self.stderr = process.stderr

    def __getattr__(self, name: str):
        return getattr(self._process, name)


class AuditRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.control_dir = self.root / "control"
        self.control_dir.mkdir(mode=0o700)
        for name in ("home", "hermes", "launch", "broker"):
            (self.control_dir / name).mkdir(mode=0o700)
        self.broker_executable = self.control_dir / "broker" / "docker"
        self.broker_executable.write_text("#!/bin/sh\nexit 126\n", encoding="utf-8")
        self.broker_executable.chmod(0o500)
        self.broker_state_path = self.control_dir / "broker" / "state.json"
        self.broker_state_path.write_text("{}\n", encoding="utf-8")
        self.broker_state_path.chmod(0o600)
        self.capture_path = self.root / "capture.json"
        self.hermes_executable = self.root / "hermes"
        self.hermes_executable.write_text(
            f"""#!{sys.executable}
import json
import os
import signal
import sys
import time
from pathlib import Path

capture = Path(os.environ["TEST_PROVIDER_KEY"])
mode = os.environ["TEST_MODE"]
if mode in {{"ignore-term", "close-output-sleep"}}:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
capture.write_text(
    json.dumps(
        {{
            "argv": sys.argv,
            "cwd": os.getcwd(),
            "cwd_entries": sorted(os.listdir(".")),
            "env": dict(os.environ),
            "pid": os.getpid(),
        }},
        sort_keys=True,
    ),
    encoding="utf-8",
)
if mode == "normal":
    os.write(1, b'{{"summary":"ok"}}')
elif mode == "dual-output":
    os.write(2, b"e" * (200 * 1024))
    os.write(1, b'{{"summary":"ok"}}')
elif mode == "stdout-limit":
    os.write(1, b"x" * (1024 * 1024 + 1))
elif mode == "stderr-limit":
    os.write(2, b"x" * (256 * 1024 + 1))
elif mode == "invalid":
    os.write(2, ("API_KEY=" + os.environ["TEST_SECRET"]).encode())
    os.write(1, b"not-json")
elif mode == "failure":
    os.write(2, ("Bearer " + os.environ["TEST_SECRET"]).encode())
    raise SystemExit(7)
elif mode == "ignore-term":
    while True:
        time.sleep(1)
elif mode == "close-output-sleep":
    os.close(1)
    os.close(2)
    while True:
        time.sleep(1)
else:
    raise RuntimeError("unknown mode")
""",
            encoding="utf-8",
        )
        self.hermes_executable.chmod(0o700)
        self.source_env = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C",
            "SSL_CERT_FILE": "/etc/ssl/cert.pem",
            "TEST_PROVIDER_KEY": str(self.capture_path),
            "TEST_MODE": "normal",
            "TEST_SECRET": SECRET,
            "HERMES_DOCKER_BINARY": "/untrusted/docker",
            "DOCKER_HOST": "tcp://untrusted.invalid",
            "TERMINAL_BACKEND": "local",
            "GIT_DIR": "/untrusted/git",
            "SSH_AUTH_SOCK": "/untrusted/agent",
            "GITHUB_TOKEN": "untrusted",
            "AWS_SECRET_ACCESS_KEY": "untrusted",
            "NPM_TOKEN": "untrusted",
            "HTTP_PROXY": "http://untrusted.invalid",
            "NO_PROXY": "*",
            "OPENAI_API_KEY": "not-selected",
        }
        self.config = parse_audit_config(
            {
                "schema_version": 1,
                "provider": PROVIDER,
                "model": MODEL,
                "provider_env": [
                    "TEST_PROVIDER_KEY",
                    "TEST_MODE",
                    "TEST_SECRET",
                ],
            }
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @staticmethod
    def _validate(data: bytes) -> object:
        return json.loads(data.decode("utf-8", errors="strict"))

    def _run(
        self,
        *,
        broker: _BrokerHarness | None = None,
        cancel_event: threading.Event | None = None,
        deadline: float | None = None,
        config=None,
    ):
        active_broker = _BrokerHarness() if broker is None else broker
        runner = AuditRunner(
            self.hermes_executable,
            broker_state_reader=active_broker.read,
            broker_cleanup=active_broker.cleanup,
        )
        result = runner.run(
            profile_name=PROFILE,
            prompt=PROMPT,
            config=self.config if config is None else config,
            control_dir=self.control_dir,
            broker_executable=self.broker_executable,
            broker_state_path=self.broker_state_path,
            deadline=_deadline() if deadline is None else deadline,
            source_env=self.source_env,
            validate_output=self._validate,
            cancel_event=cancel_event,
        )
        return result, active_broker

    def test_exact_single_query_argv_private_cwd_and_minimal_environment(self) -> None:
        original_popen = subprocess.Popen
        launches: list[tuple[tuple[object, ...], dict[str, object]]] = []

        def launch(*args: object, **kwargs: object):
            launches.append((args, kwargs))
            return original_popen(*args, **kwargs)

        with mock.patch("zeus.audit_runner.subprocess.Popen", side_effect=launch):
            result, broker = self._run()

        self.assertEqual(AuditRunnerOutcome.completed, result.outcome)
        self.assertEqual({"summary": "ok"}, result.model_result)
        self.assertIsNone(result.diagnostic)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)
        self.assertEqual(1, len(launches))
        arguments, options = launches[0]
        self.assertEqual(
            (
                [
                    str(self.hermes_executable),
                    "-p",
                    PROFILE,
                    "chat",
                    "-q",
                    PROMPT,
                    "--quiet",
                    "--ignore-rules",
                    "--max-turns",
                    "80",
                    "-t",
                    "terminal",
                    "--provider",
                    PROVIDER,
                    "-m",
                    MODEL,
                ],
            ),
            arguments,
        )
        self.assertIs(subprocess.DEVNULL, options["stdin"])
        self.assertIs(subprocess.PIPE, options["stdout"])
        self.assertIs(subprocess.PIPE, options["stderr"])
        self.assertFalse(options["shell"])
        self.assertTrue(options["start_new_session"])
        self.assertTrue(options["close_fds"])

        captured = json.loads(self.capture_path.read_text(encoding="utf-8"))
        self.assertEqual(str(self.control_dir / "launch"), captured["cwd"])
        self.assertEqual([], captured["cwd_entries"])
        expected_environment = {
            "HOME": str(self.control_dir / "home"),
            "HERMES_HOME": str(self.control_dir / "hermes"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C",
            "PATH": f"{self.control_dir / 'broker'}:/usr/bin:/bin",
            "SSL_CERT_FILE": "/etc/ssl/cert.pem",
            "TEST_MODE": "normal",
            "TEST_PROVIDER_KEY": str(self.capture_path),
            "TEST_SECRET": SECRET,
        }
        self.assertEqual(expected_environment, options["env"])
        self.assertEqual(
            expected_environment,
            {
                name: value
                for name, value in captured["env"].items()
                if name in expected_environment
            },
        )
        for forbidden in (
            "HERMES_DOCKER_BINARY",
            "DOCKER_HOST",
            "TERMINAL_BACKEND",
            "GIT_DIR",
            "SSH_AUTH_SOCK",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "NPM_TOKEN",
            "HTTP_PROXY",
            "NO_PROXY",
            "OPENAI_API_KEY",
        ):
            self.assertNotIn(forbidden, captured["env"])

    def test_stdout_and_stderr_are_drained_independently_with_exact_hard_caps(self) -> None:
        self.source_env["TEST_MODE"] = "dual-output"
        result, _broker = self._run()
        self.assertEqual(AuditRunnerOutcome.completed, result.outcome)

        self.source_env["TEST_MODE"] = "stdout-limit"
        result, _broker = self._run()
        self.assertEqual(AuditRunnerOutcome.model_output_limit, result.outcome)
        self.assertIsNone(result.model_result)

        self.source_env["TEST_MODE"] = "stderr-limit"
        result, _broker = self._run()
        self.assertEqual(AuditRunnerOutcome.stderr_output_limit, result.outcome)
        self.assertIsNone(result.model_result)

    def test_timeout_terminates_the_owned_process_group_and_cleans_broker(self) -> None:
        self.source_env["TEST_MODE"] = "ignore-term"
        with mock.patch("zeus.audit_runner.os.killpg", wraps=os.killpg) as kill_group:
            result, broker = self._run(deadline=_deadline(0.5))

        self.assertEqual(AuditRunnerOutcome.timed_out, result.outcome)
        signals = [call.args[1] for call in kill_group.call_args_list]
        self.assertIn(signal.SIGTERM, signals)
        self.assertIn(signal.SIGKILL, signals)
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)
        pid = json.loads(self.capture_path.read_text(encoding="utf-8"))["pid"]
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

        self.source_env["TEST_MODE"] = "close-output-sleep"
        result, broker = self._run(deadline=_deadline(0.5))
        self.assertEqual(AuditRunnerOutcome.timed_out, result.outcome)
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)

    def test_cancellation_and_keyboard_interrupt_are_classified_and_cleaned(self) -> None:
        self.source_env["TEST_MODE"] = "ignore-term"
        cancelled = threading.Event()
        timer = threading.Timer(0.1, cancelled.set)
        timer.start()
        try:
            result, broker = self._run(cancel_event=cancelled)
        finally:
            timer.cancel()
        self.assertEqual(AuditRunnerOutcome.cancelled, result.outcome)
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)

        with mock.patch.object(
            selectors.DefaultSelector,
            "select",
            side_effect=KeyboardInterrupt,
        ):
            result, broker = self._run()
        self.assertEqual(AuditRunnerOutcome.cancelled, result.outcome)
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)

    def test_broker_breach_terminates_hermes_and_cleans_only_sealed_state(self) -> None:
        self.source_env["TEST_MODE"] = "ignore-term"
        broker = _BrokerHarness(breach_after=2)
        result, active_broker = self._run(broker=broker)

        self.assertEqual(AuditRunnerOutcome.broker_breach, result.outcome)
        self.assertIn("terminal output limit", result.diagnostic or "")
        self.assertEqual([self.broker_state_path], active_broker.cleanup_paths)

    def test_nonzero_and_invalid_output_diagnostics_are_bounded_and_redacted(self) -> None:
        self.source_env["TEST_MODE"] = "failure"
        failed, _broker = self._run()
        self.assertEqual(AuditRunnerOutcome.process_failed, failed.outcome)
        self.assertEqual(7, failed.returncode)
        self.assertNotIn(SECRET, failed.diagnostic or "")
        self.assertIn("[redacted]", failed.diagnostic or "")

        self.source_env["TEST_MODE"] = "invalid"
        invalid, _broker = self._run()
        self.assertEqual(AuditRunnerOutcome.invalid_output, invalid.outcome)
        self.assertIsNone(invalid.model_result)
        self.assertNotIn(SECRET, invalid.diagnostic or "")
        self.assertIn("[redacted]", invalid.diagnostic or "")
        self.assertLessEqual(len((invalid.diagnostic or "").encode("utf-8")), 4096)
        result_fields = {field.name for field in fields(invalid)}
        self.assertNotIn("stdout", result_fields)
        self.assertNotIn("stderr", result_fields)
        self.assertNotIn("raw_output", result_fields)

    def test_cleanup_failure_is_explicit_without_discarding_validated_result(self) -> None:
        broker = _BrokerHarness(cleanup_returncode=126)
        result, _broker = self._run(broker=broker)

        self.assertEqual(AuditRunnerOutcome.cleanup_failed, result.outcome)
        self.assertEqual({"summary": "ok"}, result.model_result)
        self.assertFalse(result.cleanup_complete)

    def test_unsafe_or_nonempty_launch_directory_fails_before_process_start(self) -> None:
        (self.control_dir / "launch" / "unexpected").write_text(
            "state",
            encoding="utf-8",
        )
        broker = _BrokerHarness()
        runner = AuditRunner(
            self.hermes_executable,
            broker_state_reader=broker.read,
            broker_cleanup=broker.cleanup,
        )
        with (
            mock.patch("zeus.audit_runner.subprocess.Popen") as popen,
            self.assertRaisesRegex(AuditRunnerError, "launch directory"),
        ):
            runner.run(
                profile_name=PROFILE,
                prompt=PROMPT,
                config=self.config,
                control_dir=self.control_dir,
                broker_executable=self.broker_executable,
                broker_state_path=self.broker_state_path,
                deadline=_deadline(),
                source_env=self.source_env,
                validate_output=self._validate,
            )
        popen.assert_not_called()
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)

        (self.control_dir / "launch" / "unexpected").unlink()
        (self.control_dir / "launch").chmod(0o755)
        with self.assertRaises(AuditRunnerError):
            runner.run(
                profile_name=PROFILE,
                prompt=PROMPT,
                config=self.config,
                control_dir=self.control_dir,
                broker_executable=self.broker_executable,
                broker_state_path=self.broker_state_path,
                deadline=_deadline(),
                source_env=self.source_env,
                validate_output=self._validate,
            )
        self.assertEqual(0o755, stat.S_IMODE((self.control_dir / "launch").stat().st_mode))

    def test_provider_value_limit_is_enforced_before_launch_and_cleanup_still_runs(self) -> None:
        config = replace(
            self.config,
            limits=replace(self.config.limits, provider_value_bytes=8),
        )
        broker = _BrokerHarness()
        runner = AuditRunner(
            self.hermes_executable,
            broker_state_reader=broker.read,
            broker_cleanup=broker.cleanup,
        )
        with (
            mock.patch("zeus.audit_runner.subprocess.Popen") as popen,
            self.assertRaisesRegex(AuditRunnerError, "provider environment"),
        ):
            runner.run(
                profile_name=PROFILE,
                prompt=PROMPT,
                config=config,
                control_dir=self.control_dir,
                broker_executable=self.broker_executable,
                broker_state_path=self.broker_state_path,
                deadline=_deadline(),
                source_env=self.source_env,
                validate_output=self._validate,
            )
        popen.assert_not_called()
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)

        unsafe_config = replace(self.config, provider_env=("DOCKER_HOST",))
        original_popen = subprocess.Popen

        def launch(*args: object, **kwargs: object):
            return original_popen(*args, **kwargs)

        with (
            mock.patch("zeus.audit_runner.subprocess.Popen", side_effect=launch) as popen,
            self.assertRaisesRegex(AuditRunnerError, "provider environment"),
        ):
            runner.run(
                profile_name=PROFILE,
                prompt=PROMPT,
                config=unsafe_config,
                control_dir=self.control_dir,
                broker_executable=self.broker_executable,
                broker_state_path=self.broker_state_path,
                deadline=_deadline(),
                source_env=self.source_env,
                validate_output=self._validate,
            )
        popen.assert_not_called()

    def test_path_separator_control_path_is_rejected_before_fallback_docker_resolution(
        self,
    ) -> None:
        fallback_root = self.root / "fallback"
        fallback_broker = fallback_root / "control" / "broker"
        fallback_broker.mkdir(parents=True, mode=0o700)
        fallback_docker = fallback_broker / "docker"
        fallback_docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fallback_docker.chmod(0o500)
        unsafe_control = self.root / f"trusted{os.pathsep}{fallback_root}" / "control"
        unsafe_control.mkdir(parents=True, mode=0o700)
        for name in ("home", "hermes", "launch", "broker"):
            (unsafe_control / name).mkdir(mode=0o700)
        unsafe_broker = unsafe_control / "broker" / "docker"
        unsafe_broker.write_text("#!/bin/sh\nexit 126\n", encoding="utf-8")
        unsafe_broker.chmod(0o500)
        unsafe_state = unsafe_control / "broker" / "state.json"
        unsafe_state.write_text("{}\n", encoding="utf-8")
        unsafe_state.chmod(0o600)
        split_path = f"{unsafe_control / 'broker'}{os.pathsep}/usr/bin:/bin"
        self.assertEqual(str(fallback_docker), shutil.which("docker", path=split_path))

        broker = _BrokerHarness()
        runner = AuditRunner(
            self.hermes_executable,
            broker_state_reader=broker.read,
            broker_cleanup=broker.cleanup,
        )
        original_popen = subprocess.Popen

        def launch(*args: object, **kwargs: object):
            return original_popen(*args, **kwargs)

        with (
            mock.patch("zeus.audit_runner.subprocess.Popen", side_effect=launch) as popen,
            self.assertRaisesRegex(AuditRunnerError, "path separator"),
        ):
            runner.run(
                profile_name=PROFILE,
                prompt=PROMPT,
                config=self.config,
                control_dir=unsafe_control,
                broker_executable=unsafe_broker,
                broker_state_path=unsafe_state,
                deadline=_deadline(),
                source_env=self.source_env,
                validate_output=self._validate,
            )
        self.assertEqual(0, popen.call_count)
        self.assertEqual([unsafe_state], broker.cleanup_paths)

        colon_hermes = self.root / f"hermes{os.pathsep}unsafe"
        colon_hermes.write_bytes(self.hermes_executable.read_bytes())
        colon_hermes.chmod(0o700)
        with self.assertRaisesRegex(AuditRunnerError, "path separator"):
            AuditRunner(colon_hermes)

    def test_teardown_interrupts_are_cancelled_without_skipping_broker_cleanup(self) -> None:
        broker = _BrokerHarness()
        with mock.patch(
            "zeus.audit_runner._stop_process_group",
            side_effect=(KeyboardInterrupt, True),
        ) as stop_group:
            try:
                result, active_broker = self._run(broker=broker)
            except KeyboardInterrupt:
                self.fail("process-group teardown interrupt skipped broker cleanup")
        self.assertEqual(AuditRunnerOutcome.cancelled, result.outcome)
        self.assertTrue(result.cleanup_complete)
        self.assertTrue(result.process_group_stopped)
        self.assertEqual(2, stop_group.call_count)
        self.assertEqual([self.broker_state_path], active_broker.cleanup_paths)

        original_popen = subprocess.Popen

        def launch(*args: object, **kwargs: object):
            return _ProcessWithInterruptingClose(original_popen(*args, **kwargs))

        with mock.patch("zeus.audit_runner.subprocess.Popen", side_effect=launch):
            try:
                result, active_broker = self._run()
            except KeyboardInterrupt:
                self.fail("stream-close interrupt skipped broker cleanup")
        self.assertEqual(AuditRunnerOutcome.cancelled, result.outcome)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual([self.broker_state_path], active_broker.cleanup_paths)

        broker = _BrokerHarness(cleanup_interrupts=1)
        result, active_broker = self._run(broker=broker)
        self.assertEqual(AuditRunnerOutcome.cancelled, result.outcome)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(
            [self.broker_state_path, self.broker_state_path],
            active_broker.cleanup_paths,
        )

    def test_process_group_status_distinguishes_eperm_and_rechecks_after_kill(self) -> None:
        process = SimpleNamespace(
            pid=424242,
            poll=lambda: 0,
            wait=mock.Mock(),
        )
        permission_denied = PermissionError(errno.EPERM, "not permitted")
        with mock.patch("zeus.audit_runner.os.killpg", side_effect=permission_denied):
            self.assertFalse(audit_runner._stop_process_group(process))

        signals: list[int] = []

        def surviving_group(_group_id: int, sent_signal: int) -> None:
            signals.append(sent_signal)

        with (
            mock.patch("zeus.audit_runner.os.killpg", side_effect=surviving_group),
            mock.patch("zeus.audit_runner._TERM_GRACE_SECONDS", 0),
        ):
            self.assertFalse(audit_runner._stop_process_group(process))
        kill_index = signals.index(signal.SIGKILL)
        self.assertIn(0, signals[kill_index + 1 :])

    def test_completed_result_requires_verified_process_and_broker_cleanup(self) -> None:
        with mock.patch(
            "zeus.audit_runner._stop_process_group",
            return_value=False,
        ):
            result, broker = self._run()

        self.assertEqual(AuditRunnerOutcome.cleanup_failed, result.outcome)
        self.assertFalse(result.cleanup_complete)
        self.assertFalse(result.process_group_stopped)
        self.assertEqual([self.broker_state_path], broker.cleanup_paths)


if __name__ == "__main__":
    unittest.main()
