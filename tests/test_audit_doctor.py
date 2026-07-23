from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


class AuditDoctorContractTests(unittest.TestCase):
    def test_doctor_report_has_machine_and_human_rendering(self) -> None:
        from zeus.audit_doctor import AuditDoctorReport

        report = AuditDoctorReport(checks=())
        self.assertEqual("", report.to_text())
        self.assertEqual({"checks": [], "ok": True}, report.to_dict())

    def _version_executable(self, root: Path, output: bytes, *, sleep: float = 0) -> Path:
        executable = root / "hermes"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import time\n"
            f"os.write(1, {output!r})\n"
            f"time.sleep({sleep!r})\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)
        return executable

    def _forking_executable(
        self,
        root: Path,
        output: bytes,
        *,
        parent_sleep: float = 0,
    ) -> tuple[Path, Path]:
        executable = root / "forking-tool"
        marker = root / "descendant.txt"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import signal\n"
            "import time\n"
            f"marker = {str(marker)!r}\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.close(1)\n"
            "    os.close(2)\n"
            "    while True:\n"
            "        time.sleep(1)\n"
            "descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
            "try:\n"
            "    os.write(descriptor, f'{os.getpgrp()} {child}\\n'.encode())\n"
            "    os.fsync(descriptor)\n"
            "finally:\n"
            "    os.close(descriptor)\n"
            f"os.write(1, {output!r})\n"
            f"time.sleep({parent_sleep!r})\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)
        return executable, marker

    def _descendant(self, marker: Path) -> tuple[int, int]:
        process_group, child = marker.read_text(encoding="utf-8").split()
        return int(process_group), int(child)

    def _process_group_exists(self, process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        return True

    def _process_exists(self, process_id: int) -> bool:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return False
        return True

    def _cleanup_descendant(self, marker: Path) -> None:
        if not marker.exists():
            return
        process_group, child = self._descendant(marker)
        if process_group != os.getpgrp():
            with suppress(ProcessLookupError):
                os.killpg(process_group, signal.SIGKILL)
        else:
            with suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)

    def test_pinned_hermes_version_requires_documented_first_line_shape(self) -> None:
        from zeus.audit_doctor import _pinned_hermes_version

        accepted = b"Hermes Agent v0.19.0 (2026.7.20)\nPython: 3.11.13\nPlatform: test\n"
        rejected = (
            b"0.19.0\n",
            b"Hermes Agent v0.19.0\n",
            b"prefix Hermes Agent v0.19.0 (2026.7.20)\n",
            b"Hermes Agent v0.18.0 (2026.7.20)\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertTrue(
                _pinned_hermes_version(
                    self._version_executable(root, accepted),
                    deadline=time.monotonic() + 2,
                )[0]
            )
            for index, output in enumerate(rejected):
                with self.subTest(output=output):
                    self.assertFalse(
                        _pinned_hermes_version(
                            self._version_executable(root, output),
                            deadline=time.monotonic() + 2 + index,
                        )[0]
                    )

    def test_pinned_hermes_version_bounds_output_and_terminates_process_group(self) -> None:
        from zeus.audit_doctor import _pinned_hermes_version

        with tempfile.TemporaryDirectory() as temporary:
            executable = self._version_executable(
                Path(temporary),
                b"Hermes Agent v0.19.0 (2026.7.20)\n" + b"x" * 8192,
                sleep=5,
            )
            started = time.monotonic()
            with mock.patch("zeus.audit_doctor.os.killpg", wraps=os.killpg) as killpg:
                ok, observation = _pinned_hermes_version(
                    executable,
                    deadline=time.monotonic() + 2,
                )
            self.assertFalse(ok)
            self.assertIn("limit", observation)
            self.assertLess(time.monotonic() - started, 2)
            self.assertIn(signal.SIGTERM, [call.args[1] for call in killpg.call_args_list])

    def test_pinned_hermes_version_honors_the_overall_deadline(self) -> None:
        from zeus.audit_doctor import _pinned_hermes_version

        with tempfile.TemporaryDirectory() as temporary:
            executable = self._version_executable(Path(temporary), b"", sleep=5)
            started = time.monotonic()
            with mock.patch("zeus.audit_doctor.os.killpg", wraps=os.killpg) as killpg:
                ok, observation = _pinned_hermes_version(
                    executable,
                    deadline=time.monotonic() + 0.1,
                )
            self.assertFalse(ok)
            self.assertIn("deadline", observation)
            self.assertLess(time.monotonic() - started, 1)
            self.assertIn(signal.SIGTERM, [call.args[1] for call in killpg.call_args_list])

    def test_pinned_version_cleans_forked_group_after_parent_already_exited(self) -> None:
        from zeus.audit_doctor import _pinned_hermes_version

        with tempfile.TemporaryDirectory() as temporary:
            executable, marker = self._forking_executable(
                Path(temporary),
                b"Hermes Agent v0.19.0 (2026.7.20)\n",
            )
            try:
                ok, observation = _pinned_hermes_version(
                    executable,
                    deadline=time.monotonic() + 2,
                )
                process_group, child = self._descendant(marker)
                self.assertTrue(ok, observation)
                self.assertFalse(self._process_group_exists(process_group))
                self.assertFalse(self._process_exists(child))
            finally:
                self._cleanup_descendant(marker)

    def test_pinned_version_fails_when_process_group_absence_cannot_be_verified(self) -> None:
        from zeus.audit_doctor import _pinned_hermes_version

        with tempfile.TemporaryDirectory() as temporary:
            executable = self._version_executable(
                Path(temporary),
                b"Hermes Agent v0.19.0 (2026.7.20)\n",
            )
            with mock.patch("zeus.audit_doctor._stop_process_group", return_value=False):
                ok, observation = _pinned_hermes_version(
                    executable,
                    deadline=time.monotonic() + 2,
                )
            self.assertFalse(ok)
            self.assertIn("cleanup", observation)

    def test_image_probe_discards_oversized_output(self) -> None:
        from zeus.audit_doctor import _command

        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "noisy-tool"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "os.write(1, b'x' * (1024 * 1024))\n"
                "os.write(2, b'x' * (1024 * 1024))\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with mock.patch(
                "zeus.audit_doctor.subprocess.Popen",
                wraps=subprocess.Popen,
            ) as popen:
                ok, observation = _command(
                    (str(executable),),
                    deadline=time.monotonic() + 2,
                )
            self.assertTrue(ok, observation)
            self.assertIs(popen.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertIs(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_image_probe_honors_deadline_and_cleans_forked_descendant(self) -> None:
        from zeus.audit_doctor import _command

        with tempfile.TemporaryDirectory() as temporary:
            executable, marker = self._forking_executable(
                Path(temporary),
                b"",
                parent_sleep=5,
            )
            try:
                ok, observation = _command(
                    (str(executable),),
                    deadline=time.monotonic() + 0.5,
                )
                _process_group, child = self._descendant(marker)
                self.assertFalse(ok)
                self.assertIn("deadline", observation)
                self.assertFalse(self._process_exists(child))
            finally:
                self._cleanup_descendant(marker)

    def test_process_group_stop_kills_surviving_group_after_parent_exits(self) -> None:
        from zeus.audit_doctor import _stop_process_group

        process = mock.Mock(pid=424242)
        process.wait.return_value = 0
        process.poll.return_value = 0
        signals: list[int] = []
        killed = False

        def kill_group(_group_id: int, sent_signal: int) -> None:
            nonlocal killed
            signals.append(sent_signal)
            if sent_signal == signal.SIGKILL:
                killed = True
            if sent_signal == 0 and killed:
                raise ProcessLookupError

        with mock.patch("zeus.audit_doctor.os.killpg", side_effect=kill_group):
            self.assertTrue(_stop_process_group(process))
        self.assertIn(signal.SIGTERM, signals)
        self.assertIn(signal.SIGKILL, signals)
        self.assertIn(0, signals[signals.index(signal.SIGKILL) + 1 :])

    def test_broker_support_requires_every_used_posix_primitive(self) -> None:
        from zeus import audit_doctor

        self.assertTrue(audit_doctor._broker_isolation_supported())
        for target, name in (
            (audit_doctor.os, "replace"),
            (audit_doctor.os, "unlink"),
            (audit_doctor.os, "killpg"),
            (audit_doctor.fcntl, "flock"),
            (audit_doctor.signal, "SIGTERM"),
            (audit_doctor.signal, "SIGKILL"),
        ):
            with (
                self.subTest(name=name),
                mock.patch.object(target, name, None),
            ):
                self.assertFalse(audit_doctor._broker_isolation_supported())

    def test_broker_support_rejects_primitives_without_required_descriptor_keywords(self) -> None:
        from zeus import audit_doctor

        def path_only_replace(source, destination):
            return None

        with mock.patch.object(audit_doctor.os, "replace", path_only_replace):
            self.assertFalse(audit_doctor._broker_isolation_supported())

    def test_doctor_runs_complete_success_matrix_without_disclosing_credentials(self) -> None:
        from zeus.audit_config import parse_audit_config
        from zeus.audit_doctor import run_audit_doctor

        config = parse_audit_config(
            {
                "schema_version": 1,
                "provider": "provider",
                "model": "model",
                "provider_env": ["TEST_PROVIDER_KEY"],
            }
        )
        workspace = mock.Mock()
        settings = SimpleNamespace(state_dir=Path("/private/test-state"), hermes_bin="hermes")
        tool = Path(__file__).resolve()
        with (
            mock.patch("zeus.audit_doctor.inspect_private_directory", return_value=True),
            mock.patch("zeus.audit_doctor._executable", return_value=tool),
            mock.patch("zeus.audit_doctor._command", return_value=(True, "available")) as command,
            mock.patch(
                "zeus.audit_doctor._pinned_hermes_version",
                return_value=(True, "version 0.19.0"),
            ),
            mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=True),
        ):
            report = run_audit_doctor(
                workspace=workspace,
                location=mock.sentinel.location,
                settings=settings,
                env={"TEST_PROVIDER_KEY": "top-secret-value"},
                deadline=time.monotonic() + 1,
                config=config,
            )
        self.assertTrue(report.ok)
        self.assertEqual(
            {
                "repository",
                "state",
                "provider",
                "credentials",
                "docker",
                "image",
                "hermes",
                "broker_isolation",
            },
            {check.name for check in report.checks},
        )
        self.assertNotIn("top-secret-value", report.to_text())
        workspace.revalidate.assert_called_once()
        command.assert_called_once_with(
            (str(tool), "image", "inspect", config.image),
            deadline=mock.ANY,
        )

    def test_doctor_failure_matrix_reports_config_tools_credentials_and_broker(self) -> None:
        from zeus.audit_config import parse_audit_config
        from zeus.audit_doctor import run_audit_doctor

        config = parse_audit_config(
            {
                "schema_version": 1,
                "provider_env": ["TEST_PROVIDER_KEY"],
            }
        )
        workspace = mock.Mock()
        settings = SimpleNamespace(state_dir=Path("/private/test-state"), hermes_bin="hermes")
        with (
            mock.patch("zeus.audit_doctor.inspect_private_directory", return_value=False),
            mock.patch("zeus.audit_doctor._executable", return_value=None),
            mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=False),
        ):
            report = run_audit_doctor(
                workspace=workspace,
                location=mock.sentinel.location,
                settings=settings,
                env={},
                deadline=time.monotonic() + 1,
                config=config,
            )
        checks = {check.name: check for check in report.checks}
        self.assertFalse(report.ok)
        for name in (
            "state",
            "credentials",
            "docker",
            "image",
            "hermes",
            "broker_isolation",
        ):
            with self.subTest(name=name):
                self.assertFalse(checks[name].ok)

    def test_doctor_reports_invalid_configuration_without_creating_a_run(self) -> None:
        from zeus.audit_config import AuditConfigError
        from zeus.audit_doctor import run_audit_doctor

        workspace = mock.Mock()
        settings = SimpleNamespace(state_dir=Path("/private/test-state"), hermes_bin="hermes")
        with (
            mock.patch("zeus.audit_doctor.inspect_private_directory", return_value=True),
            mock.patch(
                "zeus.audit_doctor.load_audit_config",
                side_effect=AuditConfigError("invalid audit configuration"),
            ),
            mock.patch("zeus.audit_doctor._executable", return_value=None),
            mock.patch("zeus.audit_doctor._broker_isolation_supported", return_value=False),
        ):
            report = run_audit_doctor(
                workspace=workspace,
                location=mock.sentinel.location,
                settings=settings,
                env={},
                deadline=time.monotonic() + 1,
            )
        checks = {check.name: check for check in report.checks}
        self.assertFalse(checks["configuration"].ok)
        self.assertIn("invalid audit configuration", checks["configuration"].observation)


if __name__ == "__main__":
    unittest.main()
