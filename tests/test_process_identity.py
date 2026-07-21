from __future__ import annotations

import ast
import errno
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import zeus.process_identity as identity
import zeus.supervisor as supervisor_module


class ProcessReaderTests(unittest.TestCase):
    def test_linux_cmdline_parses_proc_bytes_and_handles_missing_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "4321"
            pid_dir.mkdir(parents=True)
            (pid_dir / "cmdline").write_bytes(b"hermes\0-p\0coder\0gateway\0run\0invalid-\xff\0")

            argv = identity.read_linux_cmdline(4321, proc_root=proc_root)

            self.assertEqual(
                ["hermes", "-p", "coder", "gateway", "run", "invalid-\udcff"],
                argv,
            )
            self.assertEqual([], identity.read_linux_cmdline(9999, proc_root=proc_root))

    def test_linux_start_fingerprint_reads_proc_stat_field_twenty_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "4321"
            pid_dir.mkdir(parents=True)
            fields = ["S", *["0"] * 18, "987654321", "0"]
            (pid_dir / "stat").write_text(
                f"4321 (hermes gateway) {' '.join(fields)}\n",
                encoding="utf-8",
            )

            fingerprint = identity.read_linux_process_start_fingerprint(
                4321,
                proc_root=proc_root,
            )

            self.assertEqual("linux:/proc-starttime:987654321", fingerprint)
            self.assertIsNone(
                identity.read_linux_process_start_fingerprint(9999, proc_root=proc_root)
            )

    def test_darwin_cmdline_uses_fixed_ps_command_and_parses_quotes(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout='"/Applications/Hermes CLI/hermes" -p coder gateway run\n',
        )
        with patch("zeus.process_identity.subprocess.run", return_value=completed) as run:
            argv = identity.read_darwin_cmdline(4321)

        self.assertEqual(
            ["/Applications/Hermes CLI/hermes", "-p", "coder", "gateway", "run"],
            argv,
        )
        run.assert_called_once_with(
            ["/bin/ps", "-p", "4321", "-o", "command="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )

    def test_darwin_start_fingerprint_normalizes_ps_lstart(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="  Mon Jun 29   16:54:50 2026\n",
        )
        with patch("zeus.process_identity.subprocess.run", return_value=completed) as run:
            fingerprint = identity.read_darwin_process_start_fingerprint(4321)

        self.assertEqual("darwin:ps-lstart:Mon Jun 29 16:54:50 2026", fingerprint)
        run.assert_called_once_with(
            ["/bin/ps", "-p", "4321", "-o", "lstart="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )

    def test_platform_dispatchers_select_linux_darwin_or_unsupported(self) -> None:
        with (
            patch("zeus.process_identity.platform.system", return_value="Linux"),
            patch(
                "zeus.process_identity.read_linux_cmdline",
                return_value=["linux"],
            ) as linux_cmdline,
            patch(
                "zeus.process_identity.read_linux_process_start_fingerprint",
                return_value="linux-start",
            ) as linux_start,
        ):
            self.assertEqual(["linux"], identity.read_process_cmdline(11))
            self.assertEqual("linux-start", identity.read_process_start_fingerprint(11))
        linux_cmdline.assert_called_once_with(11)
        linux_start.assert_called_once_with(11)

        with (
            patch("zeus.process_identity.platform.system", return_value="Darwin"),
            patch(
                "zeus.process_identity.read_darwin_cmdline",
                return_value=["darwin"],
            ) as darwin_cmdline,
            patch(
                "zeus.process_identity.read_darwin_process_start_fingerprint",
                return_value="darwin-start",
            ) as darwin_start,
        ):
            self.assertEqual(["darwin"], identity.read_process_cmdline(22))
            self.assertEqual("darwin-start", identity.read_process_start_fingerprint(22))
        darwin_cmdline.assert_called_once_with(22)
        darwin_start.assert_called_once_with(22)

        with patch("zeus.process_identity.platform.system", return_value="FreeBSD"):
            self.assertIsNone(identity.read_process_cmdline(33))
            self.assertIsNone(identity.read_process_start_fingerprint(33))


class CommandIdentityTests(unittest.TestCase):
    @staticmethod
    def _write_executable(path: Path, text: str = "#!/bin/sh\n") -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
        return str(path.resolve())

    def test_gateway_command_classifier_preserves_complete_shape_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._write_executable(root / "bin" / "hermes")
            fake_hermes = self._write_executable(root / "bin" / "fake-hermes")
            cases = (
                (["hermes", "-p", "coder", "gateway", "run"], True, "direct-hermes", "ok"),
                ([hermes_bin, "-p", "coder", "gateway", "run"], True, "direct-hermes", "ok"),
                (
                    [sys.executable, hermes_bin, "-p", "coder", "gateway", "run"],
                    True,
                    "python-script-wrapper",
                    "ok",
                ),
                (
                    [sys.executable, fake_hermes, "-p", "coder", "gateway", "run"],
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
                (
                    [hermes_bin, "gateway", "run"],
                    False,
                    "direct-hermes",
                    "wrong-command-intent",
                ),
                (
                    [hermes_bin, "-p", "coder", "-p", "other", "gateway", "run"],
                    False,
                    "direct-hermes",
                    "wrong-command-intent",
                ),
            )
            with patch.dict(os.environ, {"PATH": str(root / "bin")}):
                for argv, verified, classification, reason in cases:
                    with self.subTest(argv=argv):
                        check = identity.verify_gateway_command(
                            argv,
                            "coder",
                            hermes_bin,
                            require_trusted_path=True,
                        )
                        self.assertEqual(verified, check.verified)
                        self.assertEqual(classification, check.classification)
                        self.assertEqual(reason, check.reason)

    def test_command_shape_and_python_interpreter_classification_are_bounded(self) -> None:
        for command in ("python", "python3", "PYTHON3.11", "/usr/bin/python3.12"):
            with self.subTest(command=command):
                self.assertTrue(identity.looks_like_python_interpreter(command))
        for command in ("pypy3", "python3.11-config", "python-script", ""):
            with self.subTest(command=command):
                self.assertFalse(identity.looks_like_python_interpreter(command))

        self.assertEqual("empty", identity.safe_command_shape([]))
        self.assertEqual(
            "direct-hermes hermes -p <bot> gateway run",
            identity.safe_command_shape(["hermes", "-p", "secret-bot", "gateway", "run"]),
        )
        self.assertEqual(
            "python-script-wrapper hermes -p <bot> gateway run",
            identity.safe_command_shape(
                [sys.executable, "/opt/hermes", "-p", "secret-bot", "gateway", "run"]
            ),
        )
        self.assertEqual(
            "direct-hermes unrecognized",
            identity.safe_command_shape(["hermes", "doctor"]),
        )

    def test_executable_launcher_and_trusted_hermes_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._write_executable(root / "real" / "hermes")
            path_hermes = self._write_executable(root / "bin" / "path-hermes")
            launcher = root / "bin" / "hermes-launcher"
            launcher_path = self._write_executable(
                launcher,
                f'#!/bin/sh\n# delegated install\nexec "{hermes_bin}" "$@"\n',
            )

            self.assertIsNone(identity.resolve_executable(""))
            self.assertEqual(
                path_hermes, identity.resolve_executable("path-hermes", str(root / "bin"))
            )
            self.assertEqual(launcher_path, identity.resolve_executable(launcher_path))
            self.assertEqual(hermes_bin, identity.resolve_launcher_exec_target(launcher_path))
            self.assertEqual(
                {launcher_path, hermes_bin},
                identity.trusted_hermes_paths(launcher_path),
            )
            self.assertEqual({hermes_bin}, identity.trusted_hermes_paths(hermes_bin))

    def test_launcher_resolution_rejects_untrusted_or_malformed_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            not_hermes = self._write_executable(root / "bin" / "not-hermes")
            cases = (
                ("plain", f'exec "{not_hermes}" "$@"\n'),
                ("no-exec", "#!/bin/sh\nprintf ready\n"),
                ("path-lookup", '#!/bin/sh\nexec hermes "$@"\n'),
                ("malformed", "#!/bin/sh\nexec 'unterminated\n"),
                ("wrong-target", f'#!/bin/sh\nexec "{not_hermes}" "$@"\n'),
            )
            for name, text in cases:
                with self.subTest(name=name):
                    script = root / name
                    script.write_text(text, encoding="utf-8")
                    self.assertIsNone(identity.resolve_launcher_exec_target(str(script)))


class PidStateTests(unittest.TestCase):
    @staticmethod
    def _raises(exc: BaseException) -> identity.PidAliveFn:
        def raise_error(_pid: int) -> bool:
            raise exc

        return raise_error

    def test_pid_state_classifies_callbacks_and_os_errors_exactly(self) -> None:
        cases = (
            ("alive", lambda _pid: True, identity.PidState.alive),
            ("false", lambda _pid: False, identity.PidState.dead),
            (
                "esrch",
                self._raises(OSError(errno.ESRCH, "no such process")),
                identity.PidState.dead,
            ),
            (
                "eperm",
                self._raises(OSError(errno.EPERM, "operation not permitted")),
                identity.PidState.unknown,
            ),
            (
                "process-lookup",
                self._raises(ProcessLookupError(errno.ESRCH, "no such process")),
                identity.PidState.dead,
            ),
            (
                "permission",
                self._raises(PermissionError(errno.EPERM, "operation not permitted")),
                identity.PidState.unknown,
            ),
        )
        for name, callback, expected in cases:
            with self.subTest(name=name):
                self.assertIs(expected, identity.pid_state(4321, pid_alive_fn=callback))

    def test_pid_state_default_probes_with_signal_zero(self) -> None:
        with patch("zeus.process_identity.os.kill") as kill:
            self.assertIs(identity.PidState.alive, identity.pid_state(4321))
        kill.assert_called_once_with(4321, 0)


class ProcessStartIdentityTests(unittest.TestCase):
    def test_process_start_requirement_is_explicit_and_platform_bounded(self) -> None:
        self.assertTrue(identity.process_start_fingerprint_required("Linux"))
        self.assertTrue(identity.process_start_fingerprint_required("Darwin"))
        self.assertFalse(identity.process_start_fingerprint_required("FreeBSD"))
        self.assertFalse(identity.process_start_fingerprint_required("linux"))

    def test_process_start_fingerprint_validation_is_exact(self) -> None:
        self.assertTrue(identity.valid_process_start_fingerprint("x"))
        self.assertTrue(identity.valid_process_start_fingerprint("x" * 512))
        for value in (None, "", "x" * 513, 1, True, b"start"):
            with self.subTest(value=value):
                self.assertFalse(identity.valid_process_start_fingerprint(value))

    def test_process_start_comparison_preserves_required_and_optional_semantics(self) -> None:
        cases = (
            ("same", "same", True, None),
            (None, "same", True, "process start fingerprint is unavailable"),
            ("same", None, True, "process start fingerprint is unavailable"),
            ("old", "new", True, "process start fingerprint does not match"),
            (None, None, False, None),
            ("same", "same", False, None),
            (None, "live", False, "process start fingerprint does not match"),
            ("marker", None, False, "process start fingerprint is unavailable"),
            ("old", "new", False, "process start fingerprint does not match"),
        )
        for marker, live, required, expected in cases:
            with self.subTest(marker=marker, live=live, required=required):
                self.assertEqual(
                    expected,
                    identity.process_start_identity_error(
                        marker,
                        live,
                        fingerprint_required=required,
                    ),
                )


class FrozenBoundaryTests(unittest.TestCase):
    def test_identity_types_are_frozen_and_finite(self) -> None:
        self.assertEqual(
            {"alive", "dead", "unknown"},
            {state.value for state in identity.PidState},
        )
        check = identity.CommandCheck(True, "ok", "direct-hermes")
        with self.assertRaises(FrozenInstanceError):
            check.reason = "changed"  # type: ignore[misc]

    def test_process_identity_has_only_standard_library_dependencies(self) -> None:
        module_path = Path(identity.__file__)
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertNotIn("zeus", imported_roots)
        self.assertNotIn("sqlite3", imported_roots)
        self.assertNotIn("signal", imported_roots)
        self.assertNotIn("StateStore", source)
        self.assertNotIn("BotRecord", source)


class SupervisorCompatibilityTests(unittest.TestCase):
    def test_legacy_types_and_pure_helpers_remain_direct_aliases(self) -> None:
        self.assertIs(identity.PidState, supervisor_module._PidState)
        self.assertIs(identity.CommandCheck, supervisor_module._CommandCheck)
        self.assertIs(identity.PidAliveFn, supervisor_module.PidAliveFn)
        self.assertIs(identity.CmdlineReader, supervisor_module.CmdlineReader)
        self.assertIs(
            identity.ProcStartFingerprintReader,
            supervisor_module.ProcStartFingerprintReader,
        )
        aliases = {
            "_read_linux_cmdline": identity.read_linux_cmdline,
            "_read_linux_process_start_fingerprint": (
                identity.read_linux_process_start_fingerprint
            ),
            "_verify_gateway_command": identity.verify_gateway_command,
            "_looks_like_python_interpreter": identity.looks_like_python_interpreter,
            "_resolve_executable": identity.resolve_executable,
            "_trusted_hermes_paths": identity.trusted_hermes_paths,
            "_resolve_launcher_exec_target": identity.resolve_launcher_exec_target,
            "_safe_command_shape": identity.safe_command_shape,
        }
        for old_name, new_value in aliases.items():
            with self.subTest(old_name=old_name):
                self.assertIs(new_value, getattr(supervisor_module, old_name))

    def test_legacy_cmdline_dispatch_uses_current_supervisor_globals(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout='"/patched/hermes" -p coder gateway run\n',
        )
        with (
            patch("zeus.supervisor.platform.system", return_value="Darwin") as system,
            patch("zeus.supervisor.subprocess.run", return_value=completed) as run,
        ):
            argv = supervisor_module._read_process_cmdline(4321)

        self.assertEqual(["/patched/hermes", "-p", "coder", "gateway", "run"], argv)
        system.assert_called_once_with()
        run.assert_called_once_with(
            ["/bin/ps", "-p", "4321", "-o", "command="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )

    def test_legacy_direct_darwin_readers_use_current_supervisor_subprocess(self) -> None:
        command = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="/patched/hermes -p coder gateway run\n",
        )
        started = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="Mon Jun 29 16:54:50 2026\n",
        )
        with patch("zeus.supervisor.subprocess.run", side_effect=[command, started]) as run:
            argv = supervisor_module._read_darwin_cmdline(4321)
            fingerprint = supervisor_module._read_darwin_process_start_fingerprint(4321)

        self.assertEqual(["/patched/hermes", "-p", "coder", "gateway", "run"], argv)
        self.assertEqual("darwin:ps-lstart:Mon Jun 29 16:54:50 2026", fingerprint)
        self.assertEqual(2, run.call_count)

    def test_legacy_start_dispatch_uses_current_platform_and_subprocess(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["ps"],
            returncode=0,
            stdout="Mon Jun 29 16:54:50 2026\n",
        )
        with (
            patch("zeus.supervisor.platform.system", return_value="Darwin") as system,
            patch("zeus.supervisor.subprocess.run", return_value=completed) as run,
        ):
            fingerprint = supervisor_module._read_process_start_fingerprint(4321)

        self.assertEqual("darwin:ps-lstart:Mon Jun 29 16:54:50 2026", fingerprint)
        system.assert_called_once_with()
        run.assert_called_once()

    def test_supervisor_pid_state_shim_uses_live_callback_or_current_os_kill(self) -> None:
        supervisor = object.__new__(supervisor_module.Supervisor)
        supervisor.pid_alive_fn = None
        with patch("zeus.supervisor.os.kill") as kill:
            self.assertIs(identity.PidState.alive, supervisor._pid_state(4321))
            supervisor.pid_alive_fn = lambda _pid: False
            self.assertIs(identity.PidState.dead, supervisor._pid_state(4321))
        kill.assert_called_once_with(4321, 0)

        supervisor.pid_alive_fn = self._permission_denied
        self.assertIs(identity.PidState.unknown, supervisor._pid_state(4321))

    @staticmethod
    def _permission_denied(_pid: int) -> bool:
        raise PermissionError(errno.EPERM, "operation not permitted")

    def test_supervisor_process_start_shims_read_live_callback_and_platform(self) -> None:
        supervisor = object.__new__(supervisor_module.Supervisor)
        supervisor.proc_start_fingerprint_reader = lambda _pid: "same"
        with patch("zeus.supervisor.platform.system", return_value="Linux"):
            self.assertTrue(supervisor._process_start_fingerprint_required())
            self.assertTrue(supervisor._valid_marker_start("same"))
            self.assertIsNone(
                supervisor._process_start_identity_error(
                    {"proc_start_fingerprint": "same"},
                    4321,
                )
            )
            supervisor.proc_start_fingerprint_reader = lambda _pid: "reused"
            self.assertEqual(
                "process start fingerprint does not match",
                supervisor._process_start_identity_error(
                    {"proc_start_fingerprint": "same"},
                    4321,
                ),
            )

        with patch("zeus.supervisor.platform.system", return_value="FreeBSD"):
            self.assertFalse(supervisor._process_start_fingerprint_required())

    def test_supervisor_hermes_resolution_shims_use_current_adapter_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes = Path(tmp) / "hermes"
            hermes.write_text("#!/bin/sh\n", encoding="utf-8")
            supervisor = object.__new__(supervisor_module.Supervisor)
            supervisor.adapter = SimpleNamespace(hermes_bin=str(hermes))

            self.assertEqual(str(hermes.resolve()), supervisor._resolved_hermes_bin())
            self.assertEqual({str(hermes.resolve())}, supervisor._trusted_hermes_bins())


if __name__ == "__main__":
    unittest.main()
