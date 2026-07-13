from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STOP_SCRIPT = REPO_ROOT / "scripts" / "stop.sh"


class StopScriptSecurityTests(unittest.TestCase):
    def _write_fake_tools(self, workspace: Path) -> Path:
        fake_bin = workspace / "fake-bin"
        fake_bin.mkdir()

        ps_script = fake_bin / "ps"
        ps_script.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                if [ "${FAKE_PS_EXIT:-0}" = "1" ]; then
                  exit 1
                fi
                printf '%s\\n' "$FAKE_PS_ARGS"
                """
            ),
            encoding="utf-8",
        )
        ps_script.chmod(0o755)

        lsof_script = fake_bin / "lsof"
        lsof_script.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                if [ "${FAKE_LSOF_EXIT:-0}" = "1" ]; then
                  exit 1
                fi
                printf 'p%s\\nn%s\\n' "$FAKE_PID" "$FAKE_PROCESS_CWD"
                """
            ),
            encoding="utf-8",
        )
        lsof_script.chmod(0o755)

        return fake_bin

    def _run_stop(
        self,
        workspace: Path,
        *,
        ps_args: str,
        process_cwd: Path | None = None,
        fake_lsof_exit: bool = False,
        state_dir: Path | None = None,
        extra_env: dict[str, str] | None = None,
        pythonpath_prefix: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        fake_bin = self._write_fake_tools(workspace)
        env = os.environ.copy()
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        python_paths = [str(REPO_ROOT)]
        if pythonpath_prefix is not None:
            python_paths.insert(0, str(pythonpath_prefix))
        existing_pythonpath = env.get("PYTHONPATH")
        if existing_pythonpath:
            python_paths.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(python_paths)
        env["FAKE_PS_ARGS"] = ps_args
        env["FAKE_PROCESS_CWD"] = str((process_cwd or workspace).resolve())
        env["FAKE_LSOF_EXIT"] = "1" if fake_lsof_exit else "0"
        if state_dir is not None:
            env["ZEUS_STATE_DIR"] = str(state_dir)
        else:
            env.pop("ZEUS_STATE_DIR", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["sh", str(STOP_SCRIPT)],
            cwd=workspace,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def _start_sleep(self, cwd: Path) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            ["sleep", "60"],
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _terminate(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def test_rejects_malformed_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / ".zeus"
            state_dir.mkdir()
            (state_dir / "zeus.pid").write_text("123 extra\n", encoding="utf-8")

            result = self._run_stop(workspace, ps_args="python3 -m zeus.api --host 127.0.0.1")

            self.assertEqual(1, result.returncode)
            self.assertIn("Invalid Zeus PID file", result.stderr)

    def test_refuses_non_zeus_process_without_killing_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / ".zeus"
            state_dir.mkdir()
            process = self._start_sleep(workspace)
            try:
                (state_dir / "zeus.pid").write_text(f"{process.pid}\n", encoding="utf-8")

                result = self._run_stop(workspace, ps_args="sleep 60")

                self.assertEqual(1, result.returncode)
                self.assertIn("process command is not a Zeus API server", result.stderr)
                self.assertIsNone(process.poll())
            finally:
                self._terminate(process)

    def test_refuses_zeus_process_from_another_workspace_without_killing_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other_tmp:
            workspace = Path(tmp)
            other_workspace = Path(other_tmp)
            state_dir = workspace / ".zeus"
            state_dir.mkdir()
            process = self._start_sleep(other_workspace)
            try:
                (state_dir / "zeus.pid").write_text(f"{process.pid}\n", encoding="utf-8")

                result = self._run_stop(
                    workspace,
                    ps_args="python3 -m zeus.api --host 127.0.0.1 --port 4311",
                    process_cwd=other_workspace,
                )

                self.assertEqual(1, result.returncode)
                self.assertIn("process working directory is not this workspace", result.stderr)
                self.assertIsNone(process.poll())
            finally:
                self._terminate(process)

    def test_stops_verified_zeus_api_process_from_this_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / ".zeus"
            state_dir.mkdir()
            process = self._start_sleep(workspace)
            try:
                (state_dir / "zeus.pid").write_text(f"{process.pid}\n", encoding="utf-8")

                result = self._run_stop(
                    workspace,
                    ps_args="python3 -m zeus.api --host 127.0.0.1 --port 4311",
                )

                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn(f"Stopped Zeus API process {process.pid}", result.stdout)
                process.wait(timeout=5)
            finally:
                self._terminate(process)

    def test_honors_custom_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / "runtime-state"
            state_dir.mkdir()
            process = self._start_sleep(workspace)
            try:
                (state_dir / "zeus.pid").write_text(f"{process.pid}\n", encoding="utf-8")

                result = self._run_stop(
                    workspace,
                    ps_args="python3 -m zeus.api --host 127.0.0.1 --port 4311",
                    state_dir=state_dir,
                )

                self.assertEqual(0, result.returncode, result.stderr)
                process.wait(timeout=5)
            finally:
                self._terminate(process)

    def test_honors_custom_state_directory_from_dotenv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / "runtime-state"
            state_dir.mkdir()
            (workspace / ".env").write_text("ZEUS_STATE_DIR=runtime-state\n", encoding="utf-8")
            process = self._start_sleep(workspace)
            try:
                (state_dir / "zeus.pid").write_text(f"{process.pid}\n", encoding="utf-8")

                result = self._run_stop(
                    workspace,
                    ps_args="python3 -m zeus.api --host 127.0.0.1 --port 4311",
                )

                self.assertEqual(0, result.returncode, result.stderr)
                process.wait(timeout=5)
            finally:
                self._terminate(process)

    def test_removes_stale_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / ".zeus"
            state_dir.mkdir()
            pid_path = state_dir / "zeus.pid"
            pid_path.write_text("99999999\n", encoding="utf-8")

            result = self._run_stop(
                workspace,
                ps_args="python3 -m zeus.api --host 127.0.0.1",
            )

            self.assertEqual(0, result.returncode)
            self.assertFalse(pid_path.exists())

    def test_retains_pid_file_when_process_liveness_is_inaccessible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            state_dir = workspace / ".zeus"
            state_dir.mkdir()
            pid_path = state_dir / "zeus.pid"
            pid_path.write_text("99999999\n", encoding="utf-8")
            python_hook = workspace / "python-hook"
            python_hook.mkdir()
            (python_hook / "sitecustomize.py").write_text(
                "import os\n"
                "def deny_signal(_pid, _signal):\n"
                "    raise PermissionError(1, 'operation not permitted')\n"
                "os.kill = deny_signal\n",
                encoding="utf-8",
            )

            result = self._run_stop(
                workspace,
                ps_args="python3 -m zeus.api --host 127.0.0.1",
                state_dir=state_dir,
                pythonpath_prefix=python_hook,
            )

            self.assertEqual(1, result.returncode)
            self.assertIn("could not verify whether it is running", result.stderr)
            self.assertTrue(pid_path.exists())

    def test_state_resolution_failure_does_not_fall_back_to_another_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".env").write_text(
                "ZEUS_STATE_DIR=runtime-state\n",
                encoding="utf-8",
            )
            (workspace / "runtime-state").mkdir()
            default_state = workspace / ".zeus"
            default_state.mkdir()
            process = self._start_sleep(workspace)
            try:
                pid_path = default_state / "zeus.pid"
                pid_path.write_text(f"{process.pid}\n", encoding="utf-8")

                result = self._run_stop(
                    workspace,
                    ps_args="python3 -m zeus.api --host 127.0.0.1 --port 4311",
                    extra_env={"ZEUS_PORT": "not-an-integer"},
                )

                self.assertEqual(1, result.returncode)
                self.assertIn("Could not resolve Zeus state directory", result.stderr)
                self.assertIsNone(process.poll())
                self.assertTrue(pid_path.exists())
            finally:
                self._terminate(process)
