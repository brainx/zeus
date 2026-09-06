from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.host_capabilities import child_process_identity_available
from zeus.process_identity import PidState, pid_state

ROOT = Path(__file__).resolve().parents[1]
FAKE_HERMES = ROOT / "tests" / "fixtures" / "fake_slow_hermes.py"


class SubprocessLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        if not child_process_identity_available():
            self.skipTest("host does not expose child process command lines and start fingerprints")

    def _env(self, root: Path, **overrides: str) -> dict[str, str]:
        env = {
            **os.environ,
            "ZEUS_STATE_DIR": str(root / ".zeus"),
            "ZEUS_HERMES_BIN": str(FAKE_HERMES),
            "ZEUS_ENV_PASSTHROUGH": "FAKE_HERMES_MARKER_DIR",
            "FAKE_HERMES_MARKER_DIR": str(root / "markers"),
            "ZEUS_LOCK_TIMEOUT_SECONDS": "5",
        }
        env.update(overrides)
        return env

    def _run_cli(
        self,
        env: dict[str, str],
        *args: str,
        check: bool = True,
        timeout: float = 15,
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "zeus.cli", *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and completed.returncode != 0:
            self.fail(
                f"zeus {' '.join(args)} failed with {completed.returncode}\n"
                f"stdout={completed.stdout}\nstderr={completed.stderr}"
            )
        return completed

    def _wait_for_markers(self, marker_dir: Path, bot_id: str, count: int) -> list[Path]:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            markers = sorted(marker_dir.glob(f"{bot_id}-*.json"))
            if len(markers) >= count:
                return markers
            time.sleep(0.05)
        return sorted(marker_dir.glob(f"{bot_id}-*.json"))

    def test_concurrent_start_cli_processes_share_one_gateway(self) -> None:
        FAKE_HERMES.chmod(0o755)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self._env(root)
            self._run_cli(env, "bot", "create", "coder", "--template", "coding-bot")

            commands = [
                subprocess.Popen(
                    [sys.executable, "-B", "-m", "zeus.cli", "bot", "start", "coder"],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(2)
            ]
            try:
                results = [command.communicate(timeout=15) for command in commands]
            finally:
                self._run_cli(env, "bot", "stop", "coder", check=False)

            for process, (stdout, stderr) in zip(commands, results, strict=True):
                self.assertEqual(0, process.returncode, (stdout, stderr))
            statuses = [json.loads(stdout)["status"] for stdout, _stderr in results]
            self.assertEqual(["running", "running"], sorted(statuses))
            markers = self._wait_for_markers(root / "markers", "coder", 1)
            self.assertEqual(1, len(markers))

    def test_cli_stop_completes_while_another_supervisor_holds_exited_gateway_child(self) -> None:
        FAKE_HERMES.chmod(0o755)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self._env(root)
            self._run_cli(env, "bot", "create", "coder", "--template", "coding-bot")
            parent = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    "import json, subprocess, sys, uuid\n"
                    "from zeus.cli import _services\n"
                    "from zeus.config import Settings\n"
                    "_store, supervisor = _services(Settings.from_env())\n"
                    "try:\n"
                    "    result = supervisor.start(\n"
                    "        'coder', source='api', request_id=uuid.uuid4().hex)\n"
                    "    print(json.dumps({'pid': result.pid}), flush=True)\n"
                    "    sys.stdin.read()\n"
                    "finally:\n"
                    "    for child in supervisor._runtime._processes.values():\n"
                    "        if child.poll() is None:\n"
                    "            child.terminate()\n"
                    "        try:\n"
                    "            child.wait(timeout=2)\n"
                    "        except subprocess.TimeoutExpired:\n"
                    "            child.kill()\n"
                    "            child.wait(timeout=2)\n",
                ],
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert parent.stdout is not None
                readable, _, _ = select.select([parent.stdout], [], [], 10)
                self.assertTrue(readable, "gateway parent did not finish launch")
                launched = parent.stdout.readline()
                if not launched:
                    _stdout, stderr = parent.communicate("", timeout=5)
                    self.fail(f"gateway parent exited during launch: {stderr}")
                child_pid = json.loads(launched)["pid"]
                self.assertIsInstance(child_pid, int)
                self.assertIs(PidState.alive, pid_state(child_pid))

                stopped = self._run_cli(env, "bot", "stop", "coder", timeout=10)

                self.assertEqual("stopped", json.loads(stopped.stdout)["status"])
                self.assertIsNone(parent.poll())
                # The owning supervisor has not observed or reaped its child.
                # The separate CLI must recognize native exit state itself.
                os.kill(child_pid, 0)
                self.assertIs(PidState.dead, pid_state(child_pid))
            finally:
                try:
                    _stdout, stderr = parent.communicate("", timeout=10)
                except subprocess.TimeoutExpired:
                    parent.kill()
                    parent.communicate(timeout=5)
                    raise
            self.assertEqual(0, parent.returncode, stderr)

    def test_cli_process_fails_fast_when_lifecycle_lock_is_held(self) -> None:
        FAKE_HERMES.chmod(0o755)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self._env(root)
            self._run_cli(env, "bot", "create", "coder", "--template", "coding-bot")
            lock_path = root / ".zeus" / "locks" / "bots" / "coder.lock"
            holder_env = {**env, "ZEUS_LOCK_PATH": str(lock_path)}
            holder = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    (
                        "import os, time\n"
                        "from pathlib import Path\n"
                        "from zeus.process_lock import BotProcessLock\n"
                        "with BotProcessLock(Path(os.environ['ZEUS_LOCK_PATH']), "
                        "timeout_seconds=5):\n"
                        "    print('locked', flush=True)\n"
                        "    time.sleep(2)\n"
                    ),
                ],
                cwd=ROOT,
                env=holder_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual("locked", holder.stdout.readline().strip())
                locked_env = self._env(root, ZEUS_LOCK_TIMEOUT_SECONDS="0.1")
                completed = self._run_cli(
                    locked_env,
                    "bot",
                    "status",
                    "coder",
                    check=False,
                    timeout=5,
                )
                self.assertEqual(1, completed.returncode)
                body = json.loads(completed.stdout)
                self.assertEqual("bot lifecycle operation is already in progress", body["message"])
            finally:
                holder.terminate()
                try:
                    holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=5)
                if holder.stdout:
                    holder.stdout.close()
                if holder.stderr:
                    holder.stderr.close()

    def test_running_bot_replace_requires_stop_flag(self) -> None:
        FAKE_HERMES.chmod(0o755)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = self._env(root)
            self._run_cli(env, "bot", "create", "coder", "--template", "coding-bot")
            self._run_cli(env, "bot", "start", "coder")
            self.assertEqual(1, len(self._wait_for_markers(root / "markers", "coder", 1)))
            try:
                failed = self._run_cli(
                    env,
                    "bot",
                    "create",
                    "coder",
                    "--template",
                    "research-bot",
                    "--replace",
                    "--json",
                    check=False,
                )
                self.assertEqual(1, failed.returncode)
                self.assertEqual("bot_running", json.loads(failed.stdout)["error"]["code"])

                replaced = self._run_cli(
                    env,
                    "bot",
                    "create",
                    "coder",
                    "--template",
                    "research-bot",
                    "--replace",
                    "--stop",
                    "--json",
                )
                self.assertEqual("research-bot", json.loads(replaced.stdout)["template_id"])
            finally:
                self._run_cli(env, "bot", "stop", "coder", check=False)


if __name__ == "__main__":
    unittest.main()
