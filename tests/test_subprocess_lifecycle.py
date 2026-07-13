from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from zeus.supervisor import _read_process_cmdline

ROOT = Path(__file__).resolve().parents[1]
FAKE_HERMES = ROOT / "tests" / "fixtures" / "fake_slow_hermes.py"


class SubprocessLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.05)
            if _read_process_cmdline(process.pid) is None:
                self.skipTest("host does not expose child process command lines")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

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
