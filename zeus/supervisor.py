from __future__ import annotations

import os
import json
import signal
import subprocess
import time
from pathlib import Path
from typing import Callable, Protocol

from zeus.hermes_adapter import HermesAdapter
from zeus.logging_utils import tail_file
from zeus.models import BotStatus, BotStatusResponse
from zeus.state import StateStore


class PopenLike(Protocol):
    pid: int


PopenFactory = Callable[..., PopenLike]
KillFn = Callable[[int, signal.Signals], None]
PidAliveFn = Callable[[int], bool]


class Supervisor:
    def __init__(
        self,
        store: StateStore,
        hermes_bin: str,
        hermes_root: Path | str,
        popen_factory: PopenFactory = subprocess.Popen,
        kill_fn: KillFn = os.kill,
        pid_alive_fn: PidAliveFn | None = None,
        stop_grace_seconds: float = 15.0,
    ) -> None:
        self.store = store
        self.adapter = HermesAdapter(hermes_bin=hermes_bin, hermes_root=hermes_root)
        self.popen_factory = popen_factory
        self.kill_fn = kill_fn
        self.pid_alive_fn = pid_alive_fn
        self.stop_grace_seconds = stop_grace_seconds
        self._processes: dict[str, PopenLike] = {}

    def start(self, bot_id: str) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if record.pid and self._pid_alive(record.pid):
            if not self._pid_owned(record.profile_path, record.pid, bot_id):
                self.store.update_status(bot_id, BotStatus.failed, pid=record.pid)
                return BotStatusResponse(
                    bot_id=bot_id,
                    status=BotStatus.failed,
                    pid=record.pid,
                    profile_path=record.profile_path,
                    message="recorded gateway PID is alive but ownership could not be verified",
                )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.running,
                pid=record.pid,
                profile_path=record.profile_path,
                message="already running",
            )

        argv, env = self.adapter.command(bot_id, "gateway", "run")
        log_path = self.log_path(record.profile_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("ab") as log_file:
            process = self.popen_factory(argv, env=env, stdout=log_file, stderr=log_file)
        self._processes[bot_id] = process
        self._write_pid_marker(record.profile_path, process.pid, argv)
        self.store.update_status(bot_id, BotStatus.running, pid=process.pid)
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.running,
            pid=process.pid,
            profile_path=record.profile_path,
            message="started",
        )

    def stop(self, bot_id: str) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if not record.pid or not self._pid_alive(record.pid):
            self._remove_pid_marker(record.profile_path)
            self.store.update_status(bot_id, BotStatus.stopped, pid=None)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )

        if not self._pid_owned(record.profile_path, record.pid, bot_id):
            self.store.update_status(bot_id, BotStatus.failed, pid=record.pid)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=record.pid,
                profile_path=record.profile_path,
                message="refusing to stop process because PID ownership could not be verified",
            )

        self.kill_fn(record.pid, signal.SIGTERM)
        stopped = self._wait_for_exit(bot_id, record.pid)
        if not stopped:
            self.store.update_status(bot_id, BotStatus.failed, pid=record.pid)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=record.pid,
                profile_path=record.profile_path,
                message=(
                    "gateway did not stop before grace period expired; "
                    "Hermes async delegations may still be running"
                ),
            )

        self.store.update_status(bot_id, BotStatus.stopped, pid=None)
        self._processes.pop(bot_id, None)
        self._remove_pid_marker(record.profile_path)
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.stopped,
            pid=None,
            profile_path=record.profile_path,
            message="gateway shutdown completed",
        )

    def status(self, bot_id: str) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        alive = bool(record.pid and self._pid_alive(record.pid))
        if alive and record.pid and not self._pid_owned(record.profile_path, record.pid, bot_id):
            self.store.update_status(bot_id, BotStatus.failed, pid=record.pid)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=record.pid,
                profile_path=record.profile_path,
                message="recorded gateway PID is alive but ownership could not be verified",
            )
        status = BotStatus.running if alive else BotStatus.stopped
        if status != record.status:
            self.store.update_status(bot_id, status, pid=record.pid if alive else None)
        return BotStatusResponse(
            bot_id=bot_id,
            status=status,
            pid=record.pid if alive else None,
            profile_path=record.profile_path,
        )

    def logs(self, bot_id: str, max_bytes: int = 20_000) -> str:
        record = self._require_bot(bot_id)
        return tail_file(self.log_path(record.profile_path), max_bytes=max_bytes)

    def log_path(self, profile_path: str) -> Path:
        return Path(profile_path) / "logs" / "zeus-gateway.log"

    def pid_marker_path(self, profile_path: str) -> Path:
        return Path(profile_path) / "logs" / "zeus-gateway.pid.json"

    def _require_bot(self, bot_id: str):
        record = self.store.get_bot(bot_id)
        if record is None:
            raise KeyError(f"unknown bot: {bot_id}")
        return record

    def _pid_alive(self, pid: int) -> bool:
        if self.pid_alive_fn is not None:
            return self.pid_alive_fn(pid)
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def _write_pid_marker(self, profile_path: str, pid: int, argv: list[str]) -> None:
        path = self.pid_marker_path(profile_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pid": pid,
            "argv": argv,
            "started_at": time.time(),
        }
        path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    def _remove_pid_marker(self, profile_path: str) -> None:
        try:
            self.pid_marker_path(profile_path).unlink()
        except FileNotFoundError:
            return

    def _pid_owned(self, profile_path: str, pid: int, bot_id: str) -> bool:
        try:
            payload = json.loads(self.pid_marker_path(profile_path).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return False
        if payload.get("pid") != pid:
            return False
        argv = payload.get("argv")
        if not isinstance(argv, list):
            return False
        return "-p" in argv and bot_id in argv

    def _wait_for_exit(self, bot_id: str, pid: int) -> bool:
        process = self._processes.get(bot_id)
        if process is not None and hasattr(process, "wait"):
            try:
                process.wait(timeout=self.stop_grace_seconds)
                return True
            except subprocess.TimeoutExpired:
                return False
            except Exception:
                return False

        deadline = time.monotonic() + self.stop_grace_seconds
        while self._pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        return not self._pid_alive(pid)
