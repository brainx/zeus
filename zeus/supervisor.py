from __future__ import annotations

import json
import os
import platform
import signal
import subprocess  # nosec B404
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from zeus.hermes_adapter import HermesAdapter
from zeus.logging_utils import tail_file
from zeus.models import BotRecord, BotStatus, BotStatusResponse, RestartPolicy
from zeus.state import StateStore


class PopenLike(Protocol):
    pid: int


PopenFactory = Callable[..., PopenLike]
KillFn = Callable[[int, signal.Signals], None]
PidAliveFn = Callable[[int], bool]
CmdlineReader = Callable[[int], list[str] | None]


class Supervisor:
    def __init__(
        self,
        store: StateStore,
        hermes_bin: str,
        hermes_root: Path | str,
        popen_factory: PopenFactory = subprocess.Popen,
        kill_fn: KillFn = os.kill,
        pid_alive_fn: PidAliveFn | None = None,
        cmdline_reader: CmdlineReader | None = None,
        stop_grace_seconds: float = 15.0,
        restart_backoff_cap_seconds: float = 3600.0,
    ) -> None:
        self.store = store
        self.adapter = HermesAdapter(hermes_bin=hermes_bin, hermes_root=hermes_root)
        self.popen_factory = popen_factory
        self.kill_fn = kill_fn
        self.pid_alive_fn = pid_alive_fn
        self.cmdline_reader = cmdline_reader or _read_linux_cmdline
        self.stop_grace_seconds = stop_grace_seconds
        self.restart_backoff_cap_seconds = restart_backoff_cap_seconds
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
            self.store.update_status(bot_id, BotStatus.running, pid=record.pid, reset_restart=True)
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.running,
                pid=record.pid,
                profile_path=record.profile_path,
                message="already running",
            )

        return self._start_record(record, reset_restart=True, message="started")

    def _start_record(
        self, record: BotRecord, *, reset_restart: bool, message: str
    ) -> BotStatusResponse:
        bot_id = record.bot_id
        argv, env = self.adapter.command(bot_id, "gateway", "run")
        log_path = self.log_path(record.profile_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("ab") as log_file:
            process = self.popen_factory(argv, env=env, stdout=log_file, stderr=log_file)
        self._processes[bot_id] = process
        self._write_pid_marker(record.profile_path, process.pid, argv)
        self.store.update_status(
            bot_id, BotStatus.running, pid=process.pid, reset_restart=reset_restart
        )
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.running,
            pid=process.pid,
            profile_path=record.profile_path,
            message=message,
        )

    def stop(self, bot_id: str) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if not record.pid or not self._pid_alive(record.pid):
            self._remove_pid_marker(record.profile_path)
            self.store.update_status(bot_id, BotStatus.stopped, pid=None, reset_restart=True)
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

        self.store.update_status(bot_id, BotStatus.stopped, pid=None, reset_restart=True)
        self._processes.pop(bot_id, None)
        self._remove_pid_marker(record.profile_path)
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.stopped,
            pid=None,
            profile_path=record.profile_path,
            message="gateway shutdown completed",
        )

    def restart(self, bot_id: str) -> BotStatusResponse:
        stopped = self.stop(bot_id)
        if stopped.status == BotStatus.failed:
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=stopped.pid,
                profile_path=stopped.profile_path,
                message="restart aborted: " + stopped.message,
            )

        started = self.start(bot_id)
        if started.status == BotStatus.running:
            return BotStatusResponse(
                bot_id=bot_id,
                status=started.status,
                pid=started.pid,
                profile_path=started.profile_path,
                message="restarted",
            )
        return started

    def reconcile(
        self, bot_id: str | None = None, *, now: datetime | None = None
    ) -> list[BotStatusResponse]:
        current_time = now or datetime.now(UTC)
        records = [self._require_bot(bot_id)] if bot_id else self.store.list_bots()
        return [self._reconcile_record(record, current_time) for record in records]

    def _reconcile_record(self, record: BotRecord, now: datetime) -> BotStatusResponse:
        if record.pid and self._pid_alive(record.pid):
            if not self._pid_owned(record.profile_path, record.pid, record.bot_id):
                self.store.update_status(record.bot_id, BotStatus.failed, pid=record.pid)
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.failed,
                    pid=record.pid,
                    profile_path=record.profile_path,
                    message="recorded gateway PID is alive but ownership could not be verified",
                )
            self.store.update_status(
                record.bot_id, BotStatus.running, pid=record.pid, reset_restart=True
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.running,
                pid=record.pid,
                profile_path=record.profile_path,
                message="running",
            )

        if record.pid:
            self._remove_pid_marker(record.profile_path)

        if record.status == BotStatus.stopped:
            self.store.update_status(record.bot_id, BotStatus.stopped, pid=None)
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.stopped,
                pid=None,
                profile_path=record.profile_path,
                message="not running",
            )

        if record.restart_policy != RestartPolicy.on_failure:
            self.store.update_status(record.bot_id, BotStatus.failed, pid=None)
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message="gateway is not running and restart policy is manual",
            )

        if record.restart_attempts >= record.restart_max_attempts:
            self.store.update_restart_state(
                record.bot_id,
                status=BotStatus.failed,
                pid=None,
                restart_attempts=record.restart_attempts,
                next_restart_at=None,
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message="restart limit reached",
            )

        if record.next_restart_at is None:
            delay = self._restart_delay(record)
            next_restart_at = now + timedelta(seconds=delay)
            self.store.update_restart_state(
                record.bot_id,
                status=BotStatus.failed,
                pid=None,
                restart_attempts=record.restart_attempts + 1,
                next_restart_at=next_restart_at,
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=f"restart scheduled in {delay:g}s",
            )

        if record.next_restart_at > now:
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=f"restart pending until {record.next_restart_at.isoformat()}",
            )

        self.store.update_restart_state(
            record.bot_id,
            status=BotStatus.failed,
            pid=None,
            restart_attempts=record.restart_attempts,
            next_restart_at=None,
        )
        refreshed = self._require_bot(record.bot_id)
        return self._start_record(refreshed, reset_restart=False, message="restarted by reconcile")

    def _restart_delay(self, record: BotRecord) -> float:
        delay = record.restart_backoff_seconds * (2**record.restart_attempts)
        return float(min(delay, self.restart_backoff_cap_seconds))

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
        elif status == BotStatus.running:
            self.store.update_status(bot_id, status, pid=record.pid, reset_restart=True)
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

    def _require_bot(self, bot_id: str) -> BotRecord:
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
        argv_value = payload.get("argv")
        if not isinstance(argv_value, list) or not all(
            isinstance(part, str) for part in argv_value
        ):
            return False
        argv = list(argv_value)
        expected_argv = self._expected_gateway_argv(bot_id)
        if argv != expected_argv:
            return False
        live_argv = self.cmdline_reader(pid)
        if live_argv is None:
            return True
        return _cmdline_matches_expected(live_argv, expected_argv)

    def _expected_gateway_argv(self, bot_id: str) -> list[str]:
        return [self.adapter.hermes_bin, "-p", bot_id, "gateway", "run"]

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


def _read_linux_cmdline(pid: int) -> list[str] | None:
    if platform.system() != "Linux":
        return None
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def _cmdline_matches_expected(live_argv: list[str], expected_argv: list[str]) -> bool:
    if live_argv == expected_argv:
        return True
    return len(live_argv) == len(expected_argv) + 1 and live_argv[1:] == expected_argv
