from __future__ import annotations

import json
import os
import platform
import shlex
import signal
import subprocess  # nosec B404
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from zeus.hermes_adapter import HermesAdapter
from zeus.logging_utils import tail_file
from zeus.models import BotRecord, BotStatus, BotStatusResponse, RestartPolicy
from zeus.state import StateStore


class PopenLike(Protocol):
    pid: int

    def poll(self) -> int | None: ...


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
        startup_grace_seconds: float = 0.25,
        stop_grace_seconds: float = 15.0,
        kill_after_timeout: bool = False,
        restart_backoff_cap_seconds: float = 3600.0,
    ) -> None:
        self.store = store
        self.adapter = HermesAdapter(hermes_bin=hermes_bin, hermes_root=hermes_root)
        self.popen_factory = popen_factory
        self.kill_fn = kill_fn
        self.pid_alive_fn = pid_alive_fn
        self.cmdline_reader = cmdline_reader or _read_process_cmdline
        self.startup_grace_seconds = startup_grace_seconds
        self.stop_grace_seconds = stop_grace_seconds
        self.kill_after_timeout = kill_after_timeout
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
        returncode = self._poll_startup(process)
        if returncode is not None:
            self._remove_pid_marker(record.profile_path)
            self._processes.pop(bot_id, None)
            self.store.update_status(bot_id, BotStatus.failed, pid=None)
            self.store.append_audit_event(
                "bot.start_failed",
                bot_id=bot_id,
                pid=process.pid,
                returncode=returncode,
            )
            return BotStatusResponse(
                bot_id=bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=(
                    f"gateway exited during startup grace period with return code {returncode}"
                ),
            )
        self.store.update_status(
            bot_id, BotStatus.running, pid=process.pid, reset_restart=reset_restart
        )
        self.store.append_audit_event("bot.start", bot_id=bot_id, pid=process.pid)
        return BotStatusResponse(
            bot_id=bot_id,
            status=BotStatus.running,
            pid=process.pid,
            profile_path=record.profile_path,
            message=message,
        )

    def stop(self, bot_id: str, *, kill_after_timeout: bool | None = None) -> BotStatusResponse:
        record = self._require_bot(bot_id)
        if not record.pid or not self._pid_alive(record.pid):
            self._remove_pid_marker(record.profile_path)
            self.store.update_status(bot_id, BotStatus.stopped, pid=None, reset_restart=True)
            self.store.append_audit_event("bot.stop", bot_id=bot_id, pid=record.pid)
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
        should_kill = self.kill_after_timeout if kill_after_timeout is None else kill_after_timeout
        if not stopped and should_kill:
            self.kill_fn(record.pid, signal.SIGKILL)
            stopped = self._wait_for_exit(bot_id, record.pid)
            self.store.append_audit_event(
                "bot.stop_kill",
                bot_id=bot_id,
                pid=record.pid,
                succeeded=stopped,
            )
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
        self.store.append_audit_event("bot.stop", bot_id=bot_id, pid=record.pid)
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
        self,
        bot_id: str | None = None,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
    ) -> list[BotStatusResponse]:
        current_time = now or datetime.now(UTC)
        records = [self._require_bot(bot_id)] if bot_id else self.store.list_bots()
        return [
            self._reconcile_record(record, current_time, force=force, reset_restart=reset_restart)
            for record in records
        ]

    def _reconcile_record(
        self, record: BotRecord, now: datetime, *, force: bool, reset_restart: bool
    ) -> BotStatusResponse:
        if reset_restart:
            self.store.update_restart_state(
                record.bot_id,
                status=record.status,
                pid=record.pid,
                restart_attempts=0,
                next_restart_at=None,
            )
            record = replace(record, restart_attempts=0, next_restart_at=None)

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
                message="manual policy: not restarting",
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
                message=(
                    "restart limit reached: "
                    f"{record.restart_attempts}/{record.restart_max_attempts}"
                ),
            )

        if record.next_restart_at is None and not force:
            delay = self._restart_delay(record)
            next_restart_at = now + timedelta(seconds=delay)
            attempt = record.restart_attempts + 1
            self.store.update_restart_state(
                record.bot_id,
                status=BotStatus.failed,
                pid=None,
                restart_attempts=attempt,
                next_restart_at=next_restart_at,
            )
            self.store.append_audit_event(
                "bot.reconcile.restart_scheduled",
                bot_id=record.bot_id,
                attempt=attempt,
                next_restart_at=next_restart_at.isoformat(),
            )
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=(
                    "restart scheduled: "
                    f"attempt {attempt}/{record.restart_max_attempts} in {delay:g}s"
                ),
            )

        if record.next_restart_at is not None and record.next_restart_at > now and not force:
            return BotStatusResponse(
                bot_id=record.bot_id,
                status=BotStatus.failed,
                pid=None,
                profile_path=record.profile_path,
                message=(
                    "restart pending: "
                    f"attempt {record.restart_attempts}/{record.restart_max_attempts} "
                    f"due at {record.next_restart_at.isoformat()}"
                ),
            )

        attempt = record.restart_attempts
        if record.next_restart_at is None or attempt == 0:
            attempt += 1
        self.store.update_restart_state(
            record.bot_id,
            status=BotStatus.failed,
            pid=None,
            restart_attempts=attempt,
            next_restart_at=None,
        )
        refreshed = self._require_bot(record.bot_id)
        result = self._start_record(
            refreshed,
            reset_restart=False,
            message=f"restarted by reconcile: attempt {attempt}/{record.restart_max_attempts}",
        )
        if result.status == BotStatus.running:
            self.store.append_audit_event(
                "bot.reconcile.restart_started",
                bot_id=record.bot_id,
                pid=result.pid,
                attempt=attempt,
            )
        return result

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

    def inspect(self, bot_id: str, max_log_bytes: int = 20_000) -> dict[str, object]:
        record = self._require_bot(bot_id)
        profile_path = Path(record.profile_path)
        marker = self._read_pid_marker(record.profile_path)
        live_cmdline_verified = False
        if record.pid and self._pid_alive(record.pid):
            live_cmdline_verified = self._pid_owned(record.profile_path, record.pid, bot_id)
        return {
            "bot": record.to_dict(),
            "profile_files": {
                "config.yaml": (profile_path / "config.yaml").is_file(),
                "SOUL.md": (profile_path / "SOUL.md").is_file(),
                ".env": (profile_path / ".env").is_file(),
                "mcp.json": (profile_path / "mcp.json").is_file(),
                "cron/jobs.json": (profile_path / "cron" / "jobs.json").is_file(),
            },
            "pid_marker": marker,
            "live_cmdline_verified": live_cmdline_verified,
            "recent_logs": tail_file(self.log_path(record.profile_path), max_bytes=max_log_bytes),
        }

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

    def _read_pid_marker(self, profile_path: str) -> dict[str, object]:
        path = self.pid_marker_path(profile_path)
        if not path.exists():
            return {"exists": False}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"exists": True, "valid": False, "error": str(exc)}
        if not isinstance(payload, dict):
            return {"exists": True, "valid": False, "error": "pid marker must be a JSON object"}
        safe_payload: dict[str, object] = {"exists": True, "valid": True}
        for key in ("pid", "argv", "started_at"):
            if key in payload:
                safe_payload[key] = payload[key]
        return safe_payload

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
        if not live_argv:
            return False
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

    def _poll_startup(self, process: PopenLike) -> int | None:
        returncode = process.poll()
        if returncode is not None or self.startup_grace_seconds <= 0:
            return returncode

        deadline = time.monotonic() + self.startup_grace_seconds
        while time.monotonic() < deadline:
            time.sleep(min(0.01, max(deadline - time.monotonic(), 0)))
            returncode = process.poll()
            if returncode is not None:
                return returncode
        return process.poll()


def _read_process_cmdline(pid: int) -> list[str] | None:
    system = platform.system()
    if system == "Linux":
        return _read_linux_cmdline(pid)
    if system == "Darwin":
        return _read_darwin_cmdline(pid)
    return None


def _read_linux_cmdline(pid: int, proc_root: Path = Path("/proc")) -> list[str]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def _read_darwin_cmdline(pid: int) -> list[str] | None:
    try:
        completed = subprocess.run(  # nosec B603
            ["/bin/ps", "-p", str(pid), "-o", "command="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return []
    command = completed.stdout.strip()
    if not command:
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return None


def _cmdline_matches_expected(live_argv: list[str], expected_argv: list[str]) -> bool:
    if live_argv == expected_argv:
        return True
    return len(live_argv) == len(expected_argv) + 1 and live_argv[1:] == expected_argv
