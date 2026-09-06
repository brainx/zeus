"""Disposable Linux service acceptance driver; never targets an operator state tree."""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any

READ_ROWS = """
import json, sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=2)) as conn:
    conn.row_factory = sqlite3.Row
    print(json.dumps([dict(row) for row in conn.execute(sys.argv[2], json.loads(sys.argv[3]))]))
"""

BACKUP_DATABASE = """
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)) as source:
    with closing(sqlite3.connect(sys.argv[2])) as target:
        source.backup(target)
        if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("backup integrity failed")
"""


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_root(root: Path, uid: int) -> None:
    require(root.parent == Path("/run"), "temporary root must be directly beneath /run")
    require(re.fullmatch(r"zeus-service-recovery\.[A-Za-z0-9]{8}", root.name), "invalid root name")
    metadata = root.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0, "root is not an owned directory"
    )
    require(os.getuid() == 0 and uid > 0, "root driver and non-root service identity are required")


def render_unit(source: str, root: Path, user: str, group: str, port: int) -> str:
    replacements = {
        "User=zeus": f"User={user}",
        "Group=zeus": f"Group={group}",
        "WorkingDirectory=/opt/zeus": f"WorkingDirectory={root}/work",
        "/opt/zeus/.venv": f"{root}/venv",
        "/etc/zeus/zeus.env": f"{root}/service.env",
        "/var/lib/zeus": f"{root}/state",
        "ZEUS_PORT=4311": f"ZEUS_PORT={port}",
        "zeus-api.service": f"{root.name}-api.service",
        "zeus-reconcile.service": f"{root.name}-reconcile.service",
        "OnBootSec=30s": "OnActiveSec=1s",
        "OnUnitActiveSec=30s": "OnUnitActiveSec=1s",
        "AccuracySec=5s": "AccuracySec=100ms",
    }
    for original, replacement in replacements.items():
        source = source.replace(original, replacement)
    require("/opt/zeus" not in source and "/var/lib/zeus" not in source, "unmapped production path")
    return f"# Disposable Zeus recovery drill: {root}\n{source}"


def wait_for(check: Callable[[], object], description: str, seconds: float = 20) -> Any:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise RuntimeError(f"timed out: {description}")


def require_plain_tree(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "snapshot refused a link or special file")


class Drill:
    def __init__(self, root: Path, repo: Path, uid: int, gid: int) -> None:
        validate_root(root, uid)
        self.root, self.repo, self.uid, self.gid = root, repo, uid, gid
        self.user = pwd.getpwuid(uid).pw_name
        self.state = root / "state"
        self.database = self.state / "zeus.db"
        self.fake = root / "venv/bin/zeus-fake-hermes"
        self.api = f"{root.name}-api.service"
        self.reconcile = f"{root.name}-reconcile.service"
        self.timer = f"{root.name}-reconcile.timer"
        self.units = (self.timer, self.reconcile, self.api)
        self.ready = threading.Event()
        self.key = ""
        self.port = 0

    def command(
        self, *argv: str, check: bool = True, timeout: float = 25, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv, check=check, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )

    def systemctl(self, *args: str, check: bool = True) -> str:
        return self.command("systemctl", *args, check=check).stdout.strip()

    def cli(self, *args: str) -> dict[str, Any]:
        result = self.command(
            "runuser",
            "--user",
            self.user,
            "--",
            "env",
            "-i",
            f"PATH={self.root}/venv/bin:/usr/bin:/bin",
            f"HOME={self.root}/work",
            f"ZEUS_STATE_DIR={self.state}",
            f"ZEUS_HERMES_BIN={self.fake}",
            "ZEUS_SQLITE_SYNCHRONOUS=FULL",
            str(self.root / "venv/bin/zeus"),
            *args,
            cwd=self.root / "work",
        )
        return json.loads(result.stdout)

    def database_command(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        # Read-only WAL connections can create sidecars. Keep every connection
        # under the service identity so observation cannot break its permissions.
        return self.command(
            "runuser",
            "--user",
            self.user,
            "--",
            str(self.root / "venv/bin/python"),
            "-I",
            "-c",
            script,
            str(self.database),
            *args,
            timeout=10,
            cwd=self.root / "work",
        )

    def rows(self, sql: str, args: tuple[object, ...] = ()) -> list[dict[str, Any]]:
        return json.loads(self.database_command(READ_ROWS, sql, json.dumps(args)).stdout)

    def bot(self) -> dict[str, Any]:
        return self.rows("SELECT * FROM bots WHERE bot_id = 'recovery-bot'")[0]

    def request(self, method: str, path: str, timeout: float = 2) -> Any:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            connection.request(
                method, path, headers={"x-zeus-api-key": self.key, "X-Request-ID": "a" * 32}
            )
            response = connection.getresponse()
            body = response.read(128 * 1024)
            require(response.status == 200, f"unexpected API response: {response.status}")
            return json.loads(body)
        finally:
            connection.close()

    def api_ready(self) -> bool:
        try:
            return self.request("GET", "/ready")["status"] == "ready"
        except (OSError, http.client.HTTPException, RuntimeError):
            return False

    def process_identity(self, pid: int) -> str | None:
        try:
            process = Path("/proc") / str(pid)
            if process.stat().st_uid != self.uid:
                return None
            argv = (process / "cmdline").read_bytes().split(b"\0")
            if os.fsencode(self.fake) not in argv or b"recovery-bot" not in argv:
                return None
            fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
            return None if fields[0] == "Z" else f"linux:/proc-starttime:{fields[19]}"
        except (OSError, IndexError):
            return None

    def processes(self) -> dict[int, str]:
        result = {}
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                fingerprint = self.process_identity(int(entry.name))
                if fingerprint is not None:
                    result[int(entry.name)] = fingerprint
        return result

    def assert_converged(self) -> int:
        status = self.request("GET", "/bots/recovery-bot/status")
        record = self.bot()
        require(
            status["status"] == "running" and record["status"] == "running",
            "gateway is not running",
        )
        require(
            record["desired_state"] == "running" and record["pending_operation_id"] is None,
            "intent did not converge",
        )
        marker = json.loads(
            (Path(record["profile_path"]) / "logs/zeus-gateway.pid.json").read_text()
        )
        pid = record["pid"]
        require(
            self.processes() == {pid: marker["proc_start_fingerprint"]},
            "gateway ownership is not unique",
        )
        require(
            marker["pid"] == pid and marker["desired_revision"] == record["desired_revision"],
            "marker generation mismatch",
        )
        event = self.rows(
            "SELECT * FROM lifecycle_events WHERE event_id = ?", (record["last_event_id"],)
        )[0]
        require(
            event["bot_id"] == "recovery-bot" and event["pid_after"] == pid,
            "projection lost ledger correlation",
        )
        return pid

    def install_units(self, health_port: int) -> None:
        import grp
        import secrets

        self.key = secrets.token_hex(24)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        for name in ("state", "work"):
            directory = self.root / name
            directory.mkdir(mode=0o700)
            os.chown(directory, self.uid, self.gid)
        environment = {
            "PATH": f"{self.root}/venv/bin:/usr/bin:/bin",
            "HOME": str(self.root / "work"),
            "ZEUS_STATE_DIR": str(self.state),
            "ZEUS_HERMES_BIN": str(self.fake),
            "ZEUS_API_KEY": self.key,
            "ZEUS_READINESS_TIMEOUT_SECONDS": "60",
            "ZEUS_ENV_PASSTHROUGH": "API_SERVER_ENABLED,API_SERVER_HOST,API_SERVER_PORT",
            "API_SERVER_ENABLED": "1",
            "API_SERVER_HOST": "127.0.0.1",
            "API_SERVER_PORT": str(health_port),
        }
        (self.root / "service.env").write_text(
            "".join(f"{key}={value}\n" for key, value in environment.items())
        )
        for original, unit in zip(
            ("zeus-api.service", "zeus-reconcile.service", "zeus-reconcile.timer"),
            (self.api, self.reconcile, self.timer),
            strict=True,
        ):
            source = (self.repo / "systemd" / original).read_text()
            content = render_unit(
                source, self.root, self.user, grp.getgrgid(self.gid).gr_name, self.port
            )
            with (Path("/run/systemd/system") / unit).open("x") as stream:
                stream.write(content)
            (Path("/run/systemd/system") / unit).chmod(0o644)
        self.systemctl("daemon-reload")

    def cleanup(self) -> None:
        owned = []
        for unit in self.units:
            path = Path("/run/systemd/system") / unit
            if path.exists() or path.is_symlink():
                require(not path.is_symlink() and path.is_file(), "cleanup refused replaced unit")
                require(path.stat().st_uid == 0, "cleanup refused non-root unit")
                require(
                    path.read_text().startswith(f"# Disposable Zeus recovery drill: {self.root}\n"),
                    "cleanup refused unowned unit",
                )
                owned.append(unit)
        if owned:
            self.systemctl("stop", *owned, check=False)
        if self.database.is_file():
            # Prefer Zeus's full marker/lock checks; partial startup can require
            # the narrower fixture-only fallback below.
            with contextlib.suppress(subprocess.CalledProcessError, subprocess.TimeoutExpired):
                self.cli("bot", "stop", "recovery-bot", "--json")
        self.terminate_owned_gateways()
        for unit in owned:
            active = self.systemctl("show", unit, "--property=ActiveState", "--value")
            require(active in {"inactive", "failed"}, "unit is still active")
            (Path("/run/systemd/system") / unit).unlink()
        if owned:
            self.systemctl("daemon-reload")
            self.systemctl("reset-failed", *owned, check=False)

    def terminate_owned_gateways(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for pid, fingerprint in self.processes().items():
                if self.process_identity(pid) == fingerprint:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(pid, sig)
            deadline = time.monotonic() + 3
            while self.processes() and time.monotonic() < deadline:
                time.sleep(0.1)
        require(not self.processes(), "owned gateway cleanup failed")

    def run(self) -> None:
        import zeus

        require(
            Path(zeus.__file__).is_relative_to(self.root / "venv"),
            "Zeus imported outside installed wheel",
        )
        require(zeus.__version__ == version("zeus-hermes-orchestrator"), "wheel version mismatch")
        ready = self.ready

        class Health(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                payload = b'{"status":"ok","platform":"hermes-agent"}'
                self.send_response(200 if ready.is_set() else 503)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Health) as health:
            worker = threading.Thread(target=health.serve_forever, daemon=True)
            worker.start()
            try:
                self.install_units(health.server_port)
                self.cli(
                    "bot",
                    "create",
                    "recovery-bot",
                    "--template",
                    "coding-bot",
                    "--restart-policy",
                    "on-failure",
                    "--restart-backoff-seconds",
                    "0",
                    "--json",
                )
                self.systemctl("start", self.api)
                wait_for(self.api_ready, "API readiness")
                initial_api_pid = self.systemctl("show", self.api, "--property=MainPID", "--value")

                def blocked_start() -> None:
                    with contextlib.suppress(OSError, http.client.HTTPException):
                        self.request(
                            "POST", "/bots/recovery-bot/start?wait=true&timeout=60", timeout=65
                        )

                request_worker = threading.Thread(target=blocked_start, daemon=True)
                request_worker.start()
                wait_for(
                    lambda: self.bot()["pending_operation_id"] and self.processes(),
                    "persisted start intent with a live gateway",
                )
                operation = self.bot()["pending_operation_id"]
                initial_gateways = self.processes()
                self.systemctl("kill", "--kill-who=main", "--signal=SIGKILL", self.api)
                request_worker.join(timeout=5)
                require(not request_worker.is_alive(), "interrupted API request did not finish")
                wait_for(
                    lambda: (
                        self.api_ready()
                        and self.systemctl("show", self.api, "--property=MainPID", "--value")
                        != initial_api_pid
                    ),
                    "automatic API restart",
                )
                require(
                    self.bot()["pending_operation_id"] == operation,
                    "interruption lost pending intent",
                )
                wait_for(
                    lambda: (
                        not any(
                            self.process_identity(pid) == fp for pid, fp in initial_gateways.items()
                        )
                    ),
                    "API cgroup gateway cleanup",
                )
                self.ready.set()
                self.systemctl("start", self.reconcile)
                recovered_pid = self.assert_converged()
                require(
                    self.systemctl("show", self.reconcile, "--property=ActiveState", "--value")
                    == "inactive",
                    "one-shot did not finish",
                )
                events = self.rows(
                    "SELECT action FROM lifecycle_events WHERE operation_id = ? ORDER BY event_id",
                    (operation,),
                )
                require(
                    [row["action"] for row in events].count("bot.start.intent") == 1,
                    "start intent duplicated",
                )
                require(
                    [row["action"] for row in events].count("bot.start.complete") == 1,
                    "recovery completion lost or duplicated",
                )
                count = self.rows(
                    "SELECT count(*) AS count FROM reconcile_runs WHERE outcome = 'succeeded'"
                )[0]["count"]
                self.systemctl("start", self.timer)
                wait_for(
                    lambda: (
                        self.rows(
                            "SELECT count(*) AS count FROM reconcile_runs "
                            "WHERE outcome = 'succeeded'"
                        )[0]["count"]
                        >= count + 2
                    ),
                    "two completed timer passes",
                    seconds=15,
                )
                require(
                    self.assert_converged() == recovered_pid,
                    "timer duplicated or replaced healthy gateway",
                )
                self.systemctl("stop", self.timer, self.reconcile, self.api)
                recovered_identity = self.process_identity(recovered_pid)
                require(recovered_identity, "stopping reconciliation killed its gateway")
                self.backup_restore()
                require(
                    self.bot()["desired_state"] == "stopped" and not self.processes(),
                    "restored stopped snapshot launched a gateway",
                )
                self.systemctl("start", self.api)
                wait_for(self.api_ready, "restored API readiness")
                self.request("POST", "/bots/recovery-bot/start?wait=true&timeout=10", timeout=15)
                for _ in range(2):
                    self.systemctl("start", self.reconcile)
                restored_pid = self.assert_converged()
                require(
                    (restored_pid, self.process_identity(restored_pid))
                    != (recovered_pid, recovered_identity),
                    "restore reused a stale gateway generation",
                )
                self.cli("bot", "stop", "recovery-bot", "--json")
                wait_for(lambda: not self.processes(), "exact-ownership gateway stop")
                require(
                    self.bot()["desired_state"] == "stopped"
                    and self.bot()["pending_operation_id"] is None,
                    "stop did not converge",
                )
                print(
                    json.dumps(
                        {
                            "result": "passed",
                            "version": zeus.__version__,
                            "pending_intent_recovered": True,
                            "timer_preserved_gateway": True,
                            "backup_restored": True,
                            "owned_gateway_stopped": True,
                        },
                        sort_keys=True,
                    )
                )
            finally:
                health.shutdown()
                worker.join(timeout=5)

    def backup_restore(self) -> None:
        require(self.state == self.root / "state", "restore refused non-disposable state")
        require_plain_tree(self.state)
        self.cli("bot", "stop", "recovery-bot", "--json")
        wait_for(lambda: not self.processes(), "gateway stop before backup")
        backup = self.root / "backup"
        backup.mkdir(mode=0o700)
        os.chown(backup, self.uid, self.gid)
        self.database_command(BACKUP_DATABASE, str(backup / "zeus.db"))
        shutil.copytree(
            self.state, backup / "state", ignore=shutil.ignore_patterns("zeus.db", "zeus.db-*")
        )
        profile = Path(self.bot()["profile_path"])
        names = ("config.yaml", ".env", "SOUL.md", "mcp.json", "cron/jobs.json")
        hashes = {name: hashlib.sha256((profile / name).read_bytes()).hexdigest() for name in names}
        ledger = [
            tuple(row.values())
            for row in self.rows("SELECT * FROM lifecycle_events ORDER BY event_id")
        ]
        require(
            self.state.parent == self.root and not self.state.is_symlink(),
            "restore refused non-disposable state",
        )
        self.state.rename(self.root / "retired-state")
        require(not self.state.exists(), "restore target must be fresh")
        require_plain_tree(backup)
        shutil.copytree(backup / "state", self.state)
        shutil.copy2(backup / "zeus.db", self.database)
        for path in (self.state, *self.state.rglob("*")):
            require(not path.is_symlink(), "restore refused a symlink")
            os.chown(path, self.uid, self.gid)
        require(
            hashes
            == {name: hashlib.sha256((profile / name).read_bytes()).hexdigest() for name in names},
            "restored profiles differ",
        )
        require(
            ledger
            == [
                tuple(row.values())
                for row in self.rows("SELECT * FROM lifecycle_events ORDER BY event_id")
            ],
            "restore changed lifecycle ledger",
        )
        require(
            self.rows("PRAGMA integrity_check")[0]["integrity_check"] == "ok",
            "restored database integrity failed",
        )


if __name__ == "__main__":
    require(len(sys.argv) == 6 and sys.argv[1] in {"run", "cleanup"}, "invalid drill arguments")
    drill = Drill(Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
    try:
        getattr(drill, sys.argv[1])()
    except subprocess.CalledProcessError as exc:
        print(
            f"service recovery command failed: {exc.cmd[0]} (exit {exc.returncode})",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
