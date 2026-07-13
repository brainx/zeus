from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

from zeus.envfile import parse_env_text
from zeus.gateway_launcher import command_fingerprint
from zeus.models import ID_RE
from zeus.readiness import ReadinessProbe

SAFE_ENV_DEFAULTS = [
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
]


def _load_profile_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return parse_env_text(path.read_text(encoding="utf-8"))


def _base_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for name in SAFE_ENV_DEFAULTS:
        value = os.environ.get(name)
        if value:
            env[name] = value
    passthrough = os.environ.get("ZEUS_ENV_PASSTHROUGH", "")
    for raw_name in passthrough.split(","):
        name = raw_name.strip()
        if not name:
            continue
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    return env


class HermesAdapter:
    def __init__(self, hermes_bin: str, hermes_root: Path | str) -> None:
        self.hermes_bin = hermes_bin
        self.hermes_root = Path(hermes_root)

    def command(self, bot_id: str, *args: str) -> tuple[list[str], dict[str, str]]:
        if not ID_RE.match(bot_id):
            raise ValueError(f"invalid bot id: {bot_id}")
        env = _base_env()
        env.update(_load_profile_env(self.hermes_root / "profiles" / bot_id / ".env"))
        env["HERMES_HOME"] = str(self.hermes_root)
        return [self.hermes_bin, "-p", bot_id, *args], env

    def launcher_command(self, payload_fd: int, ack_fd: int) -> list[str]:
        if (
            type(payload_fd) is not int
            or type(ack_fd) is not int
            or payload_fd < 3
            or ack_fd < 3
            or payload_fd == ack_fd
        ):
            raise ValueError("launcher file descriptors must be distinct inherited descriptors")
        return [
            sys.executable,
            "-m",
            "zeus.gateway_launcher",
            str(payload_fd),
            str(ack_fd),
        ]

    def launcher_payload(
        self,
        bot_id: str,
        *,
        operation_id: str,
        desired_revision: int,
        readiness_probe: ReadinessProbe | None,
    ) -> dict[str, object]:
        argv, env = self.command(bot_id, "gateway", "run")
        resolved_hermes = self._resolved_hermes_bin(env)
        exec_argv = [resolved_hermes, *argv[1:]]
        profile_path = self.hermes_root / "profiles" / bot_id
        marker_path = profile_path / "logs" / "zeus-gateway.pid.json"
        probe_payload: dict[str, object] | None = None
        if readiness_probe is not None:
            probe_payload = {
                "url": readiness_probe.url,
                "expected_status": readiness_probe.expected_status,
                "expected_platform": readiness_probe.expected_platform,
                "timeout_seconds": readiness_probe.timeout_seconds,
                "interval_seconds": readiness_probe.interval_seconds,
            }
        marker: dict[str, object] = {
            "schema": 3,
            "bot_id": bot_id,
            "component": "gateway",
            "action": "run",
            "operation_id": operation_id,
            "desired_revision": desired_revision,
            "argv": exec_argv,
            "resolved_hermes_bin": resolved_hermes,
            "command_fingerprint": command_fingerprint(exec_argv),
            "readiness_probe": probe_payload,
        }
        return {
            "profile_path": str(profile_path),
            "marker_path": str(marker_path),
            "marker": marker,
            "argv": exec_argv,
            "env": env,
        }

    def _resolved_hermes_bin(self, env: dict[str, str]) -> str:
        candidate = (
            self.hermes_bin
            if os.path.isabs(self.hermes_bin)
            else shutil.which(self.hermes_bin, path=env.get("PATH"))
        )
        if candidate is None:
            raise FileNotFoundError(f"Hermes executable not found: {self.hermes_bin}")
        return str(Path(candidate).expanduser().resolve(strict=True))

    def run(self, bot_id: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        argv, env = self.command(bot_id, *args)
        # Zeus executes the configured Hermes binary with validated argv and shell=False.
        return subprocess.run(  # nosec B603
            argv,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
