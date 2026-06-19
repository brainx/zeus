from __future__ import annotations

import os
import subprocess  # nosec B404
from pathlib import Path

from zeus.envfile import parse_env_text
from zeus.models import ID_RE

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
        env["HERMES_HOME"] = str(self.hermes_root)
        env.update(_load_profile_env(self.hermes_root / "profiles" / bot_id / ".env"))
        return [self.hermes_bin, "-p", bot_id, *args], env

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
