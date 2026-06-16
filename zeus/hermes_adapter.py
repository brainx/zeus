from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from zeus.models import ID_RE


ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")


def _load_profile_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if separator != "=" or not ENV_KEY_RE.match(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


class HermesAdapter:
    def __init__(self, hermes_bin: str, hermes_root: Path | str) -> None:
        self.hermes_bin = hermes_bin
        self.hermes_root = Path(hermes_root)

    def command(self, bot_id: str, *args: str) -> tuple[list[str], dict[str, str]]:
        if not ID_RE.match(bot_id):
            raise ValueError(f"invalid bot id: {bot_id}")
        env = os.environ.copy()
        env["HERMES_HOME"] = str(self.hermes_root)
        env.update(_load_profile_env(self.hermes_root / "profiles" / bot_id / ".env"))
        return [self.hermes_bin, "-p", bot_id, *args], env

    def run(self, bot_id: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        argv, env = self.command(bot_id, *args)
        return subprocess.run(
            argv,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
