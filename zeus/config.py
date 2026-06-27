from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from zeus.envfile import parse_env_text


def load_dotenv(path: Path = Path(".env")) -> dict[str, str]:
    if not path.exists():
        return {}
    return parse_env_text(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    hermes_root: Path
    database_path: Path
    hermes_bin: str
    host: str
    port: int
    api_key: str | None
    allow_unauth_reads: bool
    stop_kill_after_timeout: bool

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        merged: dict[str, str] = load_dotenv()
        merged.update(dict(os.environ if env is None else env))
        state_dir = Path(merged.get("ZEUS_STATE_DIR", ".zeus")).resolve()
        return cls(
            state_dir=state_dir,
            hermes_root=state_dir / "hermes",
            database_path=state_dir / "zeus.db",
            hermes_bin=merged.get("ZEUS_HERMES_BIN", "hermes"),
            host=merged.get("ZEUS_HOST", "127.0.0.1"),
            port=int(merged.get("ZEUS_PORT", "4311")),
            api_key=merged.get("ZEUS_API_KEY") or None,
            allow_unauth_reads=merged.get("ZEUS_ALLOW_UNAUTH_READS") == "1",
            stop_kill_after_timeout=merged.get("ZEUS_STOP_KILL_AFTER_TIMEOUT") == "1",
        )

    def ensure_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.hermes_root.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "logs").mkdir(parents=True, exist_ok=True)
