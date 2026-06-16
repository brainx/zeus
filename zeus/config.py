from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(path: Path = Path(".env")) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip().strip('"').strip("'")
    return values


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    hermes_root: Path
    database_path: Path
    hermes_bin: str
    host: str
    port: int
    api_key: str | None

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
        )

    def ensure_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.hermes_root.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "logs").mkdir(parents=True, exist_ok=True)
