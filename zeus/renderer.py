from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zeus.envfile import dump_env
from zeus.models import BotCreateRequest, BotRecord, HermesTemplate


def _dump_yaml(value: Any, indent: int = 0) -> str:
    spaces = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                lines.append(f"{spaces}{key}:")
                lines.append(_dump_yaml(child, indent + 2).rstrip())
            else:
                lines.append(f"{spaces}{key}: {_yaml_scalar(child)}")
        return "\n".join(lines) + "\n"
    if isinstance(value, list):
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{spaces}-")
                lines.append(_dump_yaml(child, indent + 2).rstrip())
            else:
                lines.append(f"{spaces}- {_yaml_scalar(child)}")
        return "\n".join(lines) + "\n"
    return f"{spaces}{_yaml_scalar(value)}\n"


def _yaml_scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


class ProfileRenderer:
    def __init__(self, hermes_root: Path | str) -> None:
        self.hermes_root = Path(hermes_root)

    def render(self, request: BotCreateRequest, template: HermesTemplate) -> BotRecord:
        profile = self.hermes_root / "profiles" / request.bot_id
        profile.mkdir(parents=True, exist_ok=True)
        (profile / "cron").mkdir(exist_ok=True)
        (profile / "logs").mkdir(exist_ok=True)
        (profile / "skills").mkdir(exist_ok=True)

        (profile / "SOUL.md").write_text(template.soul.rstrip() + "\n", encoding="utf-8")
        (profile / "config.yaml").write_text(
            _dump_yaml(template.hermes.to_config()),
            encoding="utf-8",
        )
        env_path = profile / ".env"
        env_path.write_text(dump_env(template.hermes.required_env, request.env), encoding="utf-8")
        env_path.chmod(0o600)
        (profile / "mcp.json").write_text(
            json.dumps(template.mcp, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (profile / "cron" / "jobs.json").write_text(
            json.dumps(template.cron, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        now = datetime.now(UTC)
        return BotRecord(
            bot_id=request.bot_id,
            template_id=template.id,
            display_name=request.display_name or template.name,
            profile_path=str(profile),
            restart_policy=request.restart_policy,
            restart_backoff_seconds=request.restart_backoff_seconds,
            restart_max_attempts=request.restart_max_attempts,
            created_at=now,
            updated_at=now,
        )
