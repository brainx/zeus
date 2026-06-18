from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Mapping

ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_UNQUOTED_VALUE_RE = re.compile(r"^[A-Za-z0-9_./:@%+=,-]+$")


def dump_env(required_names: Iterable[str], provided: Mapping[str, str]) -> str:
    lines: list[str] = []
    for name in required_names:
        if provided.get(name):
            lines.append(f"{name}={quote_env_value(provided[name])}")
        else:
            lines.append(f"# {name}=")
    return "\n".join(lines) + ("\n" if lines else "")


def quote_env_value(value: str) -> str:
    if "\0" in value:
        raise ValueError("env values cannot contain NUL bytes")
    if _UNQUOTED_VALUE_RE.match(value):
        return value
    return json.dumps(value, ensure_ascii=True)


def parse_env_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, separator, raw_value = line.partition("=")
        key = key.strip()
        if separator != "=" or not ENV_KEY_RE.match(key):
            continue
        values[key] = parse_env_value(raw_value.strip())
    return values


def parse_env_value(raw_value: str) -> str:
    if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] == '"':
        try:
            parsed = json.loads(raw_value)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(parsed, str):
                return parsed
    if raw_value.startswith(("'", '"')):
        try:
            parts = shlex.split(raw_value, posix=True)
        except ValueError:
            parts = []
        if len(parts) == 1:
            return parts[0]
    return raw_value
