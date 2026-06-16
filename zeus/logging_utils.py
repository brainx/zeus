from __future__ import annotations

import re
from pathlib import Path

SECRET_LINE_RE = re.compile(r"(?P<name>[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD))=(?P<value>[^\s]+)")


def redact_secrets(text: str) -> str:
    return SECRET_LINE_RE.sub(lambda match: f"{match.group('name')}=[redacted]", text)


def tail_file(path: Path, max_bytes: int = 20_000) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes))
        return redact_secrets(handle.read().decode("utf-8", errors="replace"))
