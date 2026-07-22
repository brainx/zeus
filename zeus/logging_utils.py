from __future__ import annotations

from pathlib import Path

from zeus.private_io import read_private_tail
from zeus.sanitization import redact_secrets


def tail_file(path: Path, max_bytes: int = 20_000) -> str:
    data = read_private_tail(path, max_bytes)
    return redact_secrets(data.decode("utf-8", errors="replace"))
