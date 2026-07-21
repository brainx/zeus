from __future__ import annotations

import re
from pathlib import Path

from zeus.private_io import read_private_tail

SECRET_KV_RE = re.compile(
    r"""(?ix)
    (?P<prefix>["']?)
    (?P<name>[A-Z0-9_.-]*(?:API[_-]?KEY|KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_.-]*)
    (?P=prefix)
    (?P<sep>\s*[:=]\s*)
    (?P<value>
        "(?:[^"\\]|\\.)*" |
        '(?:[^'\\]|\\.)*' |
        [^\s,}]+
    )
    """
)
BEARER_RE = re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)([A-Za-z0-9._~+/=-]+)")


def redact_secrets(text: str) -> str:
    text = BEARER_RE.sub(r"\1[redacted]", text)
    return SECRET_KV_RE.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('name')}{match.group('prefix')}"
            f"{match.group('sep')}[redacted]"
        ),
        text,
    )


def tail_file(path: Path, max_bytes: int = 20_000) -> str:
    data = read_private_tail(path, max_bytes)
    return redact_secrets(data.decode("utf-8", errors="replace"))
