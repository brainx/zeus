from __future__ import annotations

from pathlib import Path

from zeus.private_io import read_private_tail
from zeus.sanitization import _escape_control_characters, redact_secrets


def tail_file(path: Path, max_bytes: int = 20_000) -> str:
    """Bounded log tail with secrets and terminal escape sequences neutralized.

    Log content includes child-process (LLM-driven) output, so C0/C1 control
    characters are escaped before the tail is printed to an operator terminal.
    """
    data = read_private_tail(path, max_bytes)
    return redact_secrets(_escape_control_characters(data.decode("utf-8", errors="replace")))
