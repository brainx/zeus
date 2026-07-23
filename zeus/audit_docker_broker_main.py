"""Executable entry point for the private audit Docker broker."""

from __future__ import annotations

import sys
from pathlib import Path

from zeus.audit_docker_broker import (
    AuditDockerBrokerError,
    invoke_audit_docker_broker,
)


def main(
    argv: list[str] | None = None,
    *,
    executable_path: Path | None = None,
) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    path = Path(sys.argv[0]) if executable_path is None else executable_path
    if not path.is_absolute():
        path = Path.cwd() / path
    state_path = path.parent / "state.json"
    try:
        result = invoke_audit_docker_broker(state_path, arguments)
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        result_code = 126
        stdout = b""
        stderr = b"audit Docker broker refused request\n"
    else:
        result_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    try:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()
    except (BrokenPipeError, OSError):
        return 126
    return result_code


if __name__ == "__main__":
    raise SystemExit(main())
