from __future__ import annotations

import errno
import os
import platform
import re
import shlex
import shutil
import subprocess  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import cast

PidAliveFn = Callable[[int], bool]
CmdlineReader = Callable[[int], list[str] | None]
ProcStartFingerprintReader = Callable[[int], str | None]

_SubprocessRun = Callable[..., subprocess.CompletedProcess[str]]
_PYTHON_INTERPRETER_RE = re.compile(r"^python(?:\d+(?:\.\d+)?)?$")


@dataclass(frozen=True)
class CommandCheck:
    verified: bool
    reason: str
    classification: str | None = None


class PidState(Enum):
    alive = "alive"
    dead = "dead"
    unknown = "unknown"


def read_process_cmdline(
    pid: int,
    *,
    system: str | None = None,
    run_process: _SubprocessRun | None = None,
) -> list[str] | None:
    current_system = platform.system() if system is None else system
    if current_system == "Linux":
        return read_linux_cmdline(pid)
    if current_system == "Darwin":
        if run_process is None:
            return read_darwin_cmdline(pid)
        return read_darwin_cmdline(pid, run_process=run_process)
    return None


def read_linux_cmdline(pid: int, proc_root: Path = Path("/proc")) -> list[str]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def read_darwin_cmdline(
    pid: int,
    *,
    run_process: _SubprocessRun | None = None,
) -> list[str] | None:
    runner = _subprocess_runner(run_process)
    try:
        completed = runner(
            ["/bin/ps", "-p", str(pid), "-o", "command="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return []
    command = completed.stdout.strip()
    if not command:
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return None


def read_process_start_fingerprint(
    pid: int,
    *,
    system: str | None = None,
    run_process: _SubprocessRun | None = None,
) -> str | None:
    current_system = platform.system() if system is None else system
    if current_system == "Darwin":
        if run_process is None:
            return read_darwin_process_start_fingerprint(pid)
        return read_darwin_process_start_fingerprint(pid, run_process=run_process)
    if current_system != "Linux":
        return None
    return read_linux_process_start_fingerprint(pid)


def read_darwin_process_start_fingerprint(
    pid: int,
    *,
    run_process: _SubprocessRun | None = None,
) -> str | None:
    runner = _subprocess_runner(run_process)
    try:
        completed = runner(
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    started = " ".join(completed.stdout.split())
    return f"darwin:ps-lstart:{started}" if started else None


def read_linux_process_start_fingerprint(
    pid: int,
    proc_root: Path = Path("/proc"),
) -> str | None:
    try:
        stat = (proc_root / str(pid) / "stat").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    try:
        fields = stat.rsplit(") ", 1)[1].split()
    except IndexError:
        return None
    if len(fields) < 20:
        return None
    return f"linux:/proc-starttime:{fields[19]}"


def pid_state(pid: int, *, pid_alive_fn: PidAliveFn | None = None) -> PidState:
    try:
        if pid_alive_fn is not None:
            return PidState.alive if pid_alive_fn(pid) else PidState.dead
        os.kill(pid, 0)
    except ProcessLookupError:
        return PidState.dead
    except PermissionError:
        return PidState.unknown
    except OSError as exc:
        return PidState.dead if exc.errno == errno.ESRCH else PidState.unknown
    return PidState.alive


def valid_process_start_fingerprint(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 512


def process_start_fingerprint_required(system: str) -> bool:
    return system in {"Darwin", "Linux"}


def process_start_identity_error(
    marker_fingerprint: object,
    live_fingerprint: str | None,
    *,
    fingerprint_required: bool,
) -> str | None:
    if fingerprint_required:
        marker_is_valid = valid_process_start_fingerprint(marker_fingerprint)
        live_is_valid = valid_process_start_fingerprint(live_fingerprint)
        if not marker_is_valid or not live_is_valid:
            return "process start fingerprint is unavailable"
        if marker_fingerprint != live_fingerprint:
            return "process start fingerprint does not match"
    elif live_fingerprint and marker_fingerprint != live_fingerprint:
        return "process start fingerprint does not match"
    elif marker_fingerprint and live_fingerprint != marker_fingerprint:
        return "process start fingerprint is unavailable"
    return None


def verify_gateway_command(
    argv: list[str],
    bot_id: str,
    trusted_hermes_bin: str | set[str] | None,
    *,
    require_trusted_path: bool,
) -> CommandCheck:
    if not argv:
        return CommandCheck(False, "live-cmdline-missing")
    classification = "direct-hermes"
    hermes_command = argv[0]
    args = argv[1:]
    if len(argv) >= 2 and looks_like_python_interpreter(argv[0]):
        classification = "python-script-wrapper"
        hermes_command = argv[1]
        args = argv[2:]
    if len(args) != 4 or args.count("-p") != 1 or args[0] != "-p":
        return CommandCheck(False, "wrong-command-intent", classification)
    if args[1] != bot_id:
        return CommandCheck(False, "wrong-bot-id", classification)
    if args[2:] != ["gateway", "run"]:
        return CommandCheck(False, "wrong-command-intent", classification)
    if require_trusted_path:
        resolved_command = resolve_executable(hermes_command)
        if isinstance(trusted_hermes_bin, str):
            trusted_hermes_bins = {trusted_hermes_bin}
        else:
            trusted_hermes_bins = trusted_hermes_bin or set()
        if not trusted_hermes_bins or resolved_command not in trusted_hermes_bins:
            return CommandCheck(False, "untrusted-executable", classification)
    return CommandCheck(True, "ok", classification)


def looks_like_python_interpreter(command: str) -> bool:
    return bool(_PYTHON_INTERPRETER_RE.fullmatch(Path(command).name.lower()))


def resolve_executable(command: str, path: str | None = None) -> str | None:
    if not command:
        return None
    candidate = command if "/" in command else shutil.which(command, path=path)
    if candidate is None:
        return None
    try:
        return str(Path(candidate).expanduser().resolve())
    except (OSError, RuntimeError):
        return str(Path(candidate).expanduser().absolute())


def trusted_hermes_paths(command: str) -> set[str]:
    resolved = resolve_executable(command)
    if resolved is None:
        return set()
    paths = {resolved}
    delegated = resolve_launcher_exec_target(resolved)
    if delegated is not None:
        paths.add(delegated)
    return paths


def resolve_launcher_exec_target(command: str) -> str | None:
    path = Path(command)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None
    if not text.startswith("#!"):
        return None
    for line in text.splitlines()[1:20]:
        stripped = line.strip()
        if not stripped.startswith("exec "):
            continue
        try:
            parts = shlex.split(stripped)
        except ValueError:
            continue
        if len(parts) < 2 or parts[0] != "exec":
            continue
        target = parts[1]
        if "/" not in target:
            continue
        resolved = resolve_executable(target)
        if resolved and Path(resolved).name == "hermes":
            return resolved
    return None


def safe_command_shape(argv: list[str]) -> str:
    if not argv:
        return "empty"
    classification = "direct-hermes"
    args = argv[1:]
    if len(argv) >= 2 and looks_like_python_interpreter(argv[0]):
        classification = "python-script-wrapper"
        args = argv[2:]
    if len(args) == 4 and args[0] == "-p" and args[2:] == ["gateway", "run"]:
        return f"{classification} hermes -p <bot> gateway run"
    return f"{classification} unrecognized"


def _subprocess_runner(run_process: _SubprocessRun | None) -> _SubprocessRun:
    if run_process is not None:
        return run_process
    return cast(_SubprocessRun, subprocess.run)
