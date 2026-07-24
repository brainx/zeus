"""Non-mutating preflight checks for native repository audits."""

from __future__ import annotations

import fcntl
import inspect
import os
import selectors
import shutil
import signal
import subprocess  # nosec B404
import sys
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from zeus.audit_config import AuditConfigError, load_audit_config, validate_provider_selection
from zeus.audit_docker_broker import HERMES_VERSION
from zeus.audit_models import AuditConfig
from zeus.audit_process import (
    AuditProcessError,
    stop_process_group,
    wait_process_exit,
)
from zeus.audit_workspace import AuditWorkspace, RepositoryLocation
from zeus.config import Settings
from zeus.private_io import UnsafeFileError, inspect_private_directory

_VERSION_OUTPUT_BYTES = 4096
_VERSION_FIRST_LINE = f"Hermes Agent v{HERMES_VERSION} (2026.7.20)"
_PROCESS_CHUNK = 64 * 1024
_PROCESS_TERM_SECONDS = 0.2
_PROCESS_KILL_SECONDS = 0.2


@dataclass(frozen=True)
class AuditDoctorCheck:
    name: str
    ok: bool
    observation: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "ok": self.ok, "observation": self.observation}


@dataclass(frozen=True)
class AuditDoctorReport:
    checks: tuple[AuditDoctorCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {"checks": [check.to_dict() for check in self.checks], "ok": self.ok}

    def to_text(self) -> str:
        return "".join(
            f"{'ok' if check.ok else 'blocked'}\t{check.name}\t{check.observation}\n"
            for check in self.checks
        )


def _executable(name: str) -> Path | None:
    candidate = shutil.which(name)
    if candidate is None:
        return None
    try:
        resolved = Path(candidate).resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_absolute() and resolved.is_file() else None


def _command(argv: Sequence[str], *, deadline: float) -> tuple[bool, str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False, "overall audit deadline has expired"
    process: subprocess.Popen[bytes] | None = None
    returncode: int | None = None
    error: str | None = None
    try:
        process = subprocess.Popen(  # nosec B603
            tuple(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            error = "command exceeded its deadline"
        else:
            try:
                returncode = wait_process_exit(
                    process,
                    deadline=time.monotonic() + min(remaining, 30),
                )
            except subprocess.TimeoutExpired:
                error = "command exceeded its deadline"
    except (AuditProcessError, OSError, TypeError, ValueError):
        error = "command could not complete"
    finally:
        if process is not None and not _stop_process_group(process):
            error = "command process group cleanup could not be verified"
    if error is not None:
        return False, error
    return returncode == 0, "available" if returncode == 0 else "unavailable"


def _stop_process_group(process: subprocess.Popen[bytes]) -> bool:
    return stop_process_group(
        process,
        term_seconds=_PROCESS_TERM_SECONDS,
        kill_seconds=_PROCESS_KILL_SECONDS,
    )


def _bounded_version_process(
    executable: Path,
    *,
    deadline: float,
) -> tuple[int | None, bytes, bytes, str | None]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None, b"", b"", "overall audit deadline has expired"
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    returncode: int | None = None
    error: str | None = None
    try:
        process = subprocess.Popen(  # nosec B603
            (str(executable), "--version"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            shell=False,
            close_fds=True,
            start_new_session=True,
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            error = "version command pipes are unavailable"
        else:
            selector.register(process.stdout, selectors.EVENT_READ, stdout)
            selector.register(process.stderr, selectors.EVENT_READ, stderr)
            while selector.get_map() and error is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = "version command exceeded its deadline"
                    break
                events = selector.select(min(0.05, remaining))
                for key, _mask in events:
                    allowance = _VERSION_OUTPUT_BYTES + 1 - total
                    if allowance <= 0:
                        error = "version output exceeded its limit"
                        break
                    chunk = os.read(key.fd, min(_PROCESS_CHUNK, allowance))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > _VERSION_OUTPUT_BYTES:
                        error = "version output exceeded its limit"
                        break
                    key.data.extend(chunk)
            if error is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = "version command exceeded its deadline"
                else:
                    try:
                        returncode = wait_process_exit(process, deadline=deadline)
                    except subprocess.TimeoutExpired:
                        error = "version command exceeded its deadline"
    except (AuditProcessError, OSError, TypeError, ValueError):
        error = "version command could not complete"
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    with suppress(OSError):
                        stream.close()
            if not _stop_process_group(process):
                error = "version process group cleanup could not be verified"
    if error is None and returncode is None:
        error = "version command could not complete"
    return returncode, bytes(stdout), bytes(stderr), error


def _pinned_hermes_version(executable: Path, *, deadline: float) -> tuple[bool, str]:
    returncode, stdout, _stderr, error = _bounded_version_process(
        executable,
        deadline=deadline,
    )
    if error is not None:
        return False, error
    if returncode != 0:
        return False, "version command failed"
    try:
        output = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False, "version output was not valid UTF-8"
    if "\x00" in output:
        return False, "version output contained NUL"
    first_line = output.split("\n", 1)[0]
    if first_line != _VERSION_FIRST_LINE:
        return False, "version did not match the supported release"
    if len(stdout) > _VERSION_OUTPUT_BYTES:
        return False, "version output exceeded its limit"
    return True, f"version {HERMES_VERSION}"


def _broker_isolation_supported() -> bool:
    required_flags = (
        ("O_RDONLY", True),
        ("O_WRONLY", False),
        ("O_APPEND", False),
        ("O_CREAT", False),
        ("O_EXCL", False),
        ("O_DIRECTORY", False),
        ("O_NOFOLLOW", False),
        ("O_CLOEXEC", False),
        ("O_NONBLOCK", False),
        ("P_PID", False),
        ("WEXITED", False),
        ("WNOHANG", False),
        ("WNOWAIT", False),
    )
    required_functions = (
        "close",
        "dup",
        "fchmod",
        "fsync",
        "fstat",
        "geteuid",
        "killpg",
        "link",
        "lstat",
        "mkdir",
        "open",
        "read",
        "replace",
        "stat",
        "unlink",
        "waitid",
        "write",
    )
    dir_fd_probes = (os.open, os.stat, os.mkdir, os.rename, os.unlink, os.link)
    follow_symlink_probes = (os.stat, os.link)
    return (
        os.name == "posix"
        and Path(sys.executable).is_file()
        and callable(getattr(fcntl, "flock", None))
        and callable(getattr(selectors, "DefaultSelector", None))
        and all(callable(getattr(os, name, None)) for name in required_functions)
        and all(
            type(getattr(os, name, None)) is int and (allow_zero or getattr(os, name) != 0)
            for name, allow_zero in required_flags
        )
        and all(probe in os.supports_dir_fd for probe in dir_fd_probes)
        and all(probe in os.supports_follow_symlinks for probe in follow_symlink_probes)
        and _supports_keywords(os.open, ("dir_fd",))
        and _supports_keywords(os.stat, ("dir_fd", "follow_symlinks"))
        and _supports_keywords(os.replace, ("src_dir_fd", "dst_dir_fd"))
        and _supports_keywords(os.unlink, ("dir_fd",))
        and isinstance(getattr(signal, "SIGTERM", None), signal.Signals)
        and isinstance(getattr(signal, "SIGKILL", None), signal.Signals)
    )


def _supports_keywords(function: object, names: tuple[str, ...]) -> bool:
    if not callable(function):
        return False
    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        return False
    return all(
        name in parameters
        and parameters[name].kind
        in {inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
        for name in names
    )


def run_audit_doctor(
    *,
    workspace: AuditWorkspace,
    location: RepositoryLocation,
    settings: Settings,
    env: Mapping[str, str],
    deadline: float,
    config: AuditConfig | None = None,
) -> AuditDoctorReport:
    """Check prerequisites without creating runs, pulling images, or launching Hermes."""
    checks: list[AuditDoctorCheck] = []
    try:
        workspace.revalidate(location, deadline=deadline)
    except Exception as exc:
        checks.append(AuditDoctorCheck("repository", False, str(exc)))
    else:
        checks.append(AuditDoctorCheck("repository", True, "Git root and hardening verified"))

    try:
        state_private = inspect_private_directory(settings.state_dir, missing_ok=True)
    except (OSError, TypeError, ValueError, UnsafeFileError) as exc:
        checks.append(AuditDoctorCheck("state", False, str(exc)))
    else:
        checks.append(
            AuditDoctorCheck(
                "state",
                True,
                "private state path is available"
                if state_private
                else "private state path is absent and will be created by audit run",
            )
        )

    active_config = config
    if active_config is None:
        try:
            active_config = load_audit_config(settings.state_dir)
        except (AuditConfigError, OSError, TypeError, ValueError, UnsafeFileError) as exc:
            checks.append(AuditDoctorCheck("configuration", False, str(exc)))
    if active_config is not None:
        try:
            validate_provider_selection(active_config)
        except AuditConfigError as exc:
            provider_ready = False
            provider_observation = str(exc)
        else:
            provider_ready = True
            provider_observation = f"provider={active_config.provider} model={active_config.model}"
        checks.append(
            AuditDoctorCheck(
                "provider",
                provider_ready,
                provider_observation,
            )
        )
        missing = tuple(name for name in active_config.provider_env if not env.get(name))
        checks.append(
            AuditDoctorCheck(
                "credentials",
                provider_ready and not missing,
                "named credentials are present"
                if provider_ready and not missing
                else (
                    "missing: " + ", ".join(missing)
                    if missing
                    else "provider credentials are not configured"
                ),
            )
        )
        docker = _executable("docker")
        checks.append(
            AuditDoctorCheck("docker", docker is not None, "available" if docker else "unavailable")
        )
        if docker is not None:
            image_ok, image_note = _command(
                (str(docker), "image", "inspect", active_config.image), deadline=deadline
            )
            checks.append(AuditDoctorCheck("image", image_ok, "digest image " + image_note))
        else:
            checks.append(AuditDoctorCheck("image", False, "Docker is unavailable"))

    hermes = _executable(settings.hermes_bin)
    if hermes is None:
        checks.append(AuditDoctorCheck("hermes", False, "pinned Hermes executable is unavailable"))
    else:
        version_ok, version_note = _pinned_hermes_version(hermes, deadline=deadline)
        checks.append(
            AuditDoctorCheck(
                "hermes",
                version_ok,
                f"expected {HERMES_VERSION}; {version_note}",
            )
        )
    broker_supported = _broker_isolation_supported()
    checks.append(
        AuditDoctorCheck(
            "broker_isolation",
            broker_supported,
            "private Docker broker primitives are supported"
            if broker_supported
            else "required private broker primitives are unavailable",
        )
    )
    return AuditDoctorReport(tuple(checks))
