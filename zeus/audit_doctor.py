"""Non-mutating preflight checks for native repository audits."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from zeus.audit_config import AuditConfigError, load_audit_config
from zeus.audit_docker_broker import HERMES_VERSION
from zeus.audit_models import AuditConfig
from zeus.audit_workspace import AuditWorkspace, RepositoryLocation
from zeus.config import Settings
from zeus.private_io import UnsafeFileError, inspect_private_directory


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
    try:
        result = subprocess.run(  # nosec B603
            tuple(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            shell=False,
            check=False,
            timeout=min(remaining, 30),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "command could not complete"
    return result.returncode == 0, "available" if result.returncode == 0 else "unavailable"


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
                state_private,
                "private state path is available"
                if state_private
                else "private state path is absent",
            )
        )

    active_config = config
    if active_config is None:
        try:
            active_config = load_audit_config(settings.state_dir)
        except (AuditConfigError, OSError, TypeError, ValueError, UnsafeFileError) as exc:
            checks.append(AuditDoctorCheck("configuration", False, str(exc)))
    if active_config is not None:
        checks.append(
            AuditDoctorCheck(
                "provider",
                True,
                f"provider={active_config.provider or '-'} model={active_config.model or '-'}",
            )
        )
        missing = tuple(name for name in active_config.provider_env if not env.get(name))
        checks.append(
            AuditDoctorCheck(
                "credentials",
                not missing,
                "named credentials are present"
                if not missing
                else "missing: " + ", ".join(missing),
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
        version_ok, version_note = _command((str(hermes), "--version"), deadline=deadline)
        checks.append(
            AuditDoctorCheck(
                "hermes",
                version_ok,
                f"expected {HERMES_VERSION}; {version_note}",
            )
        )
    checks.append(
        AuditDoctorCheck(
            "broker_isolation",
            os.name == "posix" and bool(sys.executable),
            "private Docker broker is supported" if os.name == "posix" else "POSIX is required",
        )
    )
    return AuditDoctorReport(tuple(checks))
