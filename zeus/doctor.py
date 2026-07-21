from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zeus.config import Settings, is_loopback_host
from zeus.private_io import inspect_private_directory, nofollow_absolute_path
from zeus.state import StateStore
from zeus.templates import TemplateStore


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "message": self.message}


@dataclass(frozen=True)
class DoctorReport:
    checks: list[DoctorCheck]
    strict: bool = False

    @property
    def ok(self) -> bool:
        if self.strict:
            return all(check.status == "pass" for check in self.checks)
        return all(check.status != "fail" for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "strict": self.strict,
            "checks": [check.to_dict() for check in self.checks],
        }


def run_doctor(settings: Settings | None = None, *, strict: bool = False) -> DoctorReport:
    settings = settings or Settings.from_env()
    checks: list[DoctorCheck] = []
    checks.append(_check_python())
    checks.append(_check_hermes(settings))
    checks.append(_check_templates())
    checks.append(_check_runtime_paths(settings))
    checks.append(_check_scripts())
    checks.append(_check_api_bind(settings))
    checks.append(_check_api_auth(settings))
    checks.extend(_check_bots(settings))
    return DoctorReport(checks, strict=strict)


def _check_python() -> DoctorCheck:
    version = sys.version_info
    if version >= (3, 11):
        return DoctorCheck("python", "pass", f"Python {version.major}.{version.minor} is supported")
    return DoctorCheck("python", "fail", "Python 3.11 or newer is required")


def _check_hermes(settings: Settings) -> DoctorCheck:
    resolved = shutil.which(settings.hermes_bin)
    if resolved:
        return DoctorCheck("hermes", "pass", f"Hermes executable found at {resolved}")
    return DoctorCheck(
        "hermes",
        "warn",
        f"Hermes executable {settings.hermes_bin!r} was not found on PATH; bot startup will fail",
    )


def _check_templates() -> DoctorCheck:
    try:
        templates = TemplateStore().list()
    except Exception as exc:
        return DoctorCheck("templates", "fail", f"Template validation failed: {exc}")
    if not templates:
        return DoctorCheck("templates", "fail", "No templates found in templates/*.toml")
    missing_caps = [
        template.id
        for template in templates
        if not (1 <= template.hermes.delegation.max_async_children <= 32)
    ]
    if missing_caps:
        return DoctorCheck(
            "templates",
            "fail",
            "Templates have invalid async delegation caps: " + ", ".join(missing_caps),
        )
    return DoctorCheck(
        "templates",
        "pass",
        f"{len(templates)} template(s) valid with bounded async delegation caps",
    )


def _existing_runtime_directory_check(
    path: Path,
    *,
    label: str,
) -> tuple[bool, DoctorCheck | None]:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        try:
            exists = inspect_private_directory(path, missing_ok=True)
        except OSError:
            return True, DoctorCheck(
                "runtime_paths",
                "fail",
                f"{label} {path} could not be validated safely",
            )
        if exists:
            return True, DoctorCheck(
                "runtime_paths",
                "fail",
                f"{label} {path} changed while it was inspected",
            )
        return False, None
    except OSError:
        return True, DoctorCheck(
            "runtime_paths",
            "fail",
            f"{label} {path} could not be inspected safely",
        )
    if not stat.S_ISDIR(metadata.st_mode):
        return True, DoctorCheck(
            "runtime_paths",
            "fail",
            f"{label} path {path} must be a directory and not a symlink",
        )
    if metadata.st_uid != os.geteuid():
        return True, DoctorCheck(
            "runtime_paths",
            "fail",
            f"{label} {path} must be owned by the current user",
        )
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        return True, DoctorCheck(
            "runtime_paths",
            "fail",
            f"{label} {path} must not be accessible to other users or groups",
        )
    try:
        inspect_private_directory(path)
    except OSError:
        return True, DoctorCheck(
            "runtime_paths",
            "fail",
            f"{label} {path} could not be validated safely",
        )
    return True, None


def _check_runtime_paths(settings: Settings) -> DoctorCheck:
    state_dir = nofollow_absolute_path(settings.state_dir)
    state_exists, failure = _existing_runtime_directory_check(
        state_dir,
        label="State directory",
    )
    if failure is not None:
        return failure
    if state_exists:
        _, failure = _existing_runtime_directory_check(
            state_dir / "logs",
            label="State logs directory",
        )
        if failure is not None:
            return failure
    workspace = Path.cwd().resolve()
    gitignore = workspace / ".gitignore"
    if not gitignore.exists():
        return DoctorCheck(
            "runtime_paths",
            "warn",
            "No .gitignore found; runtime ignore check skipped outside a git checkout",
        )
    try:
        relative_state = state_dir.relative_to(workspace)
    except ValueError:
        return DoctorCheck(
            "runtime_paths",
            "pass",
            f"State directory {state_dir} is outside the current workspace",
        )
    git_binary = shutil.which("git")
    if git_binary is None:
        return DoctorCheck(
            "runtime_paths",
            "warn",
            f"Could not verify that state directory {relative_state} is ignored by git",
        )
    try:
        completed = subprocess.run(  # nosec B603
            [
                git_binary,
                "check-ignore",
                "--quiet",
                "--no-index",
                "--",
                f"{relative_state}/",
            ],
            cwd=workspace,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return DoctorCheck(
            "runtime_paths",
            "warn",
            f"Could not verify that state directory {relative_state} is ignored by git",
        )
    if completed.returncode == 0:
        return DoctorCheck(
            "runtime_paths", "pass", f"State directory {relative_state} is ignored by git"
        )
    if completed.returncode == 1:
        return DoctorCheck(
            "runtime_paths",
            "fail",
            f"State directory {relative_state} must be ignored by git",
        )
    return DoctorCheck(
        "runtime_paths",
        "warn",
        f"Could not verify that state directory {relative_state} is ignored by git",
    )


def _check_scripts() -> DoctorCheck:
    script_paths = [Path("scripts/start.sh"), Path("scripts/stop.sh")]
    missing = [path for path in script_paths if not path.exists()]
    if missing:
        status = "fail" if Path("scripts").exists() else "warn"
        return DoctorCheck(
            "scripts",
            status,
            "Missing checkout script(s): " + ", ".join(map(str, missing)),
        )
    non_exec = [path for path in script_paths if not path.stat().st_mode & 0o111]
    if non_exec:
        return DoctorCheck(
            "scripts", "warn", "Script(s) are not executable: " + ", ".join(map(str, non_exec))
        )
    return DoctorCheck("scripts", "pass", "start/stop scripts are present and executable")


def _check_api_bind(settings: Settings) -> DoctorCheck:
    if not is_loopback_host(settings.host):
        return DoctorCheck("api_bind", "warn", f"API host {settings.host!r} is not loopback-only")
    if not (3000 <= settings.port <= 5000):
        return DoctorCheck(
            "api_bind",
            "warn",
            f"API port {settings.port} is outside the documented 3000-5000 range",
        )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            result = sock.connect_ex(("127.0.0.1", settings.port))
        if result == 0:
            return DoctorCheck("api_bind", "warn", f"Port {settings.port} is already in use")
    except OSError:
        return DoctorCheck("api_bind", "warn", "Could not probe localhost port availability")
    return DoctorCheck(
        "api_bind", "pass", f"API bind {settings.host}:{settings.port} is loopback and available"
    )


def _check_api_auth(settings: Settings) -> DoctorCheck:
    public_bind = not is_loopback_host(settings.host)
    if public_bind and settings.allow_unauth_reads:
        return DoctorCheck(
            "api_auth",
            "fail",
            "Public API bind cannot enable ZEUS_ALLOW_UNAUTH_READS",
        )
    if public_bind and not settings.api_key:
        return DoctorCheck(
            "api_auth",
            "fail",
            "Public API bind requires ZEUS_API_KEY; do not expose Zeus without authentication",
        )
    if public_bind and settings.api_key and len(settings.api_key) < 16:
        return DoctorCheck(
            "api_auth",
            "fail",
            "Public API bind requires a stronger ZEUS_API_KEY",
        )
    if settings.api_key and not settings.allow_unauth_reads:
        return DoctorCheck("api_auth", "pass", "Non-health API endpoints require x-zeus-api-key")
    if settings.allow_unauth_reads:
        return DoctorCheck(
            "api_auth",
            "warn",
            "ZEUS_ALLOW_UNAUTH_READS=1 permits unauthenticated low-risk read endpoints "
            "for local dev",
        )
    return DoctorCheck(
        "api_auth",
        "warn",
        "ZEUS_API_KEY is not configured; non-health API endpoints will reject requests",
    )


def _check_bots(settings: Settings) -> list[DoctorCheck]:
    store = StateStore(settings.database_path)
    if not settings.database_path.exists():
        return [DoctorCheck("bots", "pass", "No bot registry exists yet")]
    try:
        store.init()
        bots = store.list_bots()
    except Exception as exc:
        return [DoctorCheck("bots", "fail", f"Could not read bot registry: {exc}")]
    if not bots:
        return [DoctorCheck("bots", "pass", "Bot registry is empty")]
    checks: list[DoctorCheck] = []
    for bot in bots:
        profile = Path(bot.profile_path)
        missing = [
            name
            for name in ["config.yaml", "SOUL.md", ".env", "mcp.json"]
            if not (profile / name).exists()
        ]
        if missing:
            checks.append(
                DoctorCheck(
                    f"bot:{bot.bot_id}",
                    "fail",
                    "Missing rendered profile file(s): " + ", ".join(missing),
                )
            )
        else:
            checks.append(
                DoctorCheck(f"bot:{bot.bot_id}", "pass", "Rendered profile files are present")
            )
    return checks


def report_to_text(report: DoctorReport) -> str:
    lines = []
    for check in report.checks:
        if check.status == "pass":
            marker = "OK"
        elif check.status == "warn":
            marker = "WARN"
        elif check.status == "fail":
            marker = "FAIL"
        else:
            marker = check.status.upper()
        lines.append(f"{marker}\t{check.name}\t{check.message}")
    return "\n".join(lines) + ("\n" if lines else "")


def report_to_json(report: DoctorReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
