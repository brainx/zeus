from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zeus.envfile import dump_env
from zeus.models import BotCreateRequest, BotRecord, HermesTemplate, TemplateError
from zeus.private_io import nofollow_absolute_path, validate_private_directory

_LOG = logging.getLogger(__name__)


def _dump_yaml(value: Any, indent: int = 0) -> str:
    spaces = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                lines.append(f"{spaces}{key}:")
                lines.append(_dump_yaml(child, indent + 2).rstrip())
            else:
                lines.append(f"{spaces}{key}: {_yaml_scalar(child)}")
        return "\n".join(lines) + "\n"
    if isinstance(value, list):
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{spaces}-")
                lines.append(_dump_yaml(child, indent + 2).rstrip())
            else:
                lines.append(f"{spaces}- {_yaml_scalar(child)}")
        return "\n".join(lines) + "\n"
    return f"{spaces}{_yaml_scalar(value)}\n"


def _yaml_scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


class ProfileRenderer:
    def __init__(self, hermes_root: Path | str) -> None:
        self.hermes_root = Path(hermes_root)

    def render(self, request: BotCreateRequest, template: HermesTemplate) -> BotRecord:
        """Render and immediately commit a profile for compatibility with direct callers."""
        with self.transaction(request, template) as record:
            return record

    def preflight(self, request: BotCreateRequest, template: HermesTemplate) -> dict[str, str]:
        """Validate and serialize a profile without mutating the filesystem."""
        validate_request_env(request, template)
        return _rendered_profile_files(request, template)

    @contextmanager
    def transaction(
        self, request: BotCreateRequest, template: HermesTemplate
    ) -> Iterator[BotRecord]:
        """Install a profile and retain rollback state until the caller succeeds."""
        rendered_files = self.preflight(request, template)
        profile = self.hermes_root / "profiles" / request.bot_id
        now = datetime.now(UTC)
        record = BotRecord(
            bot_id=request.bot_id,
            template_id=template.id,
            display_name=request.display_name
            if request.display_name is not None
            else template.name,
            profile_path=str(profile),
            restart_policy=request.restart_policy,
            restart_backoff_seconds=request.restart_backoff_seconds,
            restart_max_attempts=request.restart_max_attempts,
            created_at=now,
            updated_at=now,
        )
        profiles_root = profile.parent
        profiles_root.mkdir(parents=True, exist_ok=True)
        if _path_exists(profile) and (profile.is_symlink() or not profile.is_dir()):
            raise TemplateError("existing profile path must be a directory")

        staging = Path(tempfile.mkdtemp(prefix=f".{request.bot_id}.staging-", dir=profiles_root))
        try:
            _write_staged_profile(staging, profile, rendered_files)
            backup = _install_staged_profile(staging, profile)
        finally:
            try:
                _remove_path(staging)
            except OSError:
                _LOG.warning("could not remove a profile staging path", exc_info=True)

        try:
            yield record
        except BaseException:
            _rollback_installed_profile(profile, backup)
            raise
        else:
            _commit_installed_profile(backup)


def _rendered_profile_files(request: BotCreateRequest, template: HermesTemplate) -> dict[str, str]:
    return {
        "SOUL.md": template.soul.rstrip() + "\n",
        "config.yaml": _dump_yaml(template.hermes.to_config()),
        ".env": dump_env(template.hermes.required_env, request.env),
        "mcp.json": json.dumps(template.mcp, indent=2, sort_keys=True) + "\n",
        "cron/jobs.json": json.dumps(template.cron, indent=2, sort_keys=True) + "\n",
    }


def _write_staged_profile(
    staging: Path, existing_profile: Path, rendered_files: dict[str, str]
) -> None:
    if existing_profile.is_dir() and not existing_profile.is_symlink():
        shutil.copytree(
            existing_profile,
            staging,
            dirs_exist_ok=True,
            symlinks=True,
        )

    _ensure_staged_directory(staging / "cron")
    _ensure_private_logs_directory(staging / "logs")
    _ensure_preserved_directory(staging / "skills")

    for relative_path, content in rendered_files.items():
        _write_staged_file(staging / relative_path, content)
    (staging / ".env").chmod(0o600)


def _ensure_staged_directory(path: Path) -> None:
    if _path_exists(path) and (path.is_symlink() or not path.is_dir()):
        _remove_path(path)
    path.mkdir(exist_ok=True)


def _ensure_preserved_directory(path: Path) -> None:
    if not _path_exists(path):
        path.mkdir()
        return
    if path.is_symlink():
        return
    if not path.is_dir():
        raise TemplateError(f"profile path must be a directory: {path.name}")


def _ensure_private_logs_directory(path: Path) -> None:
    try:
        if _path_exists(path):
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                path.unlink()
            elif not stat.S_ISDIR(metadata.st_mode):
                raise TemplateError(f"profile path must be a directory: {path.name}")
        if not _path_exists(path):
            path.mkdir(mode=0o700)
        metadata = os.lstat(path)
    except OSError as exc:
        raise TemplateError("profile logs directory could not be prepared safely") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise TemplateError("profile logs directory must be owned by the current user")
    try:
        validate_private_directory(nofollow_absolute_path(path))
    except OSError as exc:
        raise TemplateError("profile logs directory could not be made private") from exc


def _write_staged_file(path: Path, content: str) -> None:
    if _path_exists(path):
        if path.is_dir() and not path.is_symlink():
            raise TemplateError(f"managed profile path must not be a directory: {path.name}")
        path.unlink()
    path.write_text(content, encoding="utf-8")


def _install_staged_profile(staging: Path, profile: Path) -> Path | None:
    if not _path_exists(profile):
        os.replace(staging, profile)
        return None

    backup = staging.with_name(f"{staging.name}.previous")
    os.replace(profile, backup)
    try:
        os.replace(staging, profile)
    except BaseException:
        try:
            os.replace(backup, profile)
        except OSError as rollback_error:
            raise RuntimeError(
                "profile installation failed and rollback could not restore the previous profile"
            ) from rollback_error
        raise

    return backup


def _commit_installed_profile(backup: Path | None) -> None:
    if backup is None:
        return
    try:
        _remove_path(backup)
    except OSError:
        _LOG.warning("could not remove a replaced profile backup", exc_info=True)


def _rollback_installed_profile(profile: Path, backup: Path | None) -> None:
    if backup is None:
        try:
            _remove_path(profile)
        except OSError as rollback_error:
            raise RuntimeError(
                "profile transaction rollback could not remove the new profile"
            ) from rollback_error
        return

    if not _path_exists(profile):
        try:
            os.replace(backup, profile)
        except OSError as rollback_error:
            raise RuntimeError(
                "profile transaction rollback could not restore the previous profile"
            ) from rollback_error
        return

    discarded = backup.with_name(f"{backup.name}.discarded")
    try:
        os.replace(profile, discarded)
        os.replace(backup, profile)
    except OSError as rollback_error:
        if _path_exists(discarded) and not _path_exists(profile):
            try:
                os.replace(discarded, profile)
            except OSError as recovery_error:
                raise RuntimeError(
                    "profile transaction rollback failed and could not retain the installed profile"
                ) from recovery_error
        raise RuntimeError(
            "profile transaction rollback could not restore the previous profile"
        ) from rollback_error

    try:
        _remove_path(discarded)
    except OSError:
        _LOG.warning("could not remove a rolled-back profile", exc_info=True)


def _path_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _remove_path(path: Path) -> None:
    if not _path_exists(path):
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def validate_request_env(request: BotCreateRequest, template: HermesTemplate) -> None:
    allowed = set(template.hermes.required_env)
    unknown = sorted(set(request.env) - allowed)
    if unknown:
        names = ", ".join(unknown)
        raise TemplateError(f"env contains unknown key(s) for template {template.id}: {names}")
