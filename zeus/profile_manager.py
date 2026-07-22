from __future__ import annotations

import os
import shutil
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from zeus.errors import BotArchiveError, BotDeleteError
from zeus.models import BotCreateRequest, BotRecord, HermesTemplate, validate_id
from zeus.renderer import ProfileRenderer


@dataclass(frozen=True)
class ProfileDeletion:
    profile_path: Path
    tombstone_path: Path


@dataclass(frozen=True)
class ProfileArchive:
    profile_path: Path
    archive_path: Path


class ProfileManager:
    def __init__(self, hermes_root: Path | str, archive_root: Path | str) -> None:
        self.hermes_root = Path(hermes_root)
        self.archive_root = Path(archive_root)
        self._renderer = ProfileRenderer(self.hermes_root)

    def preflight(
        self,
        request: BotCreateRequest,
        template: HermesTemplate,
    ) -> dict[str, str]:
        return self._renderer.preflight(request, template)

    def install_transaction(
        self,
        request: BotCreateRequest,
        template: HermesTemplate,
    ) -> AbstractContextManager[BotRecord]:
        return self._renderer.transaction(request, template)

    def validate_profile_path(self, bot_id: str, profile_path: Path | str) -> Path:
        safe_bot_id = validate_id(bot_id, "bot_id")
        profile = Path(profile_path).resolve()
        profiles_root = (self.hermes_root / "profiles").resolve()
        return self._validate_exact_profile_path(safe_bot_id, profile, profiles_root)

    def _pin_profile_path(self, bot_id: str, profile_path: Path | str) -> Path:
        safe_bot_id = validate_id(bot_id, "bot_id")
        absolute_profile = Path(os.path.abspath(profile_path))
        profile = absolute_profile.parent.resolve() / absolute_profile.name
        profiles_root = (self.hermes_root / "profiles").resolve()
        return self._validate_exact_profile_path(safe_bot_id, profile, profiles_root)

    @staticmethod
    def _validate_exact_profile_path(
        safe_bot_id: str,
        profile: Path,
        profiles_root: Path,
    ) -> Path:
        try:
            relative = profile.relative_to(profiles_root)
        except ValueError as exc:
            raise BotDeleteError("bot profile path is outside the Hermes profiles root") from exc
        if len(relative.parts) != 1 or relative.parts[0] != safe_bot_id:
            raise BotDeleteError("bot profile path does not match bot id")
        return profile

    def stage_delete(
        self,
        bot_id: str,
        profile_path: Path | str,
    ) -> ProfileDeletion | None:
        profile = self.validate_profile_path(bot_id, profile_path)
        if not profile.exists():
            return None
        tombstone = profile.with_name(f".{profile.name}.deleting-{os.getpid()}-{time.time_ns()}")
        try:
            os.replace(profile, tombstone)
        except OSError as exc:
            raise BotDeleteError("could not stage the bot profile for deletion") from exc
        return ProfileDeletion(profile_path=profile, tombstone_path=tombstone)

    def rollback_delete(self, deletion: ProfileDeletion) -> None:
        if os.path.lexists(deletion.profile_path):
            raise BotDeleteError(
                "bot state deletion failed and the profile could not be restored because "
                "its original path is occupied"
            )
        try:
            os.replace(deletion.tombstone_path, deletion.profile_path)
        except OSError as exc:
            raise BotDeleteError(
                "bot state deletion failed and the profile could not be restored"
            ) from exc

    def finish_delete(self, deletion: ProfileDeletion) -> OSError | None:
        try:
            shutil.rmtree(deletion.tombstone_path)
        except OSError as exc:
            return exc
        return None

    def stage_archive(
        self,
        bot_id: str,
        profile_path: Path | str,
    ) -> ProfileArchive | None:
        profile = self.validate_profile_path(bot_id, profile_path)
        if not profile.exists():
            return None
        self.archive_root.mkdir(parents=True, exist_ok=True)
        archive_path = self.archive_root / (
            f"{validate_id(bot_id, 'bot_id')}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
        )
        shutil.move(str(profile), str(archive_path))
        return ProfileArchive(profile_path=profile, archive_path=archive_path)

    def rollback_archive(self, archive: ProfileArchive) -> None:
        if os.path.lexists(archive.profile_path):
            raise BotArchiveError(
                "bot state deletion failed and the archived profile could not be restored "
                "because its original path is occupied"
            )
        try:
            shutil.move(str(archive.archive_path), str(archive.profile_path))
        except OSError as exc:
            raise BotArchiveError(
                "bot state deletion failed and the archived profile could not be restored"
            ) from exc
