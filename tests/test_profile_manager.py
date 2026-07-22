from __future__ import annotations

import ast
import inspect
import json
import os
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import zeus.profile_manager as profile_manager_module
from zeus.errors import BotArchiveError, BotDeleteError
from zeus.models import BotCreateRequest, BotRecord
from zeus.profile_manager import ProfileArchive, ProfileDeletion, ProfileManager
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore


class ProfileManagerTests(unittest.TestCase):
    def _manager(self, root: Path) -> ProfileManager:
        return ProfileManager(root / "hermes", root / "archive")

    def _profile(self, root: Path) -> Path:
        return root / "hermes" / "profiles" / "coder"

    def _write_profile(self, root: Path) -> Path:
        profile = self._profile(root)
        profile.mkdir(parents=True)
        (profile / "sentinel.txt").write_text("original\n", encoding="utf-8")
        return profile

    def _supervisor_with_bot(self, root: Path) -> tuple[StateStore, Supervisor, Path]:
        profile = self._write_profile(root)
        store = StateStore(root / "zeus.db")
        store.init()
        store.upsert_bot(
            BotRecord(
                bot_id="coder",
                template_id="coding-bot",
                display_name="Coder",
                profile_path=str(profile),
            )
        )
        return store, Supervisor(store, "hermes", root / "hermes"), profile

    def test_preflight_delegates_without_mutating_the_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            template = TemplateStore().get("coding-bot")

            rendered = manager.preflight(request, template)

            self.assertEqual(template.soul.rstrip() + "\n", rendered["SOUL.md"])
            self.assertFalse((root / "hermes").exists())

    def test_install_transaction_removes_a_new_profile_on_caller_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._profile(root)
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            template = TemplateStore().get("coding-bot")

            with (
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
                manager.install_transaction(request, template) as record,
            ):
                self.assertEqual("coder", record.bot_id)
                self.assertTrue(profile.is_dir())
                raise RuntimeError("database unavailable")

            self.assertFalse(os.path.lexists(profile))
            self.assertEqual([], list(profile.parent.iterdir()))

    def test_install_transaction_restores_an_exact_replaced_profile_on_caller_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)
            (profile / "SOUL.md").write_text("original profile\n", encoding="utf-8")
            original_inode = profile.stat().st_ino
            before = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            template = replace(TemplateStore().get("coding-bot"), soul="replacement profile")

            with (
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
                manager.install_transaction(request, template),
            ):
                self.assertEqual(
                    "replacement profile\n",
                    (profile / "SOUL.md").read_text(encoding="utf-8"),
                )
                raise RuntimeError("database unavailable")

            after = {
                path.relative_to(profile): path.read_bytes()
                for path in profile.rglob("*")
                if path.is_file()
            }
            self.assertEqual(original_inode, profile.stat().st_ino)
            self.assertEqual(before, after)
            self.assertEqual(["coder"], sorted(path.name for path in profile.parent.iterdir()))

    def test_delete_stage_rollback_and_finish_use_a_pinned_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)

            deletion = manager.stage_delete("coder", str(profile))

            self.assertIsInstance(deletion, ProfileDeletion)
            assert deletion is not None
            self.assertEqual(profile.resolve(), deletion.profile_path)
            self.assertTrue(deletion.tombstone_path.is_dir())
            self.assertFalse(os.path.lexists(profile))

            manager.rollback_delete(deletion)

            self.assertEqual("original\n", (profile / "sentinel.txt").read_text(encoding="utf-8"))
            self.assertFalse(os.path.lexists(deletion.tombstone_path))

            second_deletion = manager.stage_delete("coder", str(profile))
            assert second_deletion is not None
            self.assertIsNone(manager.finish_delete(second_deletion))
            self.assertFalse(os.path.lexists(profile))
            self.assertFalse(os.path.lexists(second_deletion.tombstone_path))

    def test_finish_delete_reports_cleanup_failure_and_retains_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)
            deletion = manager.stage_delete("coder", str(profile))
            assert deletion is not None
            cleanup_error = OSError("cleanup unavailable")

            with patch("zeus.profile_manager.shutil.rmtree", side_effect=cleanup_error):
                reported = manager.finish_delete(deletion)

            self.assertIs(cleanup_error, reported)
            self.assertTrue(deletion.tombstone_path.is_dir())
            self.assertEqual(
                "original\n",
                (deletion.tombstone_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_archive_stage_and_rollback_use_a_pinned_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)

            archive = manager.stage_archive("coder", str(profile))

            self.assertIsInstance(archive, ProfileArchive)
            assert archive is not None
            self.assertEqual(profile.resolve(), archive.profile_path)
            self.assertTrue(archive.archive_path.is_dir())
            self.assertFalse(os.path.lexists(profile))

            manager.rollback_archive(archive)

            self.assertEqual("original\n", (profile / "sentinel.txt").read_text(encoding="utf-8"))
            self.assertFalse(os.path.lexists(archive.archive_path))

    def test_validate_profile_path_accepts_only_the_exact_bot_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            hermes_root = root / "hermes"
            profiles_root = hermes_root / "profiles"
            exact_profile = profiles_root / "coder"
            exact_profile.mkdir(parents=True)

            self.assertEqual(
                exact_profile.resolve(),
                manager.validate_profile_path("coder", str(exact_profile)),
            )

            rejected = {
                "Hermes root": hermes_root,
                "profiles root": profiles_root,
                "sibling profiles tree": hermes_root.parent / "other-profiles" / "coder",
                "other bot": profiles_root / "other-bot",
                "nested path": exact_profile / "nested",
                "outside path": root / "outside",
            }
            for label, candidate in rejected.items():
                with self.subTest(label=label), self.assertRaises(BotDeleteError):
                    manager.validate_profile_path("coder", str(candidate))

    def test_delete_rollback_refuses_an_occupied_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)
            deletion = manager.stage_delete("coder", str(profile))
            assert deletion is not None
            profile.mkdir()
            replacement = profile / "replacement.txt"
            replacement.write_text("replacement\n", encoding="utf-8")

            with (
                patch.object(manager, "finish_delete") as finish_delete,
                self.assertRaises(BotDeleteError),
            ):
                manager.rollback_delete(deletion)

            finish_delete.assert_not_called()
            self.assertEqual("replacement\n", replacement.read_text(encoding="utf-8"))
            self.assertEqual(
                "original\n",
                (deletion.tombstone_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_delete_rollback_refuses_a_dangling_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)
            deletion = manager.stage_delete("coder", str(profile))
            assert deletion is not None
            target = root / "untouched-delete-target"
            profile.symlink_to(target, target_is_directory=True)

            with (
                patch.object(manager, "finish_delete") as finish_delete,
                self.assertRaises(BotDeleteError),
            ):
                manager.rollback_delete(deletion)

            finish_delete.assert_not_called()
            self.assertTrue(profile.is_symlink())
            self.assertEqual(str(target), os.readlink(profile))
            self.assertFalse(target.exists())
            self.assertEqual(
                "original\n",
                (deletion.tombstone_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_archive_rollback_refuses_an_occupied_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)
            archive = manager.stage_archive("coder", str(profile))
            assert archive is not None
            profile.mkdir()
            replacement = profile / "replacement.txt"
            replacement.write_text("replacement\n", encoding="utf-8")

            with (
                patch("zeus.profile_manager.shutil.rmtree") as cleanup,
                self.assertRaises(BotArchiveError),
            ):
                manager.rollback_archive(archive)

            cleanup.assert_not_called()
            self.assertEqual("replacement\n", replacement.read_text(encoding="utf-8"))
            self.assertEqual(
                "original\n",
                (archive.archive_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_archive_rollback_refuses_a_dangling_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._manager(root)
            profile = self._write_profile(root)
            archive = manager.stage_archive("coder", str(profile))
            assert archive is not None
            target = root / "untouched-archive-target"
            profile.symlink_to(target, target_is_directory=True)

            with (
                patch("zeus.profile_manager.shutil.rmtree") as cleanup,
                self.assertRaises(BotArchiveError),
            ):
                manager.rollback_archive(archive)

            cleanup.assert_not_called()
            self.assertTrue(profile.is_symlink())
            self.assertEqual(str(target), os.readlink(profile))
            self.assertFalse(target.exists())
            self.assertEqual(
                "original\n",
                (archive.archive_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_supervisor_delete_carries_the_exact_staged_token_into_finish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            manager = supervisor._profile_manager
            staged: list[ProfileDeletion] = []
            real_stage_delete = manager.stage_delete
            real_finish_delete = manager.finish_delete

            def capture_stage(bot_id: str, profile_path: Path | str) -> ProfileDeletion | None:
                deletion = real_stage_delete(bot_id, profile_path)
                assert deletion is not None
                staged.append(deletion)
                return deletion

            def capture_finish(deletion: ProfileDeletion) -> OSError | None:
                self.assertIs(staged[0], deletion)
                return real_finish_delete(deletion)

            with (
                patch.object(manager, "stage_delete", side_effect=capture_stage),
                patch.object(manager, "finish_delete", side_effect=capture_finish) as finish,
            ):
                response = supervisor.delete_bot("coder", remove_profile=True)

            self.assertEqual("deleted", response.message)
            self.assertEqual(1, finish.call_count)
            self.assertIsNone(store.get_bot("coder"))
            self.assertFalse(os.path.lexists(profile))

    def test_supervisor_delete_cleanup_failure_stays_post_commit_and_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            manager = supervisor._profile_manager
            staged: list[ProfileDeletion] = []
            real_stage_delete = manager.stage_delete
            cleanup_error = PermissionError("cleanup unavailable")

            def capture_stage(bot_id: str, profile_path: Path | str) -> ProfileDeletion | None:
                deletion = real_stage_delete(bot_id, profile_path)
                assert deletion is not None
                staged.append(deletion)
                return deletion

            with (
                patch.object(manager, "stage_delete", side_effect=capture_stage),
                patch.object(manager, "finish_delete", return_value=cleanup_error),
            ):
                response = supervisor.delete_bot("coder", remove_profile=True)

            self.assertEqual("deleted; profile cleanup is pending", response.message)
            self.assertIsNone(store.get_bot("coder"))
            self.assertFalse(os.path.lexists(profile))
            self.assertEqual(
                "original\n",
                (staged[0].tombstone_path / "sentinel.txt").read_text(encoding="utf-8"),
            )
            events = [
                json.loads(line)
                for line in store.audit_log_path().read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(
                any(
                    event.get("event") == "bot.delete_cleanup_pending"
                    and event.get("error") == "PermissionError"
                    for event in events
                )
            )
            self.assertTrue(
                any(
                    event.get("event") == "bot.delete"
                    and event.get("profile_removed") is True
                    and event.get("cleanup_pending") is True
                    for event in events
                )
            )

    def test_supervisor_delete_carries_the_exact_staged_token_into_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            manager = supervisor._profile_manager
            staged: list[ProfileDeletion] = []
            real_stage_delete = manager.stage_delete
            real_rollback_delete = manager.rollback_delete
            database_error = RuntimeError("database unavailable")

            def capture_stage(bot_id: str, profile_path: Path | str) -> ProfileDeletion | None:
                deletion = real_stage_delete(bot_id, profile_path)
                assert deletion is not None
                staged.append(deletion)
                return deletion

            def capture_rollback(deletion: ProfileDeletion) -> None:
                self.assertIs(staged[0], deletion)
                real_rollback_delete(deletion)

            with (
                patch.object(manager, "stage_delete", side_effect=capture_stage),
                patch.object(manager, "rollback_delete", side_effect=capture_rollback) as rollback,
                patch.object(manager, "finish_delete") as finish,
                patch.object(store, "delete_bot_with_event", side_effect=database_error),
                self.assertRaisesRegex(RuntimeError, "database unavailable") as raised,
            ):
                supervisor.delete_bot("coder", remove_profile=True)

            self.assertIs(database_error, raised.exception)
            self.assertEqual(1, rollback.call_count)
            finish.assert_not_called()
            self.assertEqual("original\n", (profile / "sentinel.txt").read_text(encoding="utf-8"))

    def test_supervisor_archive_carries_the_exact_staged_token_into_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            manager = supervisor._profile_manager
            staged: list[ProfileArchive] = []
            real_stage_archive = manager.stage_archive
            real_rollback_archive = manager.rollback_archive
            database_error = RuntimeError("database unavailable")

            def capture_stage(bot_id: str, profile_path: Path | str) -> ProfileArchive | None:
                archive = real_stage_archive(bot_id, profile_path)
                assert archive is not None
                staged.append(archive)
                return archive

            def capture_rollback(archive: ProfileArchive) -> None:
                self.assertIs(staged[0], archive)
                real_rollback_archive(archive)

            with (
                patch.object(manager, "stage_archive", side_effect=capture_stage),
                patch.object(
                    manager,
                    "rollback_archive",
                    side_effect=capture_rollback,
                ) as rollback,
                patch.object(store, "delete_bot_with_event", side_effect=database_error),
                self.assertRaisesRegex(RuntimeError, "database unavailable") as raised,
            ):
                supervisor.archive_bot("coder")

            self.assertIs(database_error, raised.exception)
            self.assertEqual(1, rollback.call_count)
            self.assertEqual("original\n", (profile / "sentinel.txt").read_text(encoding="utf-8"))

    def test_supervisor_delete_chains_refused_compensation_from_database_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            manager = supervisor._profile_manager
            staged: list[ProfileDeletion] = []
            real_stage_delete = manager.stage_delete
            database_error = RuntimeError("database unavailable")

            def capture_stage(bot_id: str, profile_path: Path | str) -> ProfileDeletion | None:
                deletion = real_stage_delete(bot_id, profile_path)
                assert deletion is not None
                staged.append(deletion)
                return deletion

            def occupy_destination(*args: object, **kwargs: object) -> bool:
                profile.mkdir()
                (profile / "replacement.txt").write_text("replacement\n", encoding="utf-8")
                raise database_error

            with (
                patch.object(manager, "stage_delete", side_effect=capture_stage),
                patch.object(manager, "finish_delete") as finish,
                patch.object(store, "delete_bot_with_event", side_effect=occupy_destination),
                self.assertRaises(BotDeleteError) as raised,
            ):
                supervisor.delete_bot("coder", remove_profile=True)

            self.assertIs(database_error, raised.exception.__cause__)
            finish.assert_not_called()
            self.assertEqual(
                "replacement\n",
                (profile / "replacement.txt").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                "original\n",
                (staged[0].tombstone_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_supervisor_archive_chains_refused_compensation_from_database_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            manager = supervisor._profile_manager
            staged: list[ProfileArchive] = []
            real_stage_archive = manager.stage_archive
            database_error = RuntimeError("database unavailable")
            target = root / "untouched-supervisor-archive-target"

            def capture_stage(bot_id: str, profile_path: Path | str) -> ProfileArchive | None:
                archive = real_stage_archive(bot_id, profile_path)
                assert archive is not None
                staged.append(archive)
                return archive

            def occupy_destination(*args: object, **kwargs: object) -> bool:
                profile.symlink_to(target, target_is_directory=True)
                raise database_error

            with (
                patch.object(manager, "stage_archive", side_effect=capture_stage),
                patch.object(store, "delete_bot_with_event", side_effect=occupy_destination),
                self.assertRaises(BotArchiveError) as raised,
            ):
                supervisor.archive_bot("coder")

            self.assertIs(database_error, raised.exception.__cause__)
            self.assertTrue(profile.is_symlink())
            self.assertEqual(str(target), os.readlink(profile))
            self.assertFalse(target.exists())
            self.assertEqual(
                "original\n",
                (staged[0].archive_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_legacy_restore_wrappers_reject_unvalidated_destination_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, "hermes", root / "hermes")
            outside = root / "outside" / "coder"
            tombstone = root / "delete-evidence"
            archive_path = root / "archive-evidence"
            for evidence in (tombstone, archive_path):
                evidence.mkdir()
                (evidence / "sentinel.txt").write_text("retain\n", encoding="utf-8")

            with self.assertRaises(BotDeleteError):
                supervisor._restore_tombstoned_profile("coder", str(outside), tombstone)
            with self.assertRaises(BotDeleteError):
                supervisor._restore_archived_profile("coder", str(outside), archive_path)

            self.assertFalse(os.path.lexists(outside))
            self.assertEqual(
                "retain\n",
                (tombstone / "sentinel.txt").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                "retain\n",
                (archive_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_legacy_delete_restore_treats_an_exact_dangling_symlink_as_occupied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            deletion = supervisor._profile_manager.stage_delete("coder", str(profile))
            assert deletion is not None
            target = root / "untouched-legacy-delete-target"
            profile.symlink_to(target, target_is_directory=True)

            with self.assertRaisesRegex(BotDeleteError, "original path is occupied"):
                supervisor._restore_tombstoned_profile(
                    "coder",
                    str(profile),
                    deletion.tombstone_path,
                )

            self.assertIsNotNone(store.get_bot("coder"))
            self.assertTrue(profile.is_symlink())
            self.assertEqual(str(target), os.readlink(profile))
            self.assertFalse(target.exists())
            self.assertEqual(
                "original\n",
                (deletion.tombstone_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_legacy_archive_restore_treats_an_exact_dangling_symlink_as_occupied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, supervisor, profile = self._supervisor_with_bot(root)
            archive = supervisor._profile_manager.stage_archive("coder", str(profile))
            assert archive is not None
            target = root / "untouched-legacy-archive-target"
            profile.symlink_to(target, target_is_directory=True)

            with self.assertRaisesRegex(BotArchiveError, "original path is occupied"):
                supervisor._restore_archived_profile(
                    "coder",
                    str(profile),
                    archive.archive_path,
                )

            self.assertIsNotNone(store.get_bot("coder"))
            self.assertTrue(profile.is_symlink())
            self.assertEqual(str(target), os.readlink(profile))
            self.assertFalse(target.exists())
            self.assertEqual(
                "original\n",
                (archive.archive_path / "sentinel.txt").read_text(encoding="utf-8"),
            )

    def test_transaction_tokens_are_frozen(self) -> None:
        deletion = ProfileDeletion(Path("profile"), Path("tombstone"))
        archive = ProfileArchive(Path("profile"), Path("archive"))

        with self.assertRaises(FrozenInstanceError):
            deletion.profile_path = Path("replacement")
        with self.assertRaises(FrozenInstanceError):
            archive.profile_path = Path("replacement")

    def test_module_has_no_state_runtime_or_process_dependency(self) -> None:
        source = inspect.getsource(profile_manager_module)
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue({"sqlite3", "signal", "subprocess"}.isdisjoint(imported_roots))
        self.assertNotIn("StateStore", source)
        self.assertNotIn("GatewayRuntime", source)


if __name__ == "__main__":
    unittest.main()
