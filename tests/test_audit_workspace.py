from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
import time
import unittest
import zlib
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.audit_workspace import (
    AuditWorkspace,
    AuditWorkspaceError,
    MaterializedSnapshot,
    RepositoryChanges,
    RepositoryInspection,
    _parse_tree,
)


def _deadline(seconds: float = 10.0) -> float:
    return time.monotonic() + seconds


def _limits(**overrides: int) -> AuditLimits:
    return replace(HARD_LIMITS, **overrides)


class TemporaryGitRepository(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.temp_root = Path(self.temporary_directory.name).resolve()
        self.repository = self.temp_root / "repository"
        self.repository.mkdir(mode=0o700)
        self.git("init", "--quiet", "--object-format=sha1")
        self.git("config", "user.name", "Audit Test")
        self.git("config", "user.email", "audit@example.invalid")
        self.write("README.md", b"committed\n")
        self.git("add", "README.md")
        self.git("commit", "--quiet", "-m", "initial")
        self.workspace = AuditWorkspace()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def git(
        self,
        *arguments: str,
        input_data: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            input=input_data,
            capture_output=True,
            check=False,
            shell=False,
            timeout=10,
        )
        if check and completed.returncode != 0:
            self.fail(
                f"git {' '.join(arguments)} failed with {completed.returncode}: "
                f"{completed.stderr.decode('utf-8', errors='replace')}"
            )
        return completed

    def write(self, relative_path: str, data: bytes, *, mode: int = 0o644) -> Path:
        path = self.repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def commit(self, message: str = "update") -> str:
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.decode("ascii").strip()

    def inspect(self) -> RepositoryInspection:
        location = self.workspace.discover(self.repository, deadline=_deadline())
        return self.workspace.inspect(location, deadline=_deadline())

    def materialize(
        self,
        destination_name: str = "snapshot",
        *,
        exclude_paths: tuple[str, ...] = (),
        limits: AuditLimits = HARD_LIMITS,
        inspection: RepositoryInspection | None = None,
        deadline: float | None = None,
    ) -> MaterializedSnapshot:
        active_inspection = self.inspect() if inspection is None else inspection
        return self.workspace.materialize(
            active_inspection,
            self.temp_root / destination_name,
            exclude_paths=exclude_paths,
            limits=limits,
            deadline=_deadline() if deadline is None else deadline,
        )

    def _store_object(self, object_type: str, body: bytes) -> str:
        payload = f"{object_type} {len(body)}\0".encode("ascii") + body
        # The repository fixture explicitly uses Git's SHA-1 object format.
        object_id = hashlib.sha1(payload).hexdigest()
        object_path = self.repository / ".git" / "objects" / object_id[:2] / object_id[2:]
        object_path.parent.mkdir(mode=0o755, exist_ok=True)
        object_path.write_bytes(zlib.compress(payload))
        return object_id

    def _raw_tree(
        self,
        entries: tuple[tuple[bytes, bytes, str], ...],
    ) -> str:
        body = b"".join(
            mode + b" " + name + b"\0" + bytes.fromhex(object_id)
            for mode, name, object_id in entries
        )
        return self._store_object("tree", body)

    def install_raw_head(self, entries: tuple[tuple[bytes, bytes, str], ...]) -> str:
        tree_id = self._raw_tree(entries)
        commit_body = (
            f"tree {tree_id}\n"
            "author Audit Test <audit@example.invalid> 1700000000 +0000\n"
            "committer Audit Test <audit@example.invalid> 1700000000 +0000\n"
            "\n"
            "raw tree\n"
        ).encode("ascii")
        commit_id = self._store_object("commit", commit_body)
        self.git("update-ref", "HEAD", commit_id)
        return commit_id


class AuditWorkspaceDiscoveryTests(TemporaryGitRepository):
    def test_discovers_root_git_directories_repository_id_and_committed_head(self) -> None:
        nested = self.repository / "one" / "two"
        nested.mkdir(parents=True)

        location = self.workspace.discover(nested, deadline=_deadline())

        self.assertEqual(self.repository, location.root)
        self.assertEqual(self.repository / ".git", location.git_dir)
        self.assertEqual(location.git_dir, location.common_git_dir)
        self.assertEqual(
            self.git("rev-parse", "HEAD").stdout.decode("ascii").strip(),
            location.head,
        )
        self.assertRegex(location.repository_id, r"\A[0-9a-f]{64}\Z")
        self.assertNotIn(str(self.repository), location.repository_id)
        second = self.workspace.discover(self.repository, deadline=_deadline())
        self.assertEqual(location, second)
        with self.assertRaises(FrozenInstanceError):
            location.head = "0" * 40  # type: ignore[misc]

    def test_revalidate_rejects_head_changes_after_a_run_lock_would_be_taken(self) -> None:
        location = self.workspace.discover(self.repository, deadline=_deadline())
        self.write("second.txt", b"second\n")
        self.commit("second")

        with self.assertRaisesRegex(AuditWorkspaceError, "changed"):
            self.workspace.revalidate(location, deadline=_deadline())

    def test_inspection_records_only_dirty_staged_and_untracked_state(self) -> None:
        self.write("README.md", b"dirty worktree sentinel\n")
        self.write("staged.txt", b"staged content sentinel\n")
        self.git("add", "staged.txt")
        self.write("untracked-secret-name.txt", b"untracked content sentinel\n")
        location = self.workspace.discover(self.repository, deadline=_deadline())

        inspection = self.workspace.inspect(location, deadline=_deadline())

        self.assertTrue(inspection.changes.dirty)
        self.assertTrue(inspection.changes.staged)
        self.assertTrue(inspection.changes.untracked)
        self.assertTrue(inspection.changes.has_changes)
        self.assertNotIn("secret", repr(inspection.changes))

    def test_rejects_group_or_other_writable_repository_boundaries(self) -> None:
        cases = (self.repository, self.repository / ".git")
        for path in cases:
            with self.subTest(path=path.name):
                original_mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(original_mode | 0o022)
                try:
                    with self.assertRaisesRegex(AuditWorkspaceError, "permissions"):
                        self.workspace.discover(self.repository, deadline=_deadline())
                finally:
                    path.chmod(original_mode)

    def test_rejects_symlinked_git_administration_marker(self) -> None:
        git_directory = self.repository / ".git"
        moved_directory = self.repository / "git-admin"
        git_directory.rename(moved_directory)
        git_directory.symlink_to(moved_directory.name, target_is_directory=True)

        with self.assertRaises(AuditWorkspaceError):
            self.workspace.discover(self.repository, deadline=_deadline())

    def test_rejects_symlinked_head_metadata(self) -> None:
        head = self.repository / ".git" / "HEAD"
        real_head = head.with_name("HEAD.real")
        head.rename(real_head)
        head.symlink_to(real_head.name)

        with self.assertRaises(AuditWorkspaceError):
            self.workspace.discover(self.repository, deadline=_deadline())

    def test_inspection_rejects_object_alternates_and_replacement_refs(self) -> None:
        location = self.workspace.discover(self.repository, deadline=_deadline())
        alternates = self.repository / ".git" / "objects" / "info" / "alternates"
        alternates.write_text("/untrusted/object/store\n", encoding="utf-8")
        with self.assertRaisesRegex(AuditWorkspaceError, "alternate"):
            self.workspace.inspect(location, deadline=_deadline())
        alternates.unlink()

        old_head = location.head
        self.write("replacement.txt", b"replacement\n")
        new_head = self.commit("replacement")
        self.git("replace", new_head, old_head)
        replacement_location = self.workspace.discover(self.repository, deadline=_deadline())
        with self.assertRaisesRegex(AuditWorkspaceError, "replacement"):
            self.workspace.inspect(replacement_location, deadline=_deadline())

    def test_rejects_symlinked_object_database(self) -> None:
        objects = self.repository / ".git" / "objects"
        moved_objects = self.repository / "object-store"
        objects.rename(moved_objects)
        objects.symlink_to(moved_objects, target_is_directory=True)

        with self.assertRaisesRegex(AuditWorkspaceError, "symbolic link"):
            self.workspace.discover(self.repository, deadline=_deadline())

    def test_rejects_expired_deadlines_before_launching_git(self) -> None:
        with self.assertRaisesRegex(AuditWorkspaceError, "deadline"):
            self.workspace.discover(self.repository, deadline=time.monotonic() - 1)


class AuditWorkspaceMaterializationTests(TemporaryGitRepository):
    def test_materializes_committed_regular_executable_and_confined_symlink_entries(
        self,
    ) -> None:
        self.write("bin/tool", b"#!/bin/sh\nexit 0\n", mode=0o755)
        (self.repository / "tool-link").symlink_to("bin/tool")
        expected_head = self.commit("files")

        snapshot = self.materialize()

        self.assertEqual(expected_head, snapshot.head)
        self.assertEqual(b"committed\n", (snapshot.root / "README.md").read_bytes())
        self.assertEqual(b"#!/bin/sh\nexit 0\n", (snapshot.root / "bin/tool").read_bytes())
        self.assertTrue((snapshot.root / "bin/tool").stat().st_mode & stat.S_IXUSR)
        self.assertTrue((snapshot.root / "tool-link").is_symlink())
        self.assertEqual("bin/tool", os.readlink(snapshot.root / "tool-link"))
        manifest = {entry.path: entry for entry in snapshot.manifest}
        self.assertEqual({"README.md", "bin/tool", "tool-link"}, set(manifest))
        self.assertEqual("100755", manifest["bin/tool"].git_mode)
        self.assertEqual("120000", manifest["tool-link"].git_mode)
        self.assertEqual("bin/tool", manifest["tool-link"].symlink_target)
        self.workspace.validate_snapshot(snapshot)

    def test_streams_a_large_blob_without_losing_prefetched_protocol_bytes(self) -> None:
        content = bytes(range(256)) * 400
        self.write("large.bin", content)
        self.commit("large streamed blob")

        snapshot = self.materialize()

        self.assertEqual(content, (snapshot.root / "large.bin").read_bytes())
        self.workspace.validate_snapshot(snapshot)

    def test_reads_committed_objects_instead_of_dirty_or_untracked_worktree_content(
        self,
    ) -> None:
        dirty_sentinel = b"dirty worktree must not enter snapshot\n"
        untracked_sentinel = b"untracked must not enter snapshot\n"
        self.write("README.md", dirty_sentinel)
        self.write("untracked.txt", untracked_sentinel)

        snapshot = self.materialize()

        self.assertEqual(b"committed\n", (snapshot.root / "README.md").read_bytes())
        self.assertFalse((snapshot.root / "untracked.txt").exists())
        self.assertEqual(dirty_sentinel, (self.repository / "README.md").read_bytes())
        self.assertEqual(untracked_sentinel, (self.repository / "untracked.txt").read_bytes())

    def test_applies_exclusions_only_after_counting_all_source_entries_and_bytes(self) -> None:
        self.write("excluded/large.bin", b"0123456789")
        self.commit("large")
        inspection = self.inspect()

        with self.assertRaisesRegex(AuditWorkspaceError, "blob byte"):
            self.materialize(
                "byte-limited",
                inspection=inspection,
                exclude_paths=("excluded",),
                limits=_limits(snapshot_blob_bytes=9),
            )
        with self.assertRaisesRegex(AuditWorkspaceError, "entry"):
            self.materialize(
                "entry-limited",
                inspection=inspection,
                exclude_paths=("excluded",),
                limits=_limits(snapshot_entries=1),
            )
        self.assertFalse((self.temp_root / "byte-limited").exists())
        self.assertFalse((self.temp_root / "entry-limited").exists())

    def test_records_gitlinks_and_lfs_pointers_without_hydrating_them(self) -> None:
        lfs_pointer = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"a" * 64 + b"\n"
            b"size 123456\n"
        )
        self.write("large.dat", lfs_pointer)
        self.commit("lfs pointer")
        head = self.git("rev-parse", "HEAD").stdout.decode("ascii").strip()
        self.git("update-index", "--add", "--cacheinfo", f"160000,{head},dependency")
        self.git("commit", "--quiet", "-m", "gitlink")

        snapshot = self.materialize()

        self.assertFalse((snapshot.root / "large.dat").exists())
        self.assertFalse((snapshot.root / "dependency").exists())
        skipped = {(item.path, item.reason) for item in snapshot.skipped_content}
        self.assertEqual(
            {
                ("dependency", "gitlink"),
                ("large.dat", "git-lfs-pointer"),
            },
            skipped,
        )

    def test_rejects_unsafe_symlink_targets_and_cleans_owned_destination(self) -> None:
        for index, target in enumerate(("/absolute", "../../escape", "C:/outside")):
            with self.subTest(target=target):
                link = self.repository / "unsafe-link"
                if os.path.lexists(link):
                    link.unlink()
                link.symlink_to(target)
                self.commit(f"unsafe link {index}")
                destination_name = f"unsafe-{index}"

                with self.assertRaisesRegex(AuditWorkspaceError, "symlink"):
                    self.materialize(destination_name)

                self.assertFalse((self.temp_root / destination_name).exists())

    def test_rejects_existing_destination_without_changing_it(self) -> None:
        destination = self.temp_root / "existing"
        destination.mkdir(mode=0o700)
        marker = destination / "marker"
        marker.write_bytes(b"preserve")
        inspection = self.inspect()

        with self.assertRaisesRegex(AuditWorkspaceError, "already exists"):
            self.workspace.materialize(
                inspection,
                destination,
                exclude_paths=(),
                limits=HARD_LIMITS,
                deadline=_deadline(),
            )

        self.assertEqual(b"preserve", marker.read_bytes())

    def test_rejects_git_metadata_output_ceiling_and_expired_materialization_deadline(
        self,
    ) -> None:
        inspection = self.inspect()
        with self.assertRaisesRegex(AuditWorkspaceError, "metadata"):
            self.materialize(
                "metadata-limited",
                inspection=inspection,
                limits=_limits(git_metadata_bytes=8),
            )
        with self.assertRaisesRegex(AuditWorkspaceError, "deadline"):
            self.materialize(
                "deadline-expired",
                inspection=inspection,
                deadline=time.monotonic() - 1,
            )
        self.assertFalse((self.temp_root / "metadata-limited").exists())
        self.assertFalse((self.temp_root / "deadline-expired").exists())

    def test_validate_snapshot_rejects_content_mode_and_extra_entry_changes(self) -> None:
        snapshot = self.materialize()
        readme = snapshot.root / "README.md"
        readme.write_bytes(b"changed\n")
        with self.assertRaisesRegex(AuditWorkspaceError, "manifest"):
            self.workspace.validate_snapshot(snapshot)

        readme.write_bytes(b"committed\n")
        readme.chmod(0o700)
        with self.assertRaisesRegex(AuditWorkspaceError, "manifest"):
            self.workspace.validate_snapshot(snapshot)

        readme.chmod(0o600)
        (snapshot.root / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(AuditWorkspaceError, "manifest"):
            self.workspace.validate_snapshot(snapshot)

    def test_rejects_head_race_during_materialization(self) -> None:
        inspection = self.inspect()
        self.write("raced.txt", b"new head\n")
        self.commit("raced head")

        with self.assertRaisesRegex(AuditWorkspaceError, "changed"):
            self.materialize("raced", inspection=inspection)

        self.assertFalse((self.temp_root / "raced").exists())

    def test_rejects_unsafe_tree_paths_collisions_conflicts_and_modes(self) -> None:
        blob_id = self._store_object("blob", b"value")
        child_tree = self._raw_tree(((b"100644", b"child", blob_id),))
        cases: tuple[
            tuple[str, tuple[tuple[bytes, bytes, str], ...]],
            ...,
        ] = (
            ("dot-git", ((b"100644", b".GiT", blob_id),)),
            (
                "case-collision",
                (
                    (b"100644", b"File", blob_id),
                    (b"100644", b"file", blob_id),
                ),
            ),
            (
                "duplicate",
                (
                    (b"100644", b"same", blob_id),
                    (b"100644", b"same", blob_id),
                ),
            ),
            (
                "path-conflict",
                (
                    (b"100644", b"node", blob_id),
                    (b"40000", b"node", child_tree),
                ),
            ),
            ("traversal", ((b"100644", b"..", blob_id),)),
            ("invalid-utf8", ((b"100644", b"\xff", blob_id),)),
            (
                "non-normalized-unicode",
                ((b"100644", "cafe\u0301".encode(), blob_id),),
            ),
        )
        for label, entries in cases:
            with self.subTest(case=label):
                self.install_raw_head(entries)
                location = self.workspace.discover(self.repository, deadline=_deadline())
                inspection = RepositoryInspection(
                    location=location,
                    changes=RepositoryChanges(
                        dirty=False,
                        staged=False,
                        untracked=False,
                    ),
                )
                destination = self.temp_root / f"invalid-{label}"

                with self.assertRaises(AuditWorkspaceError):
                    self.workspace.materialize(
                        inspection,
                        destination,
                        exclude_paths=(),
                        limits=HARD_LIMITS,
                        deadline=_deadline(),
                    )

                self.assertFalse(destination.exists())

    def test_rejects_unsupported_mode_from_the_ls_tree_protocol(self) -> None:
        record = b"100664 blob " + b"a" * 40 + b" 1\todd-mode\0"

        with self.assertRaisesRegex(AuditWorkspaceError, "unsupported mode"):
            _parse_tree(record, HARD_LIMITS)
