from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
import time
import unittest
import zlib
from contextlib import suppress
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import zeus.audit_workspace as audit_workspace
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

    def _assert_private_directory(self, path: Path) -> None:
        result = path.lstat()
        self.assertTrue(stat.S_ISDIR(result.st_mode))
        self.assertEqual(os.geteuid(), result.st_uid)
        self.assertEqual(0o700, stat.S_IMODE(result.st_mode))

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

    def test_revalidate_repeats_external_object_source_checks(self) -> None:
        location = self.workspace.discover(self.repository, deadline=_deadline())
        alternates = self.repository / ".git" / "objects" / "info" / "alternates"
        alternates.write_text("/untrusted/object/store\n", encoding="utf-8")

        with self.assertRaisesRegex(AuditWorkspaceError, "alternate"):
            self.workspace.revalidate(location, deadline=_deadline())

    def test_committed_ignore_policy_is_loaded_from_exact_head(self) -> None:
        self.write(".gitignore", b".zeus/\n")
        self.commit("ignore audit state")
        location = self.workspace.discover(self.repository, deadline=_deadline())
        probes = (
            ".zeus/",
            ".zeus/audit/config.json",
            ".zeus/audit/runs/" + "0" * 32 + "/control",
        )

        self.write(".gitignore", b".zeus/only-this-file\n")
        matches = self.workspace.committed_ignore_matches(
            location,
            state_relative=Path(".zeus"),
            ignored_paths=probes,
            deadline=_deadline(),
        )

        self.assertEqual(set(probes), set(matches))
        self.assertEqual({".gitignore"}, set(matches.values()))

    def test_committed_ignore_policy_rejects_executable_and_oversized_sources(self) -> None:
        self.write(".gitignore", b".zeus/\n", mode=0o755)
        self.commit("executable ignore policy")
        executable_location = self.workspace.discover(
            self.repository,
            deadline=_deadline(),
        )
        with self.assertRaisesRegex(AuditWorkspaceError, "non-executable"):
            self.workspace.committed_ignore_matches(
                executable_location,
                state_relative=Path(".zeus"),
                ignored_paths=(".zeus/",),
                deadline=_deadline(),
            )

        self.write(
            ".gitignore",
            b"#" + b"x" * (256 * 1024) + b"\n.zeus/\n",
        )
        self.commit("oversized ignore policy")
        oversized_location = self.workspace.discover(
            self.repository,
            deadline=_deadline(),
        )
        with self.assertRaisesRegex(AuditWorkspaceError, "blob byte count"):
            self.workspace.committed_ignore_matches(
                oversized_location,
                state_relative=Path(".zeus"),
                ignored_paths=(".zeus/",),
                deadline=_deadline(),
            )

    def test_committed_ignore_policy_rejects_matching_negations(self) -> None:
        self.write(
            ".gitignore",
            b".zeus/\n!.zeus/\n!.zeus/**\n",
        )
        self.commit("negated ignore policy")
        location = self.workspace.discover(self.repository, deadline=_deadline())

        with self.assertRaisesRegex(AuditWorkspaceError, "negation"):
            self.workspace.committed_ignore_matches(
                location,
                state_relative=Path(".zeus"),
                ignored_paths=(
                    ".zeus/",
                    ".zeus/audit/config.json",
                ),
                deadline=_deadline(),
            )

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

    def test_inspection_stops_the_metadata_walk_at_the_caller_deadline(self) -> None:
        for index in range(8):
            self.write(f"tracked-{index}.txt", b"tracked\n")
        self.commit("tracked deadline fixtures")
        location = self.workspace.discover(self.repository, deadline=_deadline())
        original_lstat = audit_workspace._lstat_tracked_path
        caller_deadline = time.monotonic() + 0.5
        first_call = True

        def slow_lstat(root_descriptor: int, path: str) -> os.stat_result | None:
            nonlocal first_call
            if first_call:
                first_call = False
                time.sleep(max(0.0, caller_deadline - time.monotonic() + 0.02))
            else:
                time.sleep(0.06)
            return original_lstat(root_descriptor, path)

        started = time.monotonic()
        with (
            patch(
                "zeus.audit_workspace._lstat_tracked_path",
                side_effect=slow_lstat,
            ) as tracked_lstat,
            self.assertRaisesRegex(AuditWorkspaceError, "deadline"),
        ):
            self.workspace.inspect(location, deadline=caller_deadline)

        self.assertEqual(1, tracked_lstat.call_count)
        self.assertLess(time.monotonic() - started, 0.75)

    def test_directory_owner_mismatch_is_rejected(self) -> None:
        with (
            patch(
                "zeus.audit_workspace.os.geteuid",
                return_value=os.geteuid() + 1,
            ),
            self.assertRaisesRegex(AuditWorkspaceError, "owner"),
        ):
            audit_workspace._capture_safe_directory(
                self.repository,
                "repository root",
            )

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

        snapshot = self.materialize(exclude_paths=("excluded",))
        self.assertIn(
            ("excluded", "excluded by audit configuration"),
            {(item.path, item.reason) for item in snapshot.skipped_content},
        )

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

    def test_records_valid_sorted_extended_lfs_v1_pointer_as_skipped(self) -> None:
        oid = b"a" * 64
        pointer = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"custom metadata value \xe2\x9c\x93\n"
            b"ext-0-example sha256:" + b"b" * 64 + b"\n"
            b"oid sha256:" + oid + b"\n"
            b"size 1\n"
            b"x-note preserved\n"
        )
        self.write("extended.dat", pointer)
        self.commit("extended LFS pointer")

        snapshot = self.materialize()

        self.assertFalse((snapshot.root / "extended.dat").exists())
        self.assertIn(
            ("extended.dat", "git-lfs-pointer"),
            {(item.path, item.reason) for item in snapshot.skipped_content},
        )

    def test_treats_malformed_or_oversized_lfs_v1_forms_as_ordinary_files(self) -> None:
        oid = b"a" * 64
        oversize_prefix = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + oid + b"\n"
            b"size 1\n"
            b"x-padding "
        )
        oversized = oversize_prefix + b"a" * (1024 - len(oversize_prefix) - 1) + b"\n"
        self.assertEqual(1024, len(oversized))
        near_pointers = {
            "missing-final-lf.dat": (
                b"version https://git-lfs.github.com/spec/v1\noid sha256:" + oid + b"\nsize 1"
            ),
            "crlf.dat": (
                b"version https://git-lfs.github.com/spec/v1\r\n"
                b"oid sha256:" + oid + b"\r\n"
                b"size 1\r\n"
            ),
            "reordered.dat": (
                b"version https://git-lfs.github.com/spec/v1\nsize 1\noid sha256:" + oid + b"\n"
            ),
            "leading-zero-size.dat": (
                b"version https://git-lfs.github.com/spec/v1\noid sha256:" + oid + b"\nsize 01\n"
            ),
            "unsorted-extension.dat": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\n"
                b"ext-0-example value\n"
                b"size 1\n"
            ),
            "duplicate-key.dat": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"custom first\n"
                b"custom second\n"
                b"oid sha256:" + oid + b"\n"
                b"size 1\n"
            ),
            "double-space.dat": (
                b"version https://git-lfs.github.com/spec/v1\noid  sha256:" + oid + b"\nsize 1\n"
            ),
            "invalid-key.dat": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"Bad_key value\n"
                b"oid sha256:" + oid + b"\n"
                b"size 1\n"
            ),
            "invalid-utf8.dat": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"custom \xff\n"
                b"oid sha256:" + oid + b"\n"
                b"size 1\n"
            ),
            "duplicate-oid.dat": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\n"
                b"oid sha256:" + oid + b"\n"
                b"size 1\n"
            ),
            "uppercase-oid.dat": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + b"A" * 64 + b"\n"
                b"size 1\n"
            ),
            "oversized.dat": oversized,
        }
        for path, content in near_pointers.items():
            self.write(path, content)
        self.commit("near LFS pointers")

        snapshot = self.materialize()

        for path, content in near_pointers.items():
            with self.subTest(path=path):
                self.assertEqual(content, (snapshot.root / path).read_bytes())
        skipped_paths = {item.path for item in snapshot.skipped_content}
        self.assertTrue(skipped_paths.isdisjoint(near_pointers))

    def test_rejects_unsafe_symlink_targets_and_preserves_private_destination(self) -> None:
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

                self._assert_private_directory(self.temp_root / destination_name)

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

    def test_materialization_does_not_require_path_chmod(self) -> None:
        inspection = self.inspect()

        with patch(
            "zeus.audit_workspace.os.chmod",
            side_effect=NotImplementedError("follow_symlinks unavailable"),
        ):
            snapshot = self.materialize("descriptor-modes", inspection=inspection)

        self.assertEqual(b"committed\n", (snapshot.root / "README.md").read_bytes())
        self.workspace.validate_snapshot(snapshot)

    def test_rejects_destination_parent_swap_and_preserves_bound_leaf(self) -> None:
        output_parent = self.temp_root / "output"
        moved_parent = self.temp_root / "output-original"
        attacker = self.temp_root / "attacker"
        output_parent.mkdir(mode=0o700)
        attacker.mkdir(mode=0o700)
        destination = output_parent / "snapshot"
        inspection = self.inspect()
        original_mkdir = os.mkdir
        swapped = False

        def swapping_mkdir(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal swapped
            path_text = os.fsdecode(path)
            destination_call = (dir_fd is None and Path(path_text) == destination) or (
                dir_fd is not None and path_text == destination.name
            )
            if destination_call and not swapped:
                output_parent.rename(moved_parent)
                output_parent.symlink_to(attacker, target_is_directory=True)
                swapped = True
            if dir_fd is None:
                original_mkdir(path, mode)
            else:
                original_mkdir(path, mode, dir_fd=dir_fd)

        try:
            with (
                patch(
                    "zeus.audit_workspace.os.mkdir",
                    side_effect=swapping_mkdir,
                ),
                self.assertRaisesRegex(AuditWorkspaceError, "parent binding changed"),
            ):
                self.workspace.materialize(
                    inspection,
                    destination,
                    exclude_paths=(),
                    limits=HARD_LIMITS,
                    deadline=_deadline(),
                )

            self.assertTrue(swapped)
            self.assertFalse((attacker / destination.name).exists())
            self._assert_private_directory(moved_parent / destination.name)
        finally:
            if output_parent.is_symlink():
                output_parent.unlink()
            if moved_parent.exists():
                moved_parent.rename(output_parent)

    def test_failure_cleanup_never_removes_root_by_name(self) -> None:
        inspection = self.inspect()
        destination = self.temp_root / "cleanup-root"
        orphan = self.temp_root / "cleanup-root-original"
        opened = self.workspace._prepare_destination(
            inspection.location,
            destination,
        )
        original_rmdir = os.rmdir
        swapped = False

        def swapping_rmdir(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal swapped
            if (
                os.fsdecode(path) == destination.name
                and dir_fd == opened.parent_descriptor
                and not swapped
            ):
                destination.rename(orphan)
                destination.mkdir(mode=0o700)
                swapped = True
            if dir_fd is None:
                original_rmdir(path)
            else:
                original_rmdir(path, dir_fd=dir_fd)

        try:
            with patch(
                "zeus.audit_workspace.os.rmdir",
                side_effect=swapping_rmdir,
            ) as remove_directory:
                self.workspace._cleanup_opened_snapshot(opened)

            remove_directory.assert_not_called()
            self.assertFalse(swapped)
            self._assert_private_directory(destination)
            self.assertFalse(orphan.exists())
        finally:
            with suppress(OSError):
                os.close(opened.root_descriptor)
            with suppress(OSError):
                os.close(opened.parent_descriptor)

    def test_failure_cleanup_never_unlinks_child_by_name(self) -> None:
        inspection = self.inspect()
        destination = self.temp_root / "cleanup-file"
        opened = self.workspace._prepare_destination(
            inspection.location,
            destination,
        )
        payload = destination / "payload"
        payload.write_bytes(b"original")
        payload.chmod(0o600)
        original_unlink = os.unlink
        swapped = False

        def swapping_unlink(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal swapped
            if os.fsdecode(path) == payload.name and dir_fd is not None and not swapped:
                os.rename(
                    payload.name,
                    "payload-original",
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
                replacement = os.open(
                    payload.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=dir_fd,
                )
                try:
                    os.write(replacement, b"replacement")
                finally:
                    os.close(replacement)
                swapped = True
            if dir_fd is None:
                original_unlink(path)
            else:
                original_unlink(path, dir_fd=dir_fd)

        try:
            with patch(
                "zeus.audit_workspace.os.unlink",
                side_effect=swapping_unlink,
            ) as unlink:
                self.workspace._cleanup_opened_snapshot(opened)

            unlink.assert_not_called()
            self.assertFalse(swapped)
            self.assertEqual(b"original", payload.read_bytes())
            self.assertFalse((destination / "payload-original").exists())
            self._assert_private_directory(destination)
        finally:
            with suppress(OSError):
                os.close(opened.root_descriptor)
            with suppress(OSError):
                os.close(opened.parent_descriptor)

    def test_failure_cleanup_never_removes_child_directory_by_name(self) -> None:
        inspection = self.inspect()
        destination = self.temp_root / "cleanup-directory"
        opened = self.workspace._prepare_destination(
            inspection.location,
            destination,
        )
        child = destination / "nested"
        child.mkdir(mode=0o700)
        original_rmdir = os.rmdir
        swapped = False

        def swapping_rmdir(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal swapped
            if os.fsdecode(path) == child.name and dir_fd is not None and not swapped:
                os.rename(
                    child.name,
                    "nested-original",
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
                os.mkdir(child.name, mode=0o700, dir_fd=dir_fd)
                swapped = True
            if dir_fd is None:
                original_rmdir(path)
            else:
                original_rmdir(path, dir_fd=dir_fd)

        try:
            with patch(
                "zeus.audit_workspace.os.rmdir",
                side_effect=swapping_rmdir,
            ) as remove_directory:
                self.workspace._cleanup_opened_snapshot(opened)

            remove_directory.assert_not_called()
            self.assertFalse(swapped)
            self._assert_private_directory(child)
            self.assertFalse((destination / "nested-original").exists())
            self._assert_private_directory(destination)
        finally:
            with suppress(OSError):
                os.close(opened.root_descriptor)
            with suppress(OSError):
                os.close(opened.parent_descriptor)

    def test_rejects_destinations_inside_repository_boundaries(self) -> None:
        inspection = self.inspect()
        destinations = [
            self.repository / "snapshot",
            self.repository / ".git" / "snapshot",
        ]
        case_alias = self.repository.with_name(self.repository.name.upper())
        if case_alias != self.repository and case_alias.exists():
            destinations.append(case_alias / "case-alias-snapshot")
        for destination in destinations:
            with (
                self.subTest(destination=destination),
                self.assertRaisesRegex(AuditWorkspaceError, "inside repository"),
            ):
                self.workspace.materialize(
                    inspection,
                    destination,
                    exclude_paths=(),
                    limits=HARD_LIMITS,
                    deadline=_deadline(),
                )
            self.assertFalse(destination.exists())

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

    def test_final_snapshot_validation_honors_materialization_deadline(self) -> None:
        inspection = self.inspect()
        destination = self.temp_root / "validation-deadline"
        caller_deadline = time.monotonic() + 0.7
        original_hash = self.workspace._hash_regular_file_at
        observed_deadlines: list[float | None] = []

        def expire_during_hash(
            parent_descriptor: int,
            name: str,
            expected: os.stat_result,
            *,
            deadline: float | None = None,
        ) -> str:
            observed_deadlines.append(deadline)
            time.sleep(max(0.0, caller_deadline - time.monotonic() + 0.02))
            if deadline is None:
                return original_hash(parent_descriptor, name, expected)
            return original_hash(
                parent_descriptor,
                name,
                expected,
                deadline=deadline,
            )

        with (
            patch.object(
                self.workspace,
                "_hash_regular_file_at",
                side_effect=expire_during_hash,
            ) as hash_file,
            self.assertRaisesRegex(AuditWorkspaceError, "deadline"),
        ):
            self.workspace.materialize(
                inspection,
                destination,
                exclude_paths=(),
                limits=HARD_LIMITS,
                deadline=caller_deadline,
            )

        self.assertEqual(1, hash_file.call_count)
        self.assertEqual([caller_deadline], observed_deadlines)
        self._assert_private_directory(destination)

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
            ("drive-relative", ((b"100644", b"C:outside", blob_id),)),
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

    def test_rejects_index_and_untracked_protocol_drift(self) -> None:
        oid = b"a" * 40
        valid = (
            b"100644 " + oid + b" 0\ttracked.txt\0"
            b"  ctime: 1:2\n"
            b"  mtime: 3:4\n"
            b"  dev: 5\tino: 6\n"
            b"  uid: 7\tgid: 8\n"
            b"  size: 9\tflags: 0\n"
        )
        malformed_index_records = (
            valid[:-1],
            valid + valid,
            valid.replace(b"  mtime:", b" mtime:", 1),
        )
        for record in malformed_index_records:
            with (
                self.subTest(record=record),
                self.assertRaises(AuditWorkspaceError),
            ):
                audit_workspace._parse_index_metadata(record, HARD_LIMITS)

        for record in (b"unterminated", b"path\0\0"):
            with (
                self.subTest(untracked=record),
                self.assertRaises(AuditWorkspaceError),
            ):
                audit_workspace._parse_untracked_metadata(record)
