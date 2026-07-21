from __future__ import annotations

import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import BinaryIO
from unittest.mock import patch

from zeus import private_io
from zeus.private_io import (
    UnsafeFileError,
    append_private_bytes,
    open_private_append,
    read_private_tail,
    validate_private_directory,
)


class PrivateIOTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def assert_all_closed(self, descriptors: set[int]) -> None:
        for descriptor in descriptors:
            with self.subTest(descriptor=descriptor), self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_append_and_tail_preserve_exact_bytes(self) -> None:
        path = self.root / "logs" / "events.bin"
        first = b"first\x00line\n"
        second = b"\xffsecond\n"

        append_private_bytes(path, first)
        append_private_bytes(path, second)

        expected = first + second
        self.assertEqual(expected, path.read_bytes())
        self.assertEqual(expected, read_private_tail(path, len(expected) + 100))
        self.assertEqual(expected[-7:], read_private_tail(path, 7))
        self.assertEqual(b"", read_private_tail(path, 0))

    def test_open_private_append_is_unbuffered_and_always_appends(self) -> None:
        path = self.root / "logs" / "events.bin"
        append_private_bytes(path, b"first")

        with open_private_append(path) as handle:
            self.assertIsInstance(handle, io.RawIOBase)
            self.assertNotIsInstance(handle, io.BufferedIOBase)
            handle.seek(0)
            self.assertEqual(6, handle.write(b"second"))

        self.assertEqual(b"firstsecond", path.read_bytes())

    def test_read_missing_leaf_returns_empty_without_creating_it(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "missing.log"

        self.assertEqual(b"", read_private_tail(path, 128))

        self.assertFalse(path.exists())

    def test_read_missing_ancestor_returns_empty_without_creating_it(self) -> None:
        path = self.root / "missing" / "nested" / "events.log"

        self.assertEqual(b"", read_private_tail(path, 128))

        self.assertFalse(self.root.joinpath("missing").exists())

    def test_missing_tail_rejects_rebound_open_ancestor_and_closes_descriptors(self) -> None:
        ancestor = self.root / "safe"
        ancestor.mkdir(mode=0o700)
        displaced = self.root / "safe-displaced"
        external = self.root / "external"
        (external / "missing").mkdir(parents=True)
        target = external / "missing" / "events.log"
        target.write_bytes(b"external target")
        target_mode = stat.S_IMODE(target.stat().st_mode)
        path = ancestor / "missing" / "events.log"
        ancestor_identity = ancestor.stat()
        opened: set[int] = set()
        real_lstat = os.lstat
        real_open = os.open
        swapped = False

        def racing_lstat(
            name: str | bytes,
            *,
            dir_fd: int | None = None,
        ) -> os.stat_result:
            nonlocal swapped
            if not swapped and name == "missing" and dir_fd is not None:
                parent = os.fstat(dir_fd)
                if (
                    parent.st_dev == ancestor_identity.st_dev
                    and parent.st_ino == ancestor_identity.st_ino
                ):
                    ancestor.rename(displaced)
                    ancestor.symlink_to(external, target_is_directory=True)
                    swapped = True
            return real_lstat(name, dir_fd=dir_fd)

        def tracking_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = real_open(name, flags, mode, dir_fd=dir_fd)
            opened.add(descriptor)
            return descriptor

        with (
            patch.object(private_io.os, "lstat", side_effect=racing_lstat),
            patch.object(private_io.os, "open", side_effect=tracking_open),
            self.assertRaises(UnsafeFileError),
        ):
            read_private_tail(path, 128)

        self.assertTrue(swapped)
        self.assertEqual(b"external target", target.read_bytes())
        self.assertEqual(target_mode, stat.S_IMODE(target.stat().st_mode))
        self.assert_all_closed(opened)

    def test_missing_tail_rejects_leaf_appearing_after_observation_and_closes_descriptors(
        self,
    ) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        opened: set[int] = set()
        real_lstat = os.lstat
        real_open = os.open
        appeared = False

        def racing_lstat(
            name: str | bytes,
            *,
            dir_fd: int | None = None,
        ) -> os.stat_result:
            nonlocal appeared
            if not appeared and name == path.name and dir_fd is not None:
                try:
                    return real_lstat(name, dir_fd=dir_fd)
                except FileNotFoundError:
                    path.write_bytes(b"appeared after missing observation")
                    path.chmod(0o644)
                    appeared = True
                    raise
            return real_lstat(name, dir_fd=dir_fd)

        def tracking_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = real_open(name, flags, mode, dir_fd=dir_fd)
            opened.add(descriptor)
            return descriptor

        with (
            patch.object(private_io.os, "lstat", side_effect=racing_lstat),
            patch.object(private_io.os, "open", side_effect=tracking_open),
            self.assertRaises(UnsafeFileError),
        ):
            read_private_tail(path, 128)

        self.assertTrue(appeared)
        self.assertEqual(b"appeared after missing observation", path.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))
        self.assert_all_closed(opened)

    def test_tail_size_validation_happens_before_filesystem_mutation(self) -> None:
        path = self.root / "missing" / "events.log"

        for value in (True, -1, 1.5, "1", None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                read_private_tail(path, value)  # type: ignore[arg-type]

        self.assertFalse(path.parent.exists())

    def test_unsupported_path_shapes_fail_before_mutation(self) -> None:
        traversal_parent = self.root / "new" / ".." / "escape"

        for path in (Path("relative.log"), traversal_parent / "events.log", Path("/")):
            with self.subTest(path=path), self.assertRaises(UnsafeFileError):
                append_private_bytes(path, b"event")

        self.assertFalse((self.root / "new").exists())

    def test_missing_security_flag_fails_before_creation(self) -> None:
        path = self.root / "missing" / "events.log"

        with (
            patch.object(private_io.os, "O_NOFOLLOW", 0),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertFalse(path.parent.exists())

    def test_missing_descriptor_relative_primitive_fails_before_creation(self) -> None:
        path = self.root / "missing" / "events.log"

        with (
            patch.object(private_io.os, "supports_dir_fd", frozenset()),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertFalse(path.parent.exists())

    def test_validate_private_directory_requires_existing_directory(self) -> None:
        path = self.root / "missing"

        with self.assertRaises(UnsafeFileError):
            validate_private_directory(path)

        self.assertFalse(path.exists())

    def test_new_and_final_private_directories_are_tightened_without_changing_ancestors(
        self,
    ) -> None:
        ancestor = self.root / "ancestor"
        ancestor.mkdir(mode=0o755)
        ancestor.chmod(0o755)
        private_dir = ancestor / "private"
        private_dir.mkdir(mode=0o755)
        private_dir.chmod(0o755)

        validate_private_directory(private_dir)
        append_private_bytes(private_dir / "nested" / "events.log", b"event")

        self.assertEqual(0o755, stat.S_IMODE(ancestor.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(private_dir.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE((private_dir / "nested").stat().st_mode))

    def test_directory_link_count_is_not_restricted_to_one(self) -> None:
        private_dir = self.root / "private"
        (private_dir / "child").mkdir(parents=True)
        self.assertGreater(private_dir.stat().st_nlink, 1)

        validate_private_directory(private_dir)

        self.assertEqual(0o700, stat.S_IMODE(private_dir.stat().st_mode))

    def test_validate_directory_rejects_mode_drift_before_final_lstat(self) -> None:
        private_dir = self.root / "mode-drift-dir"
        private_dir.mkdir(mode=0o755)
        private_dir.chmod(0o755)
        real_lstat = os.lstat
        directory_lstats = 0

        def racing_lstat(name: str | bytes, *, dir_fd: int | None = None) -> os.stat_result:
            nonlocal directory_lstats
            if name == private_dir.name and dir_fd is not None:
                directory_lstats += 1
                if directory_lstats == 3:
                    private_dir.chmod(0o777)
            return real_lstat(name, dir_fd=dir_fd)

        with (
            patch.object(private_io.os, "lstat", side_effect=racing_lstat),
            self.assertRaises(UnsafeFileError),
        ):
            validate_private_directory(private_dir)

        self.assertEqual(3, directory_lstats)
        self.assertEqual(0o777, stat.S_IMODE(private_dir.stat().st_mode))

    def test_existing_file_and_parent_modes_are_tightened_before_append(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o755)
        path = private_dir / "events.log"
        path.write_bytes(b"existing")
        private_dir.chmod(0o755)
        path.chmod(0o644)

        append_private_bytes(path, b"event")

        self.assertEqual(0o700, stat.S_IMODE(private_dir.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(b"existingevent", path.read_bytes())

    def test_read_tightens_existing_file_mode(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        path.write_bytes(b"event")
        path.chmod(0o644)

        self.assertEqual(b"event", read_private_tail(path, 10))

        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_append_rejects_mode_drift_before_final_lstat(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "mode-drift.log"
        path.write_bytes(b"original")
        path.chmod(0o644)
        real_lstat = os.lstat
        file_lstats = 0

        def racing_lstat(name: str | bytes, *, dir_fd: int | None = None) -> os.stat_result:
            nonlocal file_lstats
            if name == path.name and dir_fd is not None:
                file_lstats += 1
                if file_lstats == 3:
                    path.chmod(0o644)
            return real_lstat(name, dir_fd=dir_fd)

        with (
            patch.object(private_io.os, "lstat", side_effect=racing_lstat),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertEqual(3, file_lstats)
        self.assertEqual(b"original", path.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))

    def test_leaf_symlink_is_rejected_without_touching_target(self) -> None:
        target = self.root / "target.log"
        target.write_bytes(b"original")
        path = self.root / "events.log"
        path.symlink_to(target)

        with self.assertRaises(UnsafeFileError):
            append_private_bytes(path, b"event")
        with self.assertRaises(UnsafeFileError):
            read_private_tail(path, 10)

        self.assertEqual(b"original", target.read_bytes())

    def test_intermediate_directory_symlink_is_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(UnsafeFileError):
            append_private_bytes(linked / "logs" / "events.log", b"event")

        self.assertFalse((outside / "logs").exists())

    def test_final_parent_symlink_is_rejected_without_tightening_target(self) -> None:
        outside = self.root / "outside"
        outside.mkdir(mode=0o755)
        outside.chmod(0o755)
        state = self.root / "state"
        state.mkdir()
        linked = state / "logs"
        linked.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(UnsafeFileError):
            append_private_bytes(linked / "events.log", b"event")

        self.assertFalse((outside / "events.log").exists())
        self.assertEqual(0o755, stat.S_IMODE(outside.stat().st_mode))

    def test_hardlink_is_rejected_before_chmod_or_io(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        target = private_dir / "target.log"
        target.write_bytes(b"original")
        target.chmod(0o644)
        path = private_dir / "events.log"
        os.link(target, path)

        with self.assertRaises(UnsafeFileError):
            append_private_bytes(path, b"event")
        with self.assertRaises(UnsafeFileError):
            read_private_tail(path, 10)

        self.assertEqual(b"original", target.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(target.stat().st_mode))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_fifo_is_rejected_in_bounded_subprocesses(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.fifo"
        os.mkfifo(path, mode=0o600)
        expressions = (
            "append_private_bytes(path, b'event')",
            "read_private_tail(path, 1)",
        )

        for expression in expressions:
            script = f"""
import sys
from pathlib import Path
from zeus.private_io import UnsafeFileError, append_private_bytes, read_private_tail
path = Path(sys.argv[1])
try:
    {expression}
except UnsafeFileError:
    raise SystemExit(0)
raise SystemExit(1)
"""
            with self.subTest(expression=expression):
                result = subprocess.run(
                    [sys.executable, "-c", script, str(path)],
                    check=False,
                    capture_output=True,
                    timeout=2,
                )
                self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))

    def test_directory_leaf_is_rejected(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        path.mkdir()

        with self.assertRaises(UnsafeFileError):
            append_private_bytes(path, b"event")
        with self.assertRaises(UnsafeFileError):
            read_private_tail(path, 10)

    def test_final_directory_owner_mismatch_is_rejected_before_chmod(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o755)
        private_dir.chmod(0o755)

        with (
            patch.object(private_io.os, "geteuid", return_value=os.geteuid() + 1),
            self.assertRaises(UnsafeFileError),
        ):
            validate_private_directory(private_dir)

        self.assertEqual(0o755, stat.S_IMODE(private_dir.stat().st_mode))

    def test_file_owner_mismatch_is_rejected_before_chmod_or_io(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        path.write_bytes(b"original")
        path.chmod(0o644)
        real_fstat = os.fstat

        def mismatched_file_owner(fd: int) -> os.stat_result:
            result = real_fstat(fd)
            if stat.S_ISREG(result.st_mode):
                fields = list(result)
                fields[4] = result.st_uid + 1
                return os.stat_result(fields)
            return result

        with (
            patch.object(private_io.os, "fstat", side_effect=mismatched_file_owner),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertEqual(b"original", path.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))

    def test_file_replacement_between_lstat_and_open_is_rejected(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        path.write_bytes(b"original")
        replacement = private_dir / "replacement.log"
        replacement.write_bytes(b"replacement")
        displaced = private_dir / "displaced.log"
        real_open = os.open
        swapped = False

        def racing_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if not swapped and name == path.name and dir_fd is not None:
                path.rename(displaced)
                replacement.rename(path)
                swapped = True
            return real_open(name, flags, mode, dir_fd=dir_fd)

        with (
            patch.object(private_io.os, "open", side_effect=racing_open),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertTrue(swapped)
        self.assertEqual(b"original", displaced.read_bytes())
        self.assertEqual(b"replacement", path.read_bytes())

    def test_file_replacement_before_post_lstat_is_rejected(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        path.write_bytes(b"original")
        replacement = private_dir / "replacement.log"
        replacement.write_bytes(b"replacement")
        displaced = private_dir / "displaced.log"
        real_lstat = os.lstat
        leaf_lstats = 0

        def racing_lstat(name: str | bytes, *, dir_fd: int | None = None) -> os.stat_result:
            nonlocal leaf_lstats
            if name == path.name and dir_fd is not None:
                leaf_lstats += 1
                if leaf_lstats == 2:
                    path.rename(displaced)
                    replacement.rename(path)
            return real_lstat(name, dir_fd=dir_fd)

        with (
            patch.object(private_io.os, "lstat", side_effect=racing_lstat),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertEqual(2, leaf_lstats)
        self.assertEqual(b"original", displaced.read_bytes())
        self.assertEqual(b"replacement", path.read_bytes())

    def test_directory_replacement_between_lstat_and_open_is_rejected(self) -> None:
        private_dir = self.root / "private"
        logs = private_dir / "logs"
        logs.mkdir(parents=True)
        replacement = private_dir / "replacement"
        replacement.mkdir()
        displaced = private_dir / "displaced"
        real_open = os.open
        swapped = False

        def racing_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if not swapped and name == logs.name and dir_fd is not None:
                logs.rename(displaced)
                replacement.rename(logs)
                swapped = True
            return real_open(name, flags, mode, dir_fd=dir_fd)

        with (
            patch.object(private_io.os, "open", side_effect=racing_open),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(logs / "events.log", b"event")

        self.assertTrue(swapped)
        self.assertFalse((logs / "events.log").exists())

    def test_fstat_identity_mismatch_is_rejected(self) -> None:
        private_dir = self.root / "logs"
        private_dir.mkdir(mode=0o700)
        path = private_dir / "events.log"
        path.write_bytes(b"original")
        decoy = private_dir / "decoy.log"
        decoy.write_bytes(b"decoy")
        decoy_stat = decoy.stat()
        real_fstat = os.fstat

        def mismatched_file_identity(fd: int) -> os.stat_result:
            result = real_fstat(fd)
            if stat.S_ISREG(result.st_mode):
                return decoy_stat
            return result

        with (
            patch.object(private_io.os, "fstat", side_effect=mismatched_file_identity),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assertEqual(b"original", path.read_bytes())

    def test_all_descriptors_close_when_file_fchmod_fails(self) -> None:
        path = self.root / "logs" / "events.log"
        opened: set[int] = set()
        real_open = os.open
        real_fchmod = os.fchmod

        def tracking_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = real_open(name, flags, mode, dir_fd=dir_fd)
            opened.add(descriptor)
            return descriptor

        def failing_file_fchmod(fd: int, mode: int) -> None:
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("file fchmod failed")
            real_fchmod(fd, mode)

        with (
            patch.object(private_io.os, "open", side_effect=tracking_open),
            patch.object(private_io.os, "fchmod", side_effect=failing_file_fchmod),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assert_all_closed(opened)

    def test_all_descriptors_close_when_fdopen_fails(self) -> None:
        path = self.root / "logs" / "events.log"
        opened: set[int] = set()
        real_open = os.open

        def tracking_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = real_open(name, flags, mode, dir_fd=dir_fd)
            opened.add(descriptor)
            return descriptor

        with (
            patch.object(private_io.os, "open", side_effect=tracking_open),
            patch.object(private_io.os, "fdopen", side_effect=OSError("fdopen failed")),
            self.assertRaises(UnsafeFileError),
        ):
            append_private_bytes(path, b"event")

        self.assert_all_closed(opened)

    def test_file_close_failure_does_not_prevent_parent_cleanup(self) -> None:
        path = self.root / "logs" / "events.log"
        real_fdopen = os.fdopen
        parent_fd: int | None = None
        real_open = os.open

        class FailingCloseHandle:
            def __init__(self, handle: BinaryIO) -> None:
                self.handle = handle

            def write(self, data: bytes) -> int:
                return self.handle.write(data)

            def close(self) -> None:
                self.handle.close()
                raise OSError("file close failed")

        def tracking_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal parent_fd
            descriptor = real_open(name, flags, mode, dir_fd=dir_fd)
            if name == path.name:
                parent_fd = dir_fd
            return descriptor

        def failing_close_fdopen(fd: int, mode: str, buffering: int = -1) -> FailingCloseHandle:
            return FailingCloseHandle(real_fdopen(fd, mode, buffering=buffering))

        with (
            patch.object(private_io.os, "open", side_effect=tracking_open),
            patch.object(private_io.os, "fdopen", side_effect=failing_close_fdopen),
            patch.object(private_io.os, "close", wraps=os.close) as close,
            self.assertRaisesRegex(UnsafeFileError, "close"),
        ):
            append_private_bytes(path, b"event")

        self.assertIsNotNone(parent_fd)
        close.assert_any_call(parent_fd)
        with self.assertRaises(OSError):
            os.fstat(parent_fd)  # type: ignore[arg-type]

    def test_cleanup_errors_do_not_hide_primary_unsafe_error(self) -> None:
        path = self.root / "logs" / "events.log"
        opened: set[int] = set()
        real_open = os.open
        real_close = os.close
        fdopen_failed = False

        def tracking_open(
            name: str | bytes,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            descriptor = real_open(name, flags, mode, dir_fd=dir_fd)
            opened.add(descriptor)
            return descriptor

        def failing_fdopen(*_args: object, **_kwargs: object) -> BinaryIO:
            nonlocal fdopen_failed
            fdopen_failed = True
            raise UnsafeFileError("primary unsafe error")

        def noisy_close(fd: int) -> None:
            real_close(fd)
            if fdopen_failed:
                raise OSError("cleanup noise")

        with (
            patch.object(private_io.os, "open", side_effect=tracking_open),
            patch.object(private_io.os, "fdopen", side_effect=failing_fdopen),
            patch.object(private_io.os, "close", side_effect=noisy_close),
            self.assertRaisesRegex(UnsafeFileError, "primary unsafe error"),
        ):
            append_private_bytes(path, b"event")

        self.assert_all_closed(opened)


if __name__ == "__main__":
    unittest.main()
