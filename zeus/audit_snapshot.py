from __future__ import annotations

import codecs
import hashlib
import math
import os
import stat
import time
from contextlib import suppress

from zeus.audit_shared import AuditServiceError
from zeus.audit_workspace import (
    MaterializedSnapshot,
)


def snapshot_source_line_counts(
    snapshot: MaterializedSnapshot,
    *,
    deadline: float | None = None,
) -> dict[str, int]:
    """Return line counts from manifest-bound UTF-8 regular snapshot files."""
    _check_snapshot_deadline(deadline)
    directory_flags = _snapshot_open_flags(directory=True)
    file_flags = _snapshot_open_flags(directory=False)
    try:
        _check_snapshot_deadline(deadline)
        root_before = os.lstat(snapshot.root)
        root_descriptor = os.open(snapshot.root, directory_flags)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditServiceError("snapshot source root could not be opened safely") from exc
    counts: dict[str, int] = {}
    seen: set[str] = set()
    try:
        root_opened = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_before.st_mode) or not _same_file(root_before, root_opened):
            raise AuditServiceError("snapshot source root binding changed")
        for entry in snapshot.manifest:
            _check_snapshot_deadline(deadline)
            if entry.path in seen:
                raise AuditServiceError("snapshot source manifest contains duplicate paths")
            seen.add(entry.path)
            if entry.is_symlink:
                continue
            counts.update(
                _snapshot_entry_line_count(
                    root_descriptor,
                    entry,
                    directory_flags=directory_flags,
                    file_flags=file_flags,
                    deadline=deadline,
                )
            )
        _check_snapshot_deadline(deadline)
        root_after = os.fstat(root_descriptor)
        root_current = os.lstat(snapshot.root)
        if not _same_files((root_before, root_opened, root_after, root_current)):
            raise AuditServiceError("snapshot source root binding changed")
    except AuditServiceError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise AuditServiceError("snapshot source content could not be read safely") from exc
    finally:
        with suppress(OSError):
            os.close(root_descriptor)
    return counts


def _check_snapshot_deadline(deadline: float | None) -> None:
    if deadline is None:
        return
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
        or time.monotonic() >= deadline
    ):
        raise AuditServiceError("snapshot source deadline expired")


def _snapshot_open_flags(*, directory: bool) -> int:
    flags = 0
    for name, allow_zero in (
        ("O_RDONLY", True),
        ("O_NOFOLLOW", False),
        ("O_CLOEXEC", False),
        ("O_NONBLOCK", False),
    ):
        value = getattr(os, name, None)
        if type(value) is not int or (not allow_zero and value == 0):
            raise AuditServiceError(f"snapshot source requires POSIX flag {name}")
        flags |= value
    if directory:
        value = getattr(os, "O_DIRECTORY", None)
        if type(value) is not int or value == 0:
            raise AuditServiceError("snapshot source requires POSIX flag O_DIRECTORY")
        flags |= value
    return flags


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _same_files(results: tuple[os.stat_result, ...]) -> bool:
    return all(_same_file(results[0], result) for result in results[1:])


def _snapshot_entry_line_count(
    root_descriptor: int,
    entry: object,
    *,
    directory_flags: int,
    file_flags: int,
    deadline: float | None,
) -> dict[str, int]:
    from zeus.audit_workspace import SnapshotManifestEntry

    if not isinstance(entry, SnapshotManifestEntry):
        raise AuditServiceError("snapshot source manifest entry is invalid")
    components = entry.path.split("/")
    if (
        not components
        or any(component in {"", ".", ".."} or "\x00" in component for component in components)
        or isinstance(entry.size, bool)
        or not isinstance(entry.size, int)
        or entry.size < 0
        or not isinstance(entry.sha256, str)
        or len(entry.sha256) != 64
        or any(character not in "0123456789abcdef" for character in entry.sha256)
    ):
        raise AuditServiceError("snapshot source manifest entry is invalid")

    descriptors = [os.dup(root_descriptor)]
    directory_bindings: list[tuple[int, str, int, os.stat_result]] = []
    file_descriptor = -1
    try:
        for component in components[:-1]:
            _check_snapshot_deadline(deadline)
            parent = descriptors[-1]
            before = os.lstat(component, dir_fd=parent)
            child = os.open(component, directory_flags, dir_fd=parent)
            opened = os.fstat(child)
            current = os.lstat(component, dir_fd=parent)
            if not stat.S_ISDIR(before.st_mode) or not _same_files((before, opened, current)):
                raise AuditServiceError("snapshot source directory binding changed")
            directory_bindings.append((parent, component, child, opened))
            descriptors.append(child)

        parent = descriptors[-1]
        name = components[-1]
        before = os.lstat(name, dir_fd=parent)
        file_descriptor = os.open(name, file_flags, dir_fd=parent)
        opened = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file(before, opened)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != entry.mode
            or before.st_size != entry.size
        ):
            raise AuditServiceError("snapshot source metadata does not match its manifest")

        digest = hashlib.sha256()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        text_valid = True
        contains_binary_control = False
        newline_count = 0
        last_byte: int | None = None
        remaining = entry.size
        while remaining:
            _check_snapshot_deadline(deadline)
            chunk = os.read(file_descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise AuditServiceError("snapshot source size changed while it was read")
            if len(chunk) > remaining:
                raise AuditServiceError("snapshot source exceeded its manifest size")
            remaining -= len(chunk)
            digest.update(chunk)
            newline_count += chunk.count(b"\n")
            last_byte = chunk[-1]
            contains_binary_control = contains_binary_control or any(
                (byte < 0x20 and byte not in {0x09, 0x0A, 0x0D}) or byte == 0x7F for byte in chunk
            )
            if text_valid:
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeDecodeError:
                    text_valid = False
        if os.read(file_descriptor, 1):
            raise AuditServiceError("snapshot source exceeded its manifest size")
        _check_snapshot_deadline(deadline)
        if text_valid:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                text_valid = False

        after = os.fstat(file_descriptor)
        current = os.lstat(name, dir_fd=parent)
        if (
            not _same_files((before, opened, after, current))
            or after.st_size != entry.size
            or current.st_size != entry.size
            or stat.S_IMODE(current.st_mode) != entry.mode
        ):
            raise AuditServiceError("snapshot source binding changed while it was read")
        for directory_parent, component, descriptor, expected in directory_bindings:
            if not _same_files(
                (
                    expected,
                    os.fstat(descriptor),
                    os.lstat(component, dir_fd=directory_parent),
                )
            ):
                raise AuditServiceError("snapshot source directory binding changed")
        if digest.hexdigest() != entry.sha256:
            raise AuditServiceError("snapshot source digest does not match its manifest")
        if not text_valid or contains_binary_control or entry.size == 0:
            return {}
        return {
            entry.path: newline_count + (1 if last_byte != ord("\n") else 0),
        }
    finally:
        if file_descriptor >= 0:
            with suppress(OSError):
                os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)
