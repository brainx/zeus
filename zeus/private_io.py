from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from zeus.private_io_atomic import (
    _create_atomic_temporary_file as _create_atomic_temporary_file,
)
from zeus.private_io_atomic import (
    _inspect_replacement_target as _inspect_replacement_target,
)
from zeus.private_io_atomic import (
    _require_atomic_file_operations as _require_atomic_file_operations,
)
from zeus.private_io_atomic import (
    _unlink_proven_temporary_file as _unlink_proven_temporary_file,
)
from zeus.private_io_atomic import (
    _validate_atomic_target as _validate_atomic_target,
)
from zeus.private_io_atomic import (
    _validate_replacement_target_binding as _validate_replacement_target_binding,
)
from zeus.private_io_atomic import (
    _write_private_bytes_atomic as _write_private_bytes_atomic,
)
from zeus.private_io_atomic import (
    write_private_bytes_atomic as write_private_bytes_atomic,
)
from zeus.private_io_atomic import (
    write_private_bytes_atomic_tracked as write_private_bytes_atomic_tracked,
)
from zeus.private_io_core import (
    _DIRECTORY_MODE as _DIRECTORY_MODE,
)
from zeus.private_io_core import (
    _FILE_MODE as _FILE_MODE,
)
from zeus.private_io_core import (
    _LINK_DIR_FD_PROBE as _LINK_DIR_FD_PROBE,
)
from zeus.private_io_core import (
    _LINK_NOFOLLOW_PROBE as _LINK_NOFOLLOW_PROBE,
)
from zeus.private_io_core import (
    _LSTAT_DIR_FD_PROBE as _LSTAT_DIR_FD_PROBE,
)
from zeus.private_io_core import (
    _MKDIR_DIR_FD_PROBE as _MKDIR_DIR_FD_PROBE,
)
from zeus.private_io_core import (
    _OPEN_DIR_FD_PROBE as _OPEN_DIR_FD_PROBE,
)
from zeus.private_io_core import (
    _RENAME_DIR_FD_PROBE as _RENAME_DIR_FD_PROBE,
)
from zeus.private_io_core import (
    _REQUIRED_FUNCTIONS as _REQUIRED_FUNCTIONS,
)
from zeus.private_io_core import (
    _SECURITY_FLAGS as _SECURITY_FLAGS,
)
from zeus.private_io_core import (
    _UNLINK_DIR_FD_PROBE as _UNLINK_DIR_FD_PROBE,
)
from zeus.private_io_core import (
    UnsafeFileError as UnsafeFileError,
)
from zeus.private_io_core import (
    _close_descriptor as _close_descriptor,
)
from zeus.private_io_core import (
    _close_suppressing_error as _close_suppressing_error,
)
from zeus.private_io_core import (
    _DirectoryRequirement as _DirectoryRequirement,
)
from zeus.private_io_core import (
    _lstat_at as _lstat_at,
)
from zeus.private_io_core import (
    _open_directory_at as _open_directory_at,
)
from zeus.private_io_core import (
    _open_directory_path as _open_directory_path,
)
from zeus.private_io_core import (
    _open_private_file_at as _open_private_file_at,
)
from zeus.private_io_core import (
    _open_root as _open_root,
)
from zeus.private_io_core import (
    _OpenedDirectoryPath as _OpenedDirectoryPath,
)
from zeus.private_io_core import (
    _OpenedPrivateFile as _OpenedPrivateFile,
)
from zeus.private_io_core import (
    _PinnedPrivateDirectory as _PinnedPrivateDirectory,
)
from zeus.private_io_core import (
    _Platform as _Platform,
)
from zeus.private_io_core import (
    _private_append_context as _private_append_context,
)
from zeus.private_io_core import (
    _PrivatePathMissing as _PrivatePathMissing,
)
from zeus.private_io_core import (
    _require_platform as _require_platform,
)
from zeus.private_io_core import (
    _required_flag as _required_flag,
)
from zeus.private_io_core import (
    _same_file as _same_file,
)
from zeus.private_io_core import (
    _same_files as _same_files,
)
from zeus.private_io_core import (
    _tighten_directory as _tighten_directory,
)
from zeus.private_io_core import (
    _validate_directory_bindings as _validate_directory_bindings,
)
from zeus.private_io_core import (
    _validate_directory_requirement as _validate_directory_requirement,
)
from zeus.private_io_core import (
    _validate_directory_snapshots as _validate_directory_snapshots,
)
from zeus.private_io_core import (
    _validate_file_snapshot as _validate_file_snapshot,
)
from zeus.private_io_core import (
    _validate_path as _validate_path,
)
from zeus.private_io_core import (
    _validate_private_file_snapshots as _validate_private_file_snapshots,
)
from zeus.private_io_core import (
    append_private_bytes as append_private_bytes,
)
from zeus.private_io_core import (
    nofollow_absolute_path as nofollow_absolute_path,
)
from zeus.private_io_core import (
    open_private_append as open_private_append,
)
from zeus.private_io_core import (
    read_private_bytes as read_private_bytes,
)
from zeus.private_io_core import (
    read_private_tail as read_private_tail,
)


def validate_private_directory(path: Path) -> None:
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    with _open_directory_path(parts, create=False, platform=platform):
        pass


@contextmanager
def pin_private_directory(
    path: Path,
    *,
    tighten: bool = True,
) -> Iterator[_PinnedPrivateDirectory]:
    if not isinstance(tighten, bool):
        raise TypeError("tighten must be a boolean")
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    pinned_fd = -1
    try:
        with _open_directory_path(
            parts,
            create=False,
            tighten=tighten,
            platform=platform,
        ) as opened:
            try:
                pinned_fd = os.dup(opened.fd)
                identity = os.fstat(pinned_fd)
                _validate_directory_snapshots((identity,), "pinned private directory")
                _validate_directory_requirement(
                    (identity,),
                    _DirectoryRequirement.exact_private,
                    platform.euid,
                    "pinned private directory",
                )
            except UnsafeFileError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise UnsafeFileError("private directory could not be pinned safely") from exc
    except BaseException:
        if pinned_fd >= 0:
            _close_suppressing_error(pinned_fd)
        raise
    pinned = _PinnedPrivateDirectory(pinned_fd, identity, platform)
    try:
        yield pinned
    except BaseException:
        _close_suppressing_error(pinned_fd)
        raise
    else:
        _close_descriptor(pinned_fd, "pinned private directory")


def ensure_private_directory(path: Path, *, tighten_existing: bool = True) -> None:
    if not isinstance(tighten_existing, bool):
        raise TypeError("tighten_existing must be a boolean")
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    with _open_directory_path(
        parts,
        create=True,
        tighten=tighten_existing,
        platform=platform,
    ):
        pass


def inspect_private_directory(path: Path, *, missing_ok: bool = False) -> bool:
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    try:
        with _open_directory_path(
            parts,
            create=False,
            missing_ok=missing_ok,
            tighten=False,
            platform=platform,
        ):
            pass
    except _PrivatePathMissing:
        return False
    return True
