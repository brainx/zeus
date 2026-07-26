from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from zeus.private_io_core import (
    _FILE_MODE,
    _LINK_DIR_FD_PROBE,
    _LINK_NOFOLLOW_PROBE,
    _RENAME_DIR_FD_PROBE,
    _UNLINK_DIR_FD_PROBE,
    UnsafeFileError,
    _close_descriptor,
    _close_suppressing_error,
    _open_directory_path,
    _OpenedDirectoryPath,
    _Platform,
    _require_platform,
    _same_file,
    _same_files,
    _validate_file_snapshot,
    _validate_path,
    _validate_private_file_snapshots,
)


def _require_atomic_file_operations() -> None:
    for name in ("fsync", "link", "rename", "unlink"):
        if not callable(getattr(os, name, None)):
            raise UnsafeFileError(f"required POSIX primitive os.{name} is unavailable")
    supported = getattr(os, "supports_dir_fd", ())
    for function, name in (
        (_LINK_DIR_FD_PROBE, "link"),
        (_RENAME_DIR_FD_PROBE, "rename"),
        (_UNLINK_DIR_FD_PROBE, "unlink"),
    ):
        if function not in supported:
            raise UnsafeFileError(f"descriptor-relative os.{name} is unavailable")
    follow_symlinks = getattr(os, "supports_follow_symlinks", ())
    if _LINK_NOFOLLOW_PROBE not in follow_symlinks:
        raise UnsafeFileError("no-follow os.link is unavailable")


def _create_atomic_temporary_file(
    parent_fd: int,
    platform: _Platform,
) -> tuple[str, int, os.stat_result]:
    flags = platform.append_flags | platform.create_exclusive_flags
    for _attempt in range(128):
        name = f".zeus-{secrets.token_hex(16)}.tmp"
        try:
            file_fd = os.open(name, flags, _FILE_MODE, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise UnsafeFileError("private temporary file could not be created") from exc
        except (TypeError, ValueError) as exc:
            raise UnsafeFileError("private temporary file could not be created safely") from exc
        identity: os.stat_result | None = None
        try:
            opened = os.fstat(file_fd)
            current = os.lstat(name, dir_fd=parent_fd)
            for snapshot in (opened, current):
                _validate_file_snapshot(snapshot, platform)
            if not _same_file(opened, current):
                raise UnsafeFileError("private temporary file changed while it was created")
            identity = opened
            os.fchmod(file_fd, _FILE_MODE)
            tightened = os.fstat(file_fd)
            final = os.lstat(name, dir_fd=parent_fd)
            _validate_private_file_snapshots((tightened, final), platform)
            if not _same_files((opened, current, tightened, final)):
                raise UnsafeFileError("private temporary file changed while it was created")
            return name, file_fd, tightened
        except UnsafeFileError:
            _close_suppressing_error(file_fd)
            if identity is not None:
                with suppress(UnsafeFileError):
                    _unlink_proven_temporary_file(parent_fd, name, identity)
            raise
        except (OSError, TypeError, ValueError) as exc:
            _close_suppressing_error(file_fd)
            if identity is not None:
                with suppress(UnsafeFileError):
                    _unlink_proven_temporary_file(parent_fd, name, identity)
            raise UnsafeFileError("private temporary file could not be validated") from exc
        except BaseException:
            _close_suppressing_error(file_fd)
            if identity is not None:
                with suppress(UnsafeFileError):
                    _unlink_proven_temporary_file(parent_fd, name, identity)
            raise
    raise UnsafeFileError("a unique private temporary file could not be created")


def _unlink_proven_temporary_file(
    parent_fd: int,
    name: str,
    identity: os.stat_result,
) -> None:
    try:
        current = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise UnsafeFileError("private temporary file could not be inspected") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("private temporary file could not be inspected safely") from exc
    if (
        not _same_file(identity, current)
        or not stat.S_ISREG(current.st_mode)
        or current.st_uid != identity.st_uid
    ):
        raise UnsafeFileError("private temporary file binding changed")
    try:
        os.unlink(name, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeFileError("private temporary file could not be removed") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("private temporary file could not be removed safely") from exc


def _validate_atomic_target(
    parent_fd: int,
    name: str,
    identity: os.stat_result,
    platform: _Platform,
    expected_size: int,
) -> os.stat_result:
    try:
        target = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeFileError("private file installation could not be confirmed") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("private file installation cannot be inspected safely") from exc
    _validate_private_file_snapshots(
        (identity, target),
        platform,
        expected_size=expected_size,
    )
    return target


def _inspect_replacement_target(
    parent: _OpenedDirectoryPath,
    name: str,
    platform: _Platform,
) -> os.stat_result | None:
    try:
        target = os.lstat(name, dir_fd=parent.fd)
    except FileNotFoundError:
        parent.confirm_missing(name)
        return None
    except OSError as exc:
        raise UnsafeFileError("replacement target could not be inspected") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("replacement target cannot be inspected safely") from exc
    _validate_private_file_snapshots((target,), platform)
    return target


def _validate_replacement_target_binding(
    parent: _OpenedDirectoryPath,
    name: str,
    identity: os.stat_result | None,
    platform: _Platform,
) -> None:
    if identity is None:
        parent.confirm_missing(name)
        return
    try:
        current = os.lstat(name, dir_fd=parent.fd)
    except OSError as exc:
        raise UnsafeFileError("replacement target binding changed") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("replacement target cannot be inspected safely") from exc
    _validate_private_file_snapshots((identity, current), platform)


def _write_private_bytes_atomic(
    path: Path,
    data: bytes,
    max_bytes: int,
    *,
    replace: bool,
    on_install: Callable[[os.stat_result], None] | None,
) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be an integer")
    if max_bytes < 0:
        raise TypeError("max_bytes must be non-negative")
    if len(data) > max_bytes:
        raise ValueError("data exceeds max_bytes")
    if not isinstance(replace, bool):
        raise TypeError("replace must be a boolean")
    if on_install is not None and not callable(on_install):
        raise TypeError("on_install must be callable")
    parts = _validate_path(path, file_path=True)
    platform = _require_platform()
    _require_atomic_file_operations()
    with _open_directory_path(parts[:-1], create=True, platform=platform) as parent:
        replacement_identity = (
            _inspect_replacement_target(parent, parts[-1], platform) if replace else None
        )
        temporary_name, file_fd, identity = _create_atomic_temporary_file(
            parent.fd,
            platform,
        )
        temporary_exists = True
        installed = False
        try:
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(file_fd, data[offset:])
                    if written is None or written <= 0 or written > len(data) - offset:
                        raise UnsafeFileError("private file write was incomplete")
                    offset += written
                os.fchmod(file_fd, _FILE_MODE)
                os.fsync(file_fd)
                completed = os.fstat(file_fd)
                current = os.lstat(temporary_name, dir_fd=parent.fd)
                _validate_private_file_snapshots(
                    (identity, completed, current),
                    platform,
                )
                if completed.st_size != len(data) or current.st_size != len(data):
                    raise UnsafeFileError("private file size changed while it was used")
                identity = completed
            except UnsafeFileError:
                raise
            except OSError as exc:
                raise UnsafeFileError("private file could not be written durably") from exc
            except (TypeError, ValueError) as exc:
                raise UnsafeFileError("private file could not be validated safely") from exc

            _close_descriptor(file_fd, "private temporary file")
            file_fd = -1
            parent.validate_bindings()
            try:
                if replace:
                    _validate_replacement_target_binding(
                        parent,
                        parts[-1],
                        replacement_identity,
                        platform,
                    )
                    os.rename(
                        temporary_name,
                        parts[-1],
                        src_dir_fd=parent.fd,
                        dst_dir_fd=parent.fd,
                    )
                    temporary_exists = False
                else:
                    os.link(
                        temporary_name,
                        parts[-1],
                        src_dir_fd=parent.fd,
                        dst_dir_fd=parent.fd,
                        follow_symlinks=False,
                    )
                installed = True
            except UnsafeFileError:
                raise
            except OSError as exc:
                raise UnsafeFileError("private file could not be installed atomically") from exc
            except (TypeError, ValueError) as exc:
                raise UnsafeFileError("private file could not be installed safely") from exc

            if not replace:
                _unlink_proven_temporary_file(parent.fd, temporary_name, identity)
                temporary_exists = False
            installed_identity = _validate_atomic_target(
                parent.fd,
                parts[-1],
                identity,
                platform,
                len(data),
            )
            if on_install is not None:
                on_install(installed_identity)
            parent.validate_bindings()
            try:
                os.fsync(parent.fd)
            except OSError as exc:
                raise UnsafeFileError("private parent directory could not be synchronized") from exc
            except (TypeError, ValueError) as exc:
                raise UnsafeFileError(
                    "private parent directory could not be synchronized safely"
                ) from exc
            _validate_atomic_target(
                parent.fd,
                parts[-1],
                identity,
                platform,
                len(data),
            )
        except BaseException:
            if file_fd >= 0:
                _close_suppressing_error(file_fd)
            if temporary_exists:
                with suppress(UnsafeFileError):
                    _unlink_proven_temporary_file(
                        parent.fd,
                        temporary_name,
                        identity,
                    )
            raise
        finally:
            if file_fd >= 0:
                _close_suppressing_error(file_fd)
        if not installed:
            raise UnsafeFileError("private file was not installed")


def write_private_bytes_atomic(
    path: Path,
    data: bytes,
    max_bytes: int,
    *,
    replace: bool = False,
) -> None:
    _write_private_bytes_atomic(
        path,
        data,
        max_bytes,
        replace=replace,
        on_install=None,
    )


def write_private_bytes_atomic_tracked(
    path: Path,
    data: bytes,
    max_bytes: int,
    *,
    on_install: Callable[[os.stat_result], None],
    replace: bool = False,
) -> None:
    _write_private_bytes_atomic(
        path,
        data,
        max_bytes,
        replace=replace,
        on_install=on_install,
    )
