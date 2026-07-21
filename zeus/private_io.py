from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, cast

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_SECURITY_FLAGS = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
_REQUIRED_FUNCTIONS = (
    "close",
    "dup",
    "fchmod",
    "fdopen",
    "fstat",
    "geteuid",
    "lseek",
    "lstat",
    "mkdir",
    "open",
    "read",
    "write",
)
_OPEN_DIR_FD_PROBE = os.open
_MKDIR_DIR_FD_PROBE = os.mkdir
_LSTAT_DIR_FD_PROBE = os.lstat


class UnsafeFileError(OSError):
    pass


class _PrivatePathMissing(Exception):
    pass


class _DirectoryRequirement(Enum):
    identity = "identity"
    exact_private = "exact_private"
    inspect_private = "inspect_private"


@dataclass(frozen=True)
class _Platform:
    euid: int
    directory_flags: int
    append_flags: int
    read_flags: int
    create_exclusive_flags: int


@dataclass(frozen=True)
class _OpenedDirectoryPath:
    descriptors: tuple[int, ...]
    names: tuple[str, ...]
    requirements: tuple[_DirectoryRequirement, ...]
    euid: int

    @property
    def fd(self) -> int:
        return self.descriptors[-1]

    def validate_bindings(self) -> None:
        _validate_directory_bindings(
            self.descriptors,
            self.names,
            self.requirements,
            self.euid,
        )

    def confirm_missing(self, name: str) -> None:
        self.validate_bindings()
        try:
            os.lstat(name, dir_fd=self.fd)
        except FileNotFoundError:
            self.validate_bindings()
            return
        except OSError as exc:
            raise UnsafeFileError("missing private path could not be confirmed") from exc
        except (TypeError, ValueError) as exc:
            raise UnsafeFileError("missing private path cannot be inspected safely") from exc
        raise UnsafeFileError("private path appeared while absence was confirmed")


@dataclass(frozen=True)
class _OpenedPrivateFile:
    fd: int
    parent_fd: int
    name: str
    identity: os.stat_result
    platform: _Platform

    def validate_binding(self) -> None:
        try:
            opened = os.fstat(self.fd)
            current = os.lstat(self.name, dir_fd=self.parent_fd)
            snapshots = (self.identity, opened, current)
            for snapshot in snapshots:
                _validate_file_snapshot(snapshot, self.platform)
            if not _same_files(snapshots):
                raise UnsafeFileError("private file changed while it was used")
            if any(stat.S_IMODE(snapshot.st_mode) != _FILE_MODE for snapshot in (opened, current)):
                raise UnsafeFileError("private file does not have private permissions")
        except UnsafeFileError:
            raise
        except OSError as exc:
            raise UnsafeFileError("private file binding changed while it was used") from exc
        except (TypeError, ValueError) as exc:
            raise UnsafeFileError("private file binding cannot be inspected safely") from exc


@dataclass(frozen=True)
class _PinnedPrivateDirectory:
    fd: int
    identity: os.stat_result
    platform: _Platform

    def validate_at(self, path: Path) -> None:
        parts = _validate_path(path, file_path=False)
        with _open_directory_path(
            parts,
            create=False,
            tighten=False,
            platform=self.platform,
        ) as current:
            try:
                pinned = os.fstat(self.fd)
                installed = os.fstat(current.fd)
                snapshots = (self.identity, pinned, installed)
                _validate_directory_snapshots(snapshots, "pinned private directory")
                _validate_directory_requirement(
                    snapshots,
                    _DirectoryRequirement.exact_private,
                    self.platform.euid,
                    "pinned private directory",
                )
            except UnsafeFileError:
                raise
            except OSError as exc:
                raise UnsafeFileError("pinned private directory is unavailable") from exc
            except (TypeError, ValueError) as exc:
                raise UnsafeFileError(
                    "pinned private directory cannot be inspected safely"
                ) from exc


def _required_flag(name: str, *, allow_zero: bool = False) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or (not allow_zero and value == 0):
        raise UnsafeFileError(f"required POSIX flag {name} is unavailable")
    return value


def _require_platform() -> _Platform:
    if os.name != "posix":
        raise UnsafeFileError("descriptor-safe private file access requires POSIX")
    for name in _REQUIRED_FUNCTIONS:
        if not callable(getattr(os, name, None)):
            raise UnsafeFileError(f"required POSIX primitive os.{name} is unavailable")
    supported = getattr(os, "supports_dir_fd", ())
    for function, name in (
        (_OPEN_DIR_FD_PROBE, "open"),
        (_MKDIR_DIR_FD_PROBE, "mkdir"),
        (_LSTAT_DIR_FD_PROBE, "lstat"),
    ):
        if function not in supported:
            raise UnsafeFileError(f"descriptor-relative os.{name} is unavailable")
    security_flags = {name: _required_flag(name) for name in _SECURITY_FLAGS}
    o_rdonly = _required_flag("O_RDONLY", allow_zero=True)
    o_wronly = _required_flag("O_WRONLY")
    o_append = _required_flag("O_APPEND")
    o_creat = _required_flag("O_CREAT")
    o_excl = _required_flag("O_EXCL")
    euid = os.geteuid()
    if isinstance(euid, bool) or not isinstance(euid, int) or euid < 0:
        raise UnsafeFileError("effective UID is unavailable")
    common_leaf = (
        security_flags["O_NOFOLLOW"] | security_flags["O_CLOEXEC"] | security_flags["O_NONBLOCK"]
    )
    return _Platform(
        euid=euid,
        directory_flags=(
            o_rdonly
            | security_flags["O_DIRECTORY"]
            | security_flags["O_NOFOLLOW"]
            | security_flags["O_CLOEXEC"]
        ),
        append_flags=o_wronly | o_append | common_leaf,
        read_flags=o_rdonly | common_leaf,
        create_exclusive_flags=o_creat | o_excl,
    )


def nofollow_absolute_path(path: Path) -> Path:
    """Return an absolute lexical path without resolving supplied components."""
    absolute = Path(os.path.abspath(path.expanduser()))
    if (
        sys.platform == "darwin"
        and len(absolute.parts) > 1
        and absolute.parts[1] in {"etc", "tmp", "var"}
    ):
        return Path("/private", *absolute.parts[1:])
    return absolute


def _validate_path(path: Path, *, file_path: bool) -> tuple[str, ...]:
    if not isinstance(path, Path):
        raise UnsafeFileError("private path must be a pathlib.Path")
    if not path.is_absolute() or path.anchor != "/":
        raise UnsafeFileError("private path must be an absolute POSIX path")
    parts = path.parts[1:]
    if not parts or (file_path and len(parts) < 2):
        raise UnsafeFileError("private path cannot use the filesystem root")
    if any(part in {"", ".", ".."} or "\0" in part for part in parts):
        raise UnsafeFileError("private path contains an unsupported component")
    return parts


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _same_files(results: tuple[os.stat_result, ...]) -> bool:
    return all(_same_file(results[0], result) for result in results[1:])


def _close_suppressing_error(fd: int) -> None:
    with suppress(OSError):
        os.close(fd)


def _close_descriptor(fd: int, description: str) -> None:
    try:
        os.close(fd)
    except OSError as exc:
        raise UnsafeFileError(f"{description} descriptor could not be closed") from exc


def _lstat_at(parent_fd: int, name: str, description: str) -> os.stat_result:
    try:
        return os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeFileError(f"{description} is unavailable") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError(f"{description} cannot be inspected safely") from exc


def _validate_directory_snapshots(
    snapshots: tuple[os.stat_result, ...],
    description: str,
) -> None:
    if not all(stat.S_ISDIR(snapshot.st_mode) for snapshot in snapshots):
        raise UnsafeFileError(f"{description} is not a directory")
    if not _same_files(snapshots):
        raise UnsafeFileError(f"{description} changed while it was opened")


def _validate_directory_bindings(
    descriptors: tuple[int, ...],
    names: tuple[str, ...],
    requirements: tuple[_DirectoryRequirement, ...],
    euid: int,
) -> None:
    if len(descriptors) != len(names) + 1 or len(requirements) != len(descriptors):
        raise UnsafeFileError("private directory descriptor chain is invalid")
    try:
        root_snapshots = (os.fstat(descriptors[0]), os.lstat("/"))
        _validate_directory_snapshots(root_snapshots, "filesystem root")
        _validate_directory_requirement(
            root_snapshots,
            requirements[0],
            euid,
            "filesystem root",
        )
        for parent_fd, name, directory_fd, requirement in zip(
            descriptors[:-1],
            names,
            descriptors[1:],
            requirements[1:],
            strict=True,
        ):
            description = f"private path component {name!r}"
            snapshots = (os.fstat(directory_fd), os.lstat(name, dir_fd=parent_fd))
            _validate_directory_snapshots(snapshots, description)
            _validate_directory_requirement(snapshots, requirement, euid, description)
    except UnsafeFileError:
        raise
    except OSError as exc:
        raise UnsafeFileError("private directory path binding changed") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("private directory path cannot be inspected safely") from exc


def _validate_directory_requirement(
    snapshots: tuple[os.stat_result, ...],
    requirement: _DirectoryRequirement,
    euid: int,
    description: str,
) -> None:
    if requirement is _DirectoryRequirement.identity:
        return
    if not all(snapshot.st_uid == euid for snapshot in snapshots):
        raise UnsafeFileError(f"{description} has an unexpected owner")
    modes = tuple(stat.S_IMODE(snapshot.st_mode) for snapshot in snapshots)
    if requirement is _DirectoryRequirement.exact_private:
        unsafe = any(mode != _DIRECTORY_MODE for mode in modes)
    else:
        unsafe = any(mode & 0o077 for mode in modes)
    if unsafe:
        raise UnsafeFileError(f"{description} does not have private permissions")


def _tighten_directory(
    parent_fd: int,
    name: str,
    directory_fd: int,
    snapshots: tuple[os.stat_result, ...],
    platform: _Platform,
    description: str,
) -> None:
    if not all(snapshot.st_uid == platform.euid for snapshot in snapshots):
        raise UnsafeFileError(f"{description} has an unexpected owner")
    try:
        os.fchmod(directory_fd, _DIRECTORY_MODE)
        tightened = os.fstat(directory_fd)
        current = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeFileError(f"{description} permissions could not be tightened") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError(f"{description} cannot be validated safely") from exc
    final_snapshots = (*snapshots, tightened, current)
    _validate_directory_snapshots(final_snapshots, description)
    if not all(snapshot.st_uid == platform.euid for snapshot in final_snapshots):
        raise UnsafeFileError(f"{description} has an unexpected owner")
    if any(stat.S_IMODE(snapshot.st_mode) != _DIRECTORY_MODE for snapshot in (tightened, current)):
        raise UnsafeFileError(f"{description} does not have private permissions")


def _open_root(platform: _Platform) -> int:
    try:
        before = os.lstat("/")
        root_fd = os.open("/", platform.directory_flags)
    except OSError as exc:
        raise UnsafeFileError("filesystem root cannot be opened safely") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("filesystem root cannot be inspected safely") from exc
    try:
        opened = os.fstat(root_fd)
        after = os.lstat("/")
        _validate_directory_snapshots((before, opened, after), "filesystem root")
        return root_fd
    except UnsafeFileError:
        _close_suppressing_error(root_fd)
        raise
    except (OSError, TypeError, ValueError) as exc:
        _close_suppressing_error(root_fd)
        raise UnsafeFileError("filesystem root changed while it was opened") from exc
    except BaseException:
        _close_suppressing_error(root_fd)
        raise


def _open_directory_at(
    parent_fd: int,
    name: str,
    *,
    create: bool,
    missing_ok: bool,
    private: bool,
    tighten: bool,
    platform: _Platform,
) -> tuple[int, _DirectoryRequirement]:
    description = f"private path component {name!r}"
    created = False
    try:
        before = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        if not create:
            if missing_ok:
                raise _PrivatePathMissing from exc
            raise UnsafeFileError(f"{description} is unavailable") from exc
        try:
            os.mkdir(name, mode=_DIRECTORY_MODE, dir_fd=parent_fd)
            created = True
        except FileExistsError as race:
            raise UnsafeFileError(f"{description} appeared while it was created") from race
        except OSError as mkdir_error:
            raise UnsafeFileError(f"{description} could not be created safely") from mkdir_error
        except (TypeError, ValueError) as mkdir_error:
            raise UnsafeFileError(f"{description} cannot be created safely") from mkdir_error
        before = _lstat_at(parent_fd, name, description)
    except OSError as exc:
        raise UnsafeFileError(f"{description} is unavailable") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError(f"{description} cannot be inspected safely") from exc

    if not stat.S_ISDIR(before.st_mode):
        raise UnsafeFileError(f"{description} is not a directory")
    try:
        directory_fd = os.open(name, platform.directory_flags, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeFileError(f"{description} cannot be opened safely") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError(f"{description} cannot be opened safely") from exc
    try:
        opened = os.fstat(directory_fd)
        after = os.lstat(name, dir_fd=parent_fd)
        snapshots = (before, opened, after)
        _validate_directory_snapshots(snapshots, description)
        if created or (private and tighten):
            _tighten_directory(
                parent_fd,
                name,
                directory_fd,
                snapshots,
                platform,
                description,
            )
            requirement = _DirectoryRequirement.exact_private
        elif private:
            requirement = _DirectoryRequirement.inspect_private
            _validate_directory_requirement(
                snapshots,
                requirement,
                platform.euid,
                description,
            )
        else:
            requirement = _DirectoryRequirement.identity
        return directory_fd, requirement
    except UnsafeFileError:
        _close_suppressing_error(directory_fd)
        raise
    except (OSError, TypeError, ValueError) as exc:
        _close_suppressing_error(directory_fd)
        raise UnsafeFileError(f"{description} changed while it was opened") from exc
    except BaseException:
        _close_suppressing_error(directory_fd)
        raise


@contextmanager
def _open_directory_path(
    parts: tuple[str, ...],
    *,
    create: bool,
    missing_ok: bool = False,
    tighten: bool = True,
    platform: _Platform,
) -> Iterator[_OpenedDirectoryPath]:
    descriptors = [_open_root(platform)]
    names: list[str] = []
    requirements = [_DirectoryRequirement.identity]
    try:
        for index, component in enumerate(parts):
            try:
                next_fd, requirement = _open_directory_at(
                    descriptors[-1],
                    component,
                    create=create,
                    missing_ok=missing_ok,
                    private=index == len(parts) - 1,
                    tighten=tighten,
                    platform=platform,
                )
            except _PrivatePathMissing:
                _OpenedDirectoryPath(
                    tuple(descriptors),
                    tuple(names),
                    tuple(requirements),
                    platform.euid,
                ).confirm_missing(component)
                raise
            descriptors.append(next_fd)
            names.append(component)
            requirements.append(requirement)
    except BaseException:
        for descriptor in reversed(descriptors):
            _close_suppressing_error(descriptor)
        raise

    opened = _OpenedDirectoryPath(
        tuple(descriptors),
        tuple(names),
        tuple(requirements),
        platform.euid,
    )
    try:
        yield opened
    except BaseException:
        for descriptor in reversed(descriptors):
            _close_suppressing_error(descriptor)
        raise
    else:
        try:
            opened.validate_bindings()
        except BaseException:
            for descriptor in reversed(descriptors):
                _close_suppressing_error(descriptor)
            raise
        close_error: UnsafeFileError | None = None
        for descriptor in reversed(descriptors):
            try:
                _close_descriptor(descriptor, "private directory")
            except UnsafeFileError as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None:
            raise close_error


def _validate_file_snapshot(snapshot: os.stat_result, platform: _Platform) -> None:
    if not stat.S_ISREG(snapshot.st_mode):
        raise UnsafeFileError("private file is not a regular file")
    if snapshot.st_uid != platform.euid:
        raise UnsafeFileError("private file has an unexpected owner")
    if snapshot.st_nlink != 1:
        raise UnsafeFileError("private file has unexpected links")


def _open_private_file_at(
    parent_fd: int,
    name: str,
    *,
    append: bool,
    create: bool,
    platform: _Platform,
) -> _OpenedPrivateFile | None:
    before: os.stat_result | None
    try:
        before = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        before = None
    except OSError as exc:
        raise UnsafeFileError("private file is unavailable") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("private file cannot be inspected safely") from exc
    if before is None and not create:
        return None
    if before is not None:
        _validate_file_snapshot(before, platform)

    flags = platform.append_flags if append else platform.read_flags
    if before is None:
        flags |= platform.create_exclusive_flags
    try:
        file_fd = os.open(name, flags, _FILE_MODE, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeFileError("private file cannot be opened safely") from exc
    except (TypeError, ValueError) as exc:
        raise UnsafeFileError("private file cannot be opened safely") from exc
    try:
        opened = os.fstat(file_fd)
        current = os.lstat(name, dir_fd=parent_fd)
        initial_snapshots = (opened, current) if before is None else (before, opened, current)
        for snapshot in initial_snapshots:
            _validate_file_snapshot(snapshot, platform)
        if not _same_files(initial_snapshots):
            raise UnsafeFileError("private file changed while it was opened")

        os.fchmod(file_fd, _FILE_MODE)
        tightened = os.fstat(file_fd)
        final = os.lstat(name, dir_fd=parent_fd)
        final_snapshots = (*initial_snapshots, tightened, final)
        for snapshot in final_snapshots:
            _validate_file_snapshot(snapshot, platform)
        if not _same_files(final_snapshots):
            raise UnsafeFileError("private file changed while it was opened")
        if any(stat.S_IMODE(snapshot.st_mode) != _FILE_MODE for snapshot in (tightened, final)):
            raise UnsafeFileError("private file does not have private permissions")
        return _OpenedPrivateFile(
            fd=file_fd,
            parent_fd=parent_fd,
            name=name,
            identity=tightened,
            platform=platform,
        )
    except UnsafeFileError:
        _close_suppressing_error(file_fd)
        raise
    except (OSError, TypeError, ValueError) as exc:
        _close_suppressing_error(file_fd)
        raise UnsafeFileError("private file could not be validated safely") from exc
    except BaseException:
        _close_suppressing_error(file_fd)
        raise


@contextmanager
def _private_append_context(
    parent_parts: tuple[str, ...],
    name: str,
    platform: _Platform,
) -> Iterator[BinaryIO]:
    with _open_directory_path(parent_parts, create=True, platform=platform) as parent:
        opened_file = _open_private_file_at(
            parent.fd,
            name,
            append=True,
            create=True,
            platform=platform,
        )
        if opened_file is None:
            raise UnsafeFileError("private file was not created")
        file_fd = opened_file.fd
        try:
            try:
                handle = cast(BinaryIO, os.fdopen(file_fd, "ab", buffering=0))
            except UnsafeFileError:
                _close_suppressing_error(file_fd)
                raise
            except (OSError, TypeError, ValueError) as exc:
                _close_suppressing_error(file_fd)
                raise UnsafeFileError("private file descriptor could not be wrapped") from exc
            file_fd = -1
            try:
                yield handle
            except BaseException:
                with suppress(OSError):
                    handle.close()
                raise
            else:
                try:
                    opened_file.validate_binding()
                except BaseException:
                    with suppress(OSError):
                        handle.close()
                    raise
                try:
                    handle.close()
                except OSError as exc:
                    raise UnsafeFileError("private file descriptor could not be closed") from exc
        finally:
            if file_fd >= 0:
                _close_suppressing_error(file_fd)


def append_private_bytes(path: Path, data: bytes) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    with open_private_append(path) as handle:
        offset = 0
        while offset < len(data):
            try:
                written = handle.write(data[offset:])
            except OSError as exc:
                raise UnsafeFileError("private file write failed") from exc
            if written is None or written <= 0 or written > len(data) - offset:
                raise UnsafeFileError("private file write was incomplete")
            offset += written


def open_private_append(path: Path) -> AbstractContextManager[BinaryIO]:
    parts = _validate_path(path, file_path=True)
    platform = _require_platform()
    return _private_append_context(parts[:-1], parts[-1], platform)


def read_private_tail(path: Path, max_bytes: int) -> bytes:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be an integer")
    if max_bytes < 0:
        raise TypeError("max_bytes must be non-negative")
    parts = _validate_path(path, file_path=True)
    platform = _require_platform()
    try:
        with _open_directory_path(
            parts[:-1], create=False, missing_ok=True, platform=platform
        ) as parent:
            opened_file = _open_private_file_at(
                parent.fd,
                parts[-1],
                append=False,
                create=False,
                platform=platform,
            )
            if opened_file is None:
                parent.confirm_missing(parts[-1])
                return b""
            file_fd = opened_file.fd
            try:
                try:
                    end = os.lseek(file_fd, 0, os.SEEK_END)
                    start = max(0, end - max_bytes)
                    os.lseek(file_fd, start, os.SEEK_SET)
                    chunks: list[bytes] = []
                    remaining = min(max_bytes, end - start)
                    while remaining:
                        chunk = os.read(file_fd, min(65536, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    result = b"".join(chunks)
                except OSError as exc:
                    raise UnsafeFileError("private file tail could not be read") from exc
                opened_file.validate_binding()
            except BaseException:
                _close_suppressing_error(file_fd)
                raise
            else:
                _close_descriptor(file_fd, "private file")
                return result
    except _PrivatePathMissing:
        return b""


def validate_private_directory(path: Path) -> None:
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    with _open_directory_path(parts, create=False, platform=platform):
        pass


@contextmanager
def pin_private_directory(path: Path) -> Iterator[_PinnedPrivateDirectory]:
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    pinned_fd = -1
    with _open_directory_path(parts, create=False, platform=platform) as opened:
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
            if pinned_fd >= 0:
                _close_suppressing_error(pinned_fd)
            raise
        except (OSError, TypeError, ValueError) as exc:
            if pinned_fd >= 0:
                _close_suppressing_error(pinned_fd)
            raise UnsafeFileError("private directory could not be pinned safely") from exc
    pinned = _PinnedPrivateDirectory(pinned_fd, identity, platform)
    try:
        yield pinned
    except BaseException:
        _close_suppressing_error(pinned_fd)
        raise
    else:
        _close_descriptor(pinned_fd, "pinned private directory")


def ensure_private_directory(path: Path) -> None:
    parts = _validate_path(path, file_path=False)
    platform = _require_platform()
    with _open_directory_path(parts, create=True, platform=platform):
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
