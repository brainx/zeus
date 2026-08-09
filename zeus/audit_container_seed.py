"""Constant source for the isolated audit workspace seed process."""

from __future__ import annotations

SEED_SCRIPT = r"""
import os, posixpath, re, stat, sys, tarfile

if len(sys.argv) != 3:
    raise RuntimeError("workspace seed arguments are invalid")
expected_entries = int(sys.argv[1])
max_bytes = int(sys.argv[2])
if expected_entries < 0 or max_bytes < 1:
    raise RuntimeError("workspace seed limits are invalid")

chunk_size = 65536
directory_flags = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
file_flags = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
windows_drive = re.compile(r"[A-Za-z]:")


def path_parts(path):
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\0" in path
        or windows_drive.fullmatch(path.split("/", 1)[0]) is not None
    ):
        raise RuntimeError("workspace seed path is not confined")
    parts = path.split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise RuntimeError("workspace seed path is not confined")
    if any(part.casefold() == ".git" for part in parts):
        raise RuntimeError("workspace seed path reaches Git metadata")
    return parts


def open_parent(root_descriptor, parts):
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def validate_symlink(path, target):
    if (
        not target
        or target.startswith("/")
        or "\\" in target
        or "\0" in target
        or windows_drive.match(target.split("/", 1)[0]) is not None
    ):
        raise RuntimeError("workspace seed symlink is not confined")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise RuntimeError("workspace seed symlink escapes the workspace")
    if any(part.casefold() == ".git" for part in resolved.split("/")):
        raise RuntimeError("workspace seed symlink reaches Git metadata")


def write_all(descriptor, data):
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RuntimeError("workspace seed file write failed")
        remaining = remaining[written:]


root_descriptor = os.open(".", directory_flags)
try:
    root = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root.st_mode) or stat.S_IMODE(root.st_mode) != 0o700:
        raise RuntimeError("workspace seed root is unsafe")
    if os.listdir(root_descriptor):
        raise RuntimeError("workspace seed root is not empty")

    seen = set()
    entry_count = 0
    content_bytes = 0
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        for member in archive:
            entry_count += 1
            if entry_count > expected_entries:
                raise RuntimeError("workspace seed entry limit exceeded")
            parts = path_parts(member.name)
            if member.name in seen:
                raise RuntimeError("workspace seed contains a duplicate path")
            seen.add(member.name)
            mode = member.mode
            if mode < 0 or mode & ~0o777:
                raise RuntimeError("workspace seed mode is invalid")

            parent, name = open_parent(root_descriptor, parts)
            try:
                if member.isdir():
                    if member.type != tarfile.DIRTYPE or mode != 0o700:
                        raise RuntimeError("workspace seed directory mode is invalid")
                    os.mkdir(name, 0o700, dir_fd=parent)
                    directory = os.open(name, directory_flags, dir_fd=parent)
                    try:
                        os.fchmod(directory, 0o700)
                    finally:
                        os.close(directory)
                    continue

                if member.type == tarfile.REGTYPE:
                    if mode not in (0o600, 0o700) or member.size < 0:
                        raise RuntimeError("workspace seed file metadata is invalid")
                    content_bytes += member.size
                    if content_bytes > max_bytes:
                        raise RuntimeError("workspace seed byte limit exceeded")
                    source = archive.extractfile(member)
                    if source is None:
                        raise RuntimeError("workspace seed file content is unavailable")
                    descriptor = os.open(name, file_flags, 0o600, dir_fd=parent)
                    try:
                        remaining_bytes = member.size
                        while remaining_bytes:
                            data = source.read(min(chunk_size, remaining_bytes))
                            if not data:
                                raise RuntimeError("workspace seed file is truncated")
                            write_all(descriptor, data)
                            remaining_bytes -= len(data)
                        if source.read(1):
                            raise RuntimeError("workspace seed file size is inconsistent")
                        os.fchmod(descriptor, mode)
                    finally:
                        os.close(descriptor)
                        source.close()
                    continue

                if member.type == tarfile.SYMTYPE:
                    if mode != 0o777:
                        raise RuntimeError("workspace seed symlink mode is invalid")
                    validate_symlink(member.name, member.linkname)
                    content_bytes += len(member.linkname.encode("utf-8"))
                    if content_bytes > max_bytes:
                        raise RuntimeError("workspace seed byte limit exceeded")
                    os.symlink(member.linkname, name, dir_fd=parent)
                    continue

                raise RuntimeError("workspace seed entry type is unsupported")
            finally:
                os.close(parent)
    if entry_count != expected_entries:
        raise RuntimeError("workspace seed entry count mismatch")
finally:
    os.close(root_descriptor)
"""
