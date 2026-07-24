from __future__ import annotations

import errno
import hashlib
import math
import os
import posixpath
import re
import selectors
import shutil
import stat
import subprocess  # nosec B404
import tempfile
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import IO, NoReturn, Protocol

from zeus.audit_models import HARD_LIMITS, AuditLimits, SkippedContent
from zeus.audit_process import AuditProcessError, stop_process_group, wait_process_exit

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_EXECUTABLE_MODE = 0o700
_DISCOVERY_OUTPUT_BYTES = 64 * 1024
_BATCH_HEADER_BYTES = 256
_LFS_POINTER_MAX_BYTES = 1024
_SYMLINK_TARGET_BYTES = 8 * 1024
_PROCESS_READ_CHUNK = 64 * 1024
_OBJECT_ID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:")
_LFS_VERSION_VALUE = "https://git-lfs.github.com/spec/v1"
_LFS_KEY_RE = re.compile(r"[a-z0-9.-]+\Z")
_LFS_OID_VALUE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LFS_SIZE_VALUE_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_IGNORE_POLICY_BLOB_BYTES = 256 * 1024
_IGNORE_POLICY_METADATA_BYTES = 64 * 1024
_IGNORE_POLICY_OUTPUT_BYTES = 2 * 1024 * 1024
_IGNORE_POLICY_MAX_DEPTH = 64
_INDEX_DEBUG_RE = re.compile(
    rb"  ctime: (?P<ctime_seconds>[0-9]{1,20}):(?P<ctime_nanoseconds>[0-9]{1,20})\n"
    rb"  mtime: (?P<mtime_seconds>[0-9]{1,20}):(?P<mtime_nanoseconds>[0-9]{1,20})\n"
    rb"  dev: (?P<device>[0-9]{1,20})\tino: (?P<inode>[0-9]{1,20})\n"
    rb"  uid: (?P<uid>[0-9]{1,20})\tgid: (?P<gid>[0-9]{1,20})\n"
    rb"  size: (?P<size>[0-9]{1,20})\tflags: (?P<flags>[0-9a-f]{1,16})\n"
)


GIT_HARDENING_ARGUMENTS = (
    "--no-pager",
    "--literal-pathspecs",
    "--no-optional-locks",
    "--no-replace-objects",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    f"core.attributesFile={os.devnull}",
    "-c",
    "diff.external=",
    "-c",
    "diff.trustExitCode=false",
    "-c",
    "credential.helper=",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "maintenance.auto=false",
    "-c",
    "gc.auto=0",
)


class AuditWorkspaceError(RuntimeError):
    pass


@dataclass(frozen=True)
class _PathIdentity:
    device: int
    inode: int
    owner: int
    permissions: int


@dataclass(frozen=True)
class RepositoryLocation:
    root: Path
    git_dir: Path
    common_git_dir: Path
    repository_id: str
    head: str
    _root_identity: _PathIdentity
    _git_marker_identity: _PathIdentity
    _git_dir_identity: _PathIdentity
    _common_git_dir_identity: _PathIdentity


@dataclass(frozen=True)
class RepositoryChanges:
    dirty: bool
    staged: bool
    untracked: bool

    @property
    def has_changes(self) -> bool:
        return self.dirty or self.staged or self.untracked


@dataclass(frozen=True)
class RepositoryInspection:
    location: RepositoryLocation
    changes: RepositoryChanges


@dataclass(frozen=True)
class SnapshotManifestEntry:
    path: str
    object_id: str
    git_mode: str
    mode: int
    size: int
    sha256: str
    symlink_target: str | None = None

    @property
    def executable(self) -> bool:
        return self.git_mode == "100755"

    @property
    def is_symlink(self) -> bool:
        return self.git_mode == "120000"


@dataclass(frozen=True)
class MaterializedSnapshot:
    root: Path
    repository_id: str
    head: str
    manifest: tuple[SnapshotManifestEntry, ...]
    skipped_content: tuple[SkippedContent, ...]
    source_entry_count: int
    source_blob_bytes: int
    excluded_paths: tuple[str, ...]
    _root_identity: _PathIdentity


@dataclass(frozen=True)
class _OpenedSnapshotDestination:
    root: Path
    parent: Path
    name: str
    parent_descriptor: int
    root_descriptor: int
    parent_identity: _PathIdentity
    root_identity: _PathIdentity


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    object_type: str
    object_id: str
    size: int | None
    path: str


@dataclass(frozen=True)
class _IndexEntry:
    mode: str
    object_id: str
    stage: int
    path: str
    ctime_seconds: int
    ctime_nanoseconds: int
    mtime_seconds: int
    mtime_nanoseconds: int
    inode: int
    uid: int
    gid: int
    size: int


def _error(message: str) -> NoReturn:
    raise AuditWorkspaceError(message)


def _validate_deadline(deadline: float) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        _error("audit workspace deadline must be a finite monotonic timestamp")
    result = float(deadline)
    if result <= time.monotonic():
        _error("audit workspace deadline has expired")
    return result


def _bounded_deadline(deadline: float, seconds: int) -> float:
    validated = _validate_deadline(deadline)
    return min(validated, time.monotonic() + seconds)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _error("audit workspace deadline has expired")
    return remaining


def _check_optional_deadline(deadline: float | None) -> None:
    if deadline is not None:
        _remaining(deadline)


def _same_identity(left: _PathIdentity, right: _PathIdentity) -> bool:
    return left.device == right.device and left.inode == right.inode


def _path_identity(result: os.stat_result) -> _PathIdentity:
    return _PathIdentity(
        device=result.st_dev,
        inode=result.st_ino,
        owner=result.st_uid,
        permissions=stat.S_IMODE(result.st_mode),
    )


def _strict_utf8_path_text(value: str, description: str) -> None:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise AuditWorkspaceError(f"{description} is not valid normalized UTF-8") from exc
    if encoded.decode("utf-8", errors="strict") != value:
        _error(f"{description} is not valid normalized UTF-8")
    if unicodedata.normalize("NFC", value) != value:
        _error(f"{description} is not normalized UTF-8")


def _absolute_lexical_path(path: Path, description: str) -> Path:
    if not isinstance(path, Path):
        _error(f"{description} must be a pathlib.Path")
    absolute = Path(os.path.abspath(path))
    _strict_utf8_path_text(str(absolute), description)
    if Path(os.path.realpath(absolute)) != absolute:
        _error(f"{description} contains a symbolic link")
    return absolute


def _capture_safe_directory(
    path: Path,
    description: str,
    *,
    private: bool = False,
) -> _PathIdentity:
    try:
        result = path.lstat()
    except OSError as exc:
        raise AuditWorkspaceError(f"{description} is unavailable") from exc
    if stat.S_ISLNK(result.st_mode):
        _error(f"{description} must not be a symbolic link")
    if not stat.S_ISDIR(result.st_mode):
        _error(f"{description} is not a directory")
    if result.st_uid != os.geteuid():
        _error(f"{description} has an unexpected owner")
    permissions = stat.S_IMODE(result.st_mode)
    if permissions & 0o022:
        _error(f"{description} has unsafe permissions")
    if private and permissions & 0o077:
        _error(f"{description} does not have private permissions")
    return _path_identity(result)


def _capture_safe_regular_file(
    path: Path,
    description: str,
    *,
    allowed_owners: frozenset[int],
    executable: bool = False,
) -> _PathIdentity:
    try:
        result = path.lstat()
    except OSError as exc:
        raise AuditWorkspaceError(f"{description} is unavailable") from exc
    if stat.S_ISLNK(result.st_mode):
        _error(f"{description} must not be a symbolic link")
    if not stat.S_ISREG(result.st_mode) or result.st_nlink != 1:
        _error(f"{description} is not a single-link regular file")
    if result.st_uid not in allowed_owners:
        _error(f"{description} has an unexpected owner")
    permissions = stat.S_IMODE(result.st_mode)
    if permissions & 0o022:
        _error(f"{description} has unsafe permissions")
    if executable and not permissions & 0o111:
        _error(f"{description} is not executable")
    return _path_identity(result)


def _validate_identity(
    path: Path,
    expected: _PathIdentity,
    description: str,
    *,
    private: bool = False,
) -> None:
    current = _capture_safe_directory(path, description, private=private)
    if not _same_identity(current, expected) or current != expected:
        _error(f"{description} binding changed")


class _Digest(Protocol):
    def update(self, data: bytes) -> None: ...

    def hexdigest(self) -> str: ...


def _capture_repository_marker(root: Path) -> _PathIdentity:
    marker = root / ".git"
    try:
        result = marker.lstat()
    except OSError as exc:
        raise AuditWorkspaceError("repository Git administration marker is unavailable") from exc
    if stat.S_ISLNK(result.st_mode):
        _error("repository Git administration marker must not be a symbolic link")
    if not (stat.S_ISDIR(result.st_mode) or stat.S_ISREG(result.st_mode)):
        _error("repository Git administration marker has an unsupported type")
    if result.st_uid != os.geteuid():
        _error("repository Git administration marker has an unexpected owner")
    if stat.S_IMODE(result.st_mode) & 0o022:
        _error("repository Git administration marker has unsafe permissions")
    if stat.S_ISREG(result.st_mode) and result.st_nlink != 1:
        _error("repository Git administration marker has an unsafe link count")
    return _path_identity(result)


def _validate_repository_metadata(git_dir: Path, common_git_dir: Path) -> None:
    _capture_safe_regular_file(
        git_dir / "HEAD",
        "repository HEAD metadata",
        allowed_owners=frozenset({os.geteuid()}),
    )
    _capture_safe_directory(
        common_git_dir / "objects",
        "repository Git object database",
    )
    refs = common_git_dir / "refs"
    if os.path.lexists(refs):
        _capture_safe_directory(refs, "repository Git references")
    packed_refs = common_git_dir / "packed-refs"
    if os.path.lexists(packed_refs):
        _capture_safe_regular_file(
            packed_refs,
            "repository packed references",
            allowed_owners=frozenset({os.geteuid()}),
        )


def audit_git_environment() -> dict[str, str]:
    return {
        "HOME": os.devnull,
        "XDG_CONFIG_HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": os.devnull,
        "GIT_SSH_COMMAND": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PAGER": "cat",
    }


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if not stop_process_group(process):
        _error("Git process group cleanup could not be verified")


def _collect_bounded_process(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    max_output_bytes: int,
    description: str,
) -> bytes:
    if process.stdout is None or process.stderr is None:
        _stop_process(process)
        _error(f"{description} process pipes are unavailable")
    selector = selectors.DefaultSelector()
    output = bytearray()
    total = 0
    streams = (process.stdout, process.stderr)
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            events = selector.select(_remaining(deadline))
            if not events:
                _stop_process(process)
                _error(f"{description} exceeded its deadline")
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, _PROCESS_READ_CHUNK)
                except OSError as exc:
                    _stop_process(process)
                    raise AuditWorkspaceError(f"{description} output could not be read") from exc
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > max_output_bytes:
                    _stop_process(process)
                    _error(f"{description} output exceeded its metadata byte limit")
                if key.fileobj is process.stdout:
                    output.extend(chunk)
        try:
            return_code = wait_process_exit(process, deadline=deadline)
        except (AuditProcessError, subprocess.TimeoutExpired):
            _stop_process(process)
            _error(f"{description} exceeded its deadline")
        if return_code != 0:
            _error(f"{description} failed")
        return bytes(output)
    finally:
        selector.close()
        for stream in streams:
            with suppress(OSError):
                stream.close()
        if process.returncode is None:
            _stop_process(process)


def _single_line(data: bytes, description: str) -> str:
    if not data.endswith(b"\n") or data.count(b"\n") != 1 or b"\0" in data:
        _error(f"{description} returned ambiguous output")
    try:
        value = data[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditWorkspaceError(f"{description} is not valid UTF-8") from exc
    if not value:
        _error(f"{description} returned empty output")
    _strict_utf8_path_text(value, description)
    return value


def _single_oid(data: bytes, description: str) -> str:
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        _error(f"{description} returned ambiguous output")
    try:
        value = data[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditWorkspaceError(f"{description} is not an object ID") from exc
    if _OBJECT_ID_RE.fullmatch(value) is None:
        _error(f"{description} is not a full Git object ID")
    return value


def _validate_relative_path_text(value: str, description: str) -> str:
    _strict_utf8_path_text(value, description)
    if not value or value.startswith("/") or "\\" in value or "\0" in value:
        _error(f"{description} is not a confined relative POSIX path")
    components = value.split("/")
    if (
        any(component in {"", ".", ".."} for component in components)
        or any(component.casefold() == ".git" for component in components)
        or _WINDOWS_DRIVE_RE.match(components[0]) is not None
        or posixpath.normpath(value) != value
    ):
        _error(f"{description} is not a confined relative POSIX path")
    return value


def _validate_exclusions(exclude_paths: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(exclude_paths, tuple):
        _error("snapshot exclusions must be a tuple")
    result: list[str] = []
    folded: set[str] = set()
    for value in exclude_paths:
        if type(value) is not str:
            _error("snapshot exclusions must contain text paths")
        path = _validate_relative_path_text(value, "snapshot exclusion")
        casefolded = path.casefold()
        if casefolded in folded:
            _error("snapshot exclusions contain duplicate or case-colliding paths")
        folded.add(casefolded)
        result.append(path)
    return tuple(result)


def _is_excluded(path: str, exclusions: tuple[str, ...]) -> bool:
    return any(path == exclusion or path.startswith(f"{exclusion}/") for exclusion in exclusions)


def _path_is_within(path: Path, boundary: Path) -> bool:
    try:
        return Path(os.path.commonpath((path, boundary))) == boundary
    except ValueError:
        return False


def _existing_directory_is_within(directory: Path, boundary: Path) -> bool:
    for candidate in (directory, *directory.parents):
        try:
            if candidate.samefile(boundary):
                return True
        except OSError as exc:
            raise AuditWorkspaceError(
                "snapshot destination ancestry could not be inspected"
            ) from exc
    return False


def _validate_limits(limits: AuditLimits) -> None:
    if not isinstance(limits, AuditLimits):
        _error("audit workspace limits are invalid")
    for name in (
        "git_command_seconds",
        "materialization_seconds",
        "snapshot_entries",
        "git_metadata_bytes",
        "snapshot_blob_bytes",
    ):
        value = getattr(limits, name)
        hard = getattr(HARD_LIMITS, name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > hard:
            _error(f"audit workspace limit {name} is outside its hard ceiling")


def _decode_tree_path(path_bytes: bytes) -> str:
    try:
        path = path_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditWorkspaceError("Git tree path is not valid UTF-8") from exc
    return _validate_relative_path_text(path, "Git tree path")


def _parse_tree(data: bytes, limits: AuditLimits) -> tuple[tuple[_TreeEntry, ...], int]:
    if not data:
        return (), 0
    if not data.endswith(b"\0"):
        _error("Git tree metadata is not NUL terminated")
    records = data[:-1].split(b"\0")
    if len(records) > limits.snapshot_entries:
        _error("Git tree entry count exceeded the snapshot entry limit")

    entries: list[_TreeEntry] = []
    blob_bytes = 0
    paths: set[str] = set()
    casefolded_prefixes: dict[str, str] = {}
    for record in records:
        try:
            header, path_bytes = record.split(b"\t", 1)
            mode_bytes, type_bytes, object_id_bytes, size_bytes = header.split()
            mode = mode_bytes.decode("ascii", errors="strict")
            object_type = type_bytes.decode("ascii", errors="strict")
            object_id = object_id_bytes.decode("ascii", errors="strict")
            size_text = size_bytes.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditWorkspaceError("Git tree metadata has an invalid record") from exc
        if _OBJECT_ID_RE.fullmatch(object_id) is None:
            _error("Git tree metadata contains an invalid object ID")
        path = _decode_tree_path(path_bytes)
        if path in paths:
            _error("Git tree metadata contains a duplicate path")
        paths.add(path)

        components = path.split("/")
        for index in range(1, len(components) + 1):
            prefix = "/".join(components[:index])
            folded = prefix.casefold()
            previous = casefolded_prefixes.get(folded)
            if previous is not None and previous != prefix:
                _error("Git tree metadata contains a case-colliding path")
            casefolded_prefixes[folded] = prefix

        if mode in {"100644", "100755", "120000"}:
            if object_type != "blob" or not size_text.isdigit():
                _error("Git tree metadata contains an invalid blob entry")
            size = int(size_text)
            blob_bytes += size
            if blob_bytes > limits.snapshot_blob_bytes:
                _error("Git tree blob byte count exceeded the snapshot blob byte limit")
        elif mode == "160000":
            if object_type != "commit" or size_text != "-":
                _error("Git tree metadata contains an invalid gitlink entry")
            size = None
        else:
            _error("Git tree metadata contains an unsupported mode")
        entries.append(
            _TreeEntry(
                mode=mode,
                object_type=object_type,
                object_id=object_id,
                size=size,
                path=path,
            )
        )

    for path in paths:
        components = path.split("/")
        for index in range(1, len(components)):
            if "/".join(components[:index]) in paths:
                _error("Git tree metadata contains a file and directory path conflict")
    return tuple(entries), blob_bytes


def _parse_index_metadata(
    data: bytes,
    limits: AuditLimits,
) -> tuple[_IndexEntry, ...]:
    if not data:
        return ()
    entries: list[_IndexEntry] = []
    keys: set[tuple[str, int]] = set()
    oid_length: int | None = None
    position = 0
    while position < len(data):
        terminator = data.find(b"\0", position)
        if terminator < 0:
            _error("Git index metadata has an unterminated record")
        header = data[position:terminator]
        position = terminator + 1
        try:
            metadata, path_bytes = header.split(b"\t", 1)
            mode_bytes, object_id_bytes, stage_bytes = metadata.split(b" ")
            mode = mode_bytes.decode("ascii", errors="strict")
            object_id = object_id_bytes.decode("ascii", errors="strict")
            stage_text = stage_bytes.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditWorkspaceError("Git index metadata has an invalid record") from exc
        if mode not in {"100644", "100755", "120000", "160000"}:
            _error("Git index metadata contains an unsupported mode")
        if _OBJECT_ID_RE.fullmatch(object_id) is None:
            _error("Git index metadata contains an invalid object ID")
        if oid_length is None:
            oid_length = len(object_id)
        elif len(object_id) != oid_length:
            _error("Git index metadata mixes object ID formats")
        if stage_text not in {"0", "1", "2", "3"}:
            _error("Git index metadata contains an invalid stage")
        stage = int(stage_text)
        path = _decode_tree_path(path_bytes)
        key = (path, stage)
        if key in keys:
            _error("Git index metadata contains a duplicate path and stage")
        keys.add(key)
        match = _INDEX_DEBUG_RE.match(data, position)
        if match is None:
            _error("Git index debug metadata has an invalid record")
        position = match.end()
        try:
            values = {
                name: int(match.group(name), 10)
                for name in (
                    "ctime_seconds",
                    "ctime_nanoseconds",
                    "mtime_seconds",
                    "mtime_nanoseconds",
                    "inode",
                    "uid",
                    "gid",
                    "size",
                )
            }
        except ValueError as exc:
            raise AuditWorkspaceError("Git index debug metadata has an invalid number") from exc
        if values["ctime_nanoseconds"] >= 1_000_000_000:
            _error("Git index debug metadata has an invalid ctime")
        if values["mtime_nanoseconds"] >= 1_000_000_000:
            _error("Git index debug metadata has an invalid mtime")
        entries.append(
            _IndexEntry(
                mode=mode,
                object_id=object_id,
                stage=stage,
                path=path,
                ctime_seconds=values["ctime_seconds"],
                ctime_nanoseconds=values["ctime_nanoseconds"],
                mtime_seconds=values["mtime_seconds"],
                mtime_nanoseconds=values["mtime_nanoseconds"],
                inode=values["inode"],
                uid=values["uid"],
                gid=values["gid"],
                size=values["size"],
            )
        )
        if len(entries) > limits.snapshot_entries * 4:
            _error("Git index entry count exceeded the metadata entry limit")
    return tuple(entries)


def _parse_head_index_metadata(
    data: bytes,
    limits: AuditLimits,
) -> dict[str, tuple[str, str]]:
    if not data:
        return {}
    if not data.endswith(b"\0"):
        _error("Git HEAD metadata is not NUL terminated")
    records = data[:-1].split(b"\0")
    if len(records) > limits.snapshot_entries:
        _error("Git HEAD entry count exceeded the metadata entry limit")
    result: dict[str, tuple[str, str]] = {}
    oid_length: int | None = None
    for record in records:
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode_bytes, type_bytes, object_id_bytes = metadata.split(b" ")
            mode = mode_bytes.decode("ascii", errors="strict")
            object_type = type_bytes.decode("ascii", errors="strict")
            object_id = object_id_bytes.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditWorkspaceError("Git HEAD metadata has an invalid record") from exc
        if mode in {"100644", "100755", "120000"}:
            if object_type != "blob":
                _error("Git HEAD metadata contains an invalid blob entry")
        elif mode == "160000":
            if object_type != "commit":
                _error("Git HEAD metadata contains an invalid gitlink entry")
        else:
            _error("Git HEAD metadata contains an unsupported mode")
        if _OBJECT_ID_RE.fullmatch(object_id) is None:
            _error("Git HEAD metadata contains an invalid object ID")
        if oid_length is None:
            oid_length = len(object_id)
        elif len(object_id) != oid_length:
            _error("Git HEAD metadata mixes object ID formats")
        path = _decode_tree_path(path_bytes)
        if path in result:
            _error("Git HEAD metadata contains a duplicate path")
        result[path] = (mode, object_id)
    return result


def _parse_untracked_metadata(data: bytes) -> bool:
    if not data:
        return False
    if not data.endswith(b"\0"):
        _error("Git untracked metadata is not NUL terminated")
    records = data[:-1].split(b"\0")
    if any(not record for record in records):
        _error("Git untracked metadata contains an empty record")
    seen: set[bytes] = set()
    for record in records:
        if record in seen:
            _error("Git untracked metadata contains a duplicate path")
        seen.add(record)
        try:
            path = record.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AuditWorkspaceError("Git untracked path is not valid UTF-8") from exc
        if path.endswith("/"):
            path = path[:-1]
        _validate_relative_path_text(path, "Git untracked path")
    return True


def _required_posix_open_flags(*names: str) -> int:
    flags = os.O_RDONLY
    for name in names:
        value = getattr(os, name, None)
        if not isinstance(value, int) or value == 0:
            _error(f"required POSIX flag {name} is unavailable")
        flags |= value
    return flags


def _lstat_tracked_path(root_descriptor: int, path: str) -> os.stat_result | None:
    components = path.split("/")
    directory_descriptor = root_descriptor
    owned_descriptor: int | None = None
    directory_flags = _required_posix_open_flags(
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_CLOEXEC",
    )
    try:
        for component in components[:-1]:
            try:
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                if exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
                    return None
                raise AuditWorkspaceError(
                    "tracked worktree parent metadata could not be inspected"
                ) from exc
            if owned_descriptor is not None:
                os.close(owned_descriptor)
            owned_descriptor = next_descriptor
            directory_descriptor = next_descriptor
        try:
            return os.lstat(components[-1], dir_fd=directory_descriptor)
        except OSError as exc:
            if exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}:
                return None
            raise AuditWorkspaceError("tracked worktree metadata could not be inspected") from exc
    finally:
        if owned_descriptor is not None:
            with suppress(OSError):
                os.close(owned_descriptor)


def _index_entry_matches_worktree(
    entry: _IndexEntry,
    result: os.stat_result,
) -> bool:
    if entry.mode in {"100644", "100755"}:
        if not stat.S_ISREG(result.st_mode):
            return False
        if bool(result.st_mode & 0o111) != (entry.mode == "100755"):
            return False
    elif entry.mode == "120000":
        if not stat.S_ISLNK(result.st_mode):
            return False
    elif entry.mode == "160000":
        if not stat.S_ISDIR(result.st_mode):
            return False
    else:
        _error("Git index metadata contains an unsupported mode")
    ctime_seconds, ctime_nanoseconds = divmod(result.st_ctime_ns, 1_000_000_000)
    mtime_seconds, mtime_nanoseconds = divmod(result.st_mtime_ns, 1_000_000_000)
    mask = 0xFFFF_FFFF
    return (
        entry.ctime_seconds == ctime_seconds & mask
        and entry.ctime_nanoseconds == ctime_nanoseconds
        and entry.mtime_seconds == mtime_seconds & mask
        and entry.mtime_nanoseconds == mtime_nanoseconds
        and entry.inode == result.st_ino & mask
        and entry.uid == result.st_uid & mask
        and entry.gid == result.st_gid & mask
        and entry.size == result.st_size & mask
    )


def _tracked_worktree_is_dirty(
    location: RepositoryLocation,
    entries: tuple[_IndexEntry, ...],
    *,
    deadline: float,
) -> bool:
    _remaining(deadline)
    if any(entry.stage != 0 for entry in entries):
        return True
    flags = _required_posix_open_flags(
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_CLOEXEC",
    )
    try:
        root_descriptor = os.open(location.root, flags)
    except OSError as exc:
        raise AuditWorkspaceError("repository root could not be opened safely") from exc
    try:
        opened = os.fstat(root_descriptor)
        if _path_identity(opened) != location._root_identity:
            _error("repository root binding changed")
        for entry in entries:
            _remaining(deadline)
            result = _lstat_tracked_path(root_descriptor, entry.path)
            _remaining(deadline)
            if result is None or not _index_entry_matches_worktree(entry, result):
                return True
        return False
    except OSError as exc:
        raise AuditWorkspaceError("tracked worktree metadata could not be inspected") from exc
    finally:
        with suppress(OSError):
            os.close(root_descriptor)


def _looks_like_lfs_pointer(data: bytes) -> bool:
    if not data or len(data) >= _LFS_POINTER_MAX_BYTES or not data.endswith(b"\n"):
        return False
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    if "\r" in text or "\0" in text:
        return False
    lines = text[:-1].split("\n")
    if not lines or lines[0] != f"version {_LFS_VERSION_VALUE}":
        return False

    seen = {"version"}
    previous_key = ""
    has_oid = False
    has_size = False
    for line in lines[1:]:
        key, separator, value = line.partition(" ")
        if (
            separator != " "
            or not value
            or value.startswith(" ")
            or _LFS_KEY_RE.fullmatch(key) is None
            or key in seen
            or key <= previous_key
        ):
            return False
        seen.add(key)
        previous_key = key
        if key == "oid":
            if _LFS_OID_VALUE_RE.fullmatch(value) is None:
                return False
            has_oid = True
        elif key == "size":
            if _LFS_SIZE_VALUE_RE.fullmatch(value) is None:
                return False
            has_size = True
    return has_oid and has_size


def _git_blob_digest(object_id: str, size: int) -> _Digest:
    if len(object_id) == 40:
        # SHA-1 is selected by the repository object format, not for new security design.
        digest = hashlib.sha1()  # nosec B324
    elif len(object_id) == 64:
        digest = hashlib.sha256()
    else:
        _error("Git blob has an unsupported object ID format")
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def _verify_small_git_blob(entry: _TreeEntry, data: bytes) -> None:
    digest = _git_blob_digest(entry.object_id, len(data))
    digest.update(data)
    if digest.hexdigest() != entry.object_id:
        _error("Git blob content does not match its object ID")


def _blob_size(entry: _TreeEntry) -> int:
    if entry.size is None:
        _error("Git blob entry is missing its declared size")
    return entry.size


def _decode_symlink_target(data: bytes, path: str) -> str:
    if len(data) > _SYMLINK_TARGET_BYTES:
        _error(f"snapshot symlink target for {path} is too large")
    try:
        target = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditWorkspaceError(f"snapshot symlink target for {path} is not UTF-8") from exc
    _strict_utf8_path_text(target, f"snapshot symlink target for {path}")
    if (
        not target
        or target.startswith("/")
        or "\\" in target
        or "\0" in target
        or _WINDOWS_DRIVE_RE.match(target.split("/", 1)[0]) is not None
    ):
        _error(f"snapshot symlink target for {path} is not confined")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        _error(f"snapshot symlink target for {path} escapes the snapshot")
    if any(component.casefold() == ".git" for component in resolved.split("/")):
        _error(f"snapshot symlink target for {path} reaches Git metadata")
    return target


class _BoundedPipeReader:
    def __init__(
        self,
        stream: IO[bytes],
        *,
        deadline: float,
        byte_limit: int,
    ) -> None:
        self._stream = stream
        self._deadline = deadline
        self._byte_limit = byte_limit
        self._bytes_read = 0
        self._buffer = bytearray()
        self._selector = selectors.DefaultSelector()
        self._selector.register(stream, selectors.EVENT_READ)

    def close(self) -> None:
        self._selector.close()

    def _read_chunk(self) -> bytes:
        events = self._selector.select(_remaining(self._deadline))
        if not events:
            _error("Git blob stream exceeded its deadline")
        try:
            chunk = os.read(self._stream.fileno(), _PROCESS_READ_CHUNK)
        except OSError as exc:
            raise AuditWorkspaceError("Git blob stream could not be read") from exc
        if not chunk:
            _error("Git blob stream ended unexpectedly")
        self._bytes_read += len(chunk)
        if self._bytes_read > self._byte_limit:
            _error("Git blob stream exceeded its byte limit")
        return chunk

    def read_until(self, delimiter: bytes, maximum: int) -> bytes:
        while True:
            index = self._buffer.find(delimiter)
            if index >= 0:
                end = index + len(delimiter)
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if len(self._buffer) >= maximum:
                _error("Git blob stream header exceeded its byte limit")
            self._buffer.extend(self._read_chunk())
            if len(self._buffer) > maximum and delimiter not in self._buffer[: maximum + 1]:
                _error("Git blob stream header exceeded its byte limit")

    def read_exact(self, size: int) -> bytes:
        if size < 0:
            _error("Git blob stream requested a negative byte count")
        while len(self._buffer) < size:
            self._buffer.extend(self._read_chunk())
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def copy_exact(
        self,
        size: int,
        destination_fd: int,
        digests: tuple[_Digest, ...],
    ) -> None:
        remaining = size
        while remaining:
            if self._buffer:
                chunk_size = min(remaining, len(self._buffer))
                chunk = bytes(self._buffer[:chunk_size])
                del self._buffer[:chunk_size]
            else:
                received = self._read_chunk()
                chunk = received[:remaining]
                self._buffer.extend(received[len(chunk) :])
            view = memoryview(chunk)
            while view:
                try:
                    written = os.write(destination_fd, view)
                except OSError as exc:
                    raise AuditWorkspaceError(
                        "materialized snapshot file could not be written"
                    ) from exc
                if written <= 0:
                    _error("materialized snapshot file write made no progress")
                view = view[written:]
            for digest in digests:
                digest.update(chunk)
            remaining -= len(chunk)

    def ensure_eof(self) -> None:
        if self._buffer:
            _error("Git blob stream returned unexpected trailing output")
        while True:
            events = self._selector.select(_remaining(self._deadline))
            if not events:
                _error("Git blob stream exceeded its deadline")
            try:
                chunk = os.read(self._stream.fileno(), _PROCESS_READ_CHUNK)
            except OSError as exc:
                raise AuditWorkspaceError("Git blob stream could not be read") from exc
            if not chunk:
                return
            self._bytes_read += len(chunk)
            if self._bytes_read > self._byte_limit:
                _error("Git blob stream exceeded its byte limit")
            _error("Git blob stream returned unexpected trailing output")


class AuditWorkspace:
    def __init__(self, git_executable: Path | None = None) -> None:
        if git_executable is None:
            resolved = shutil.which("git")
            if resolved is None:
                raise AuditWorkspaceError("Git executable is unavailable")
            candidate = Path(resolved)
        else:
            if not isinstance(git_executable, Path):
                raise AuditWorkspaceError("Git executable must be a pathlib.Path")
            candidate = git_executable
        try:
            self._git_executable = candidate.resolve(strict=True)
        except OSError as exc:
            raise AuditWorkspaceError("Git executable is unavailable") from exc
        if not self._git_executable.is_absolute():
            raise AuditWorkspaceError("Git executable did not resolve to an absolute path")
        self._git_identity = _capture_safe_regular_file(
            self._git_executable,
            "Git executable",
            allowed_owners=frozenset({0, os.geteuid()}),
            executable=True,
        )

    def _validate_git_executable(self) -> None:
        current = _capture_safe_regular_file(
            self._git_executable,
            "Git executable",
            allowed_owners=frozenset({0, os.geteuid()}),
            executable=True,
        )
        if current != self._git_identity:
            _error("Git executable binding changed")

    def _argv(
        self,
        cwd: Path,
        arguments: tuple[str, ...],
        *,
        literal_pathspecs: bool = True,
    ) -> tuple[str, ...]:
        return (
            str(self._git_executable),
            *(
                argument
                for argument in GIT_HARDENING_ARGUMENTS
                if literal_pathspecs or argument != "--literal-pathspecs"
            ),
            "-C",
            str(cwd),
            *arguments,
        )

    def _spawn(
        self,
        cwd: Path,
        arguments: tuple[str, ...],
        *,
        stdin: int,
        stderr: int,
        literal_pathspecs: bool = True,
    ) -> subprocess.Popen[bytes]:
        self._validate_git_executable()
        try:
            return subprocess.Popen(  # nosec B603
                self._argv(
                    cwd,
                    arguments,
                    literal_pathspecs=literal_pathspecs,
                ),
                cwd=cwd,
                env=audit_git_environment(),
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=stderr,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            raise AuditWorkspaceError("Git process could not be started") from exc

    def _run(
        self,
        cwd: Path,
        arguments: tuple[str, ...],
        *,
        deadline: float,
        command_seconds: int,
        max_output_bytes: int,
        description: str,
        input_data: bytes | None = None,
        literal_pathspecs: bool = True,
    ) -> bytes:
        command_deadline = _bounded_deadline(deadline, command_seconds)
        process = self._spawn(
            cwd,
            arguments,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            literal_pathspecs=literal_pathspecs,
        )
        if input_data is not None:
            if process.stdin is None:
                _stop_process(process)
                _error(f"{description} input pipe is unavailable")
            try:
                written = process.stdin.write(input_data)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError) as exc:
                _stop_process(process)
                raise AuditWorkspaceError(f"{description} input could not be written") from exc
            if written != len(input_data):
                _stop_process(process)
                _error(f"{description} input could not be written completely")
        return _collect_bounded_process(
            process,
            deadline=command_deadline,
            max_output_bytes=max_output_bytes,
            description=description,
        )

    def committed_ignore_matches(
        self,
        location: RepositoryLocation,
        *,
        state_relative: Path,
        ignored_paths: tuple[str, ...],
        deadline: float,
    ) -> dict[str, str]:
        """Evaluate only bounded ignore rules loaded from the exact committed tree."""
        if not isinstance(location, RepositoryLocation):
            _error("repository location is invalid")
        if (
            not isinstance(state_relative, Path)
            or state_relative.is_absolute()
            or not state_relative.parts
            or len(state_relative.parts) > _IGNORE_POLICY_MAX_DEPTH
        ):
            _error("audit state ignore policy path is invalid")
        state_text = _validate_relative_path_text(
            state_relative.as_posix(),
            "audit state ignore policy path",
        )
        if state_text != state_relative.as_posix():
            _error("audit state ignore policy path is invalid")
        if not ignored_paths or len(set(ignored_paths)) != len(ignored_paths):
            _error("audit state ignore policy probes are invalid")
        for path in ignored_paths:
            _validate_relative_path_text(path.rstrip("/"), "audit state ignore policy probe")

        candidates = tuple(
            Path(*state_relative.parts[:depth], ".gitignore").as_posix()
            for depth in range(len(state_relative.parts) + 1)
        )
        self._validate_location_bindings(location)
        policy_limits = replace(
            HARD_LIMITS,
            snapshot_entries=len(candidates),
            snapshot_blob_bytes=_IGNORE_POLICY_BLOB_BYTES,
            git_metadata_bytes=_IGNORE_POLICY_METADATA_BYTES,
        )
        tree_output = self._run(
            location.root,
            (
                "ls-tree",
                "-z",
                "--full-tree",
                "--long",
                location.head,
                "--",
                *candidates,
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=_IGNORE_POLICY_METADATA_BYTES,
            description="committed audit ignore metadata",
        )
        entries, _blob_bytes = _parse_tree(tree_output, policy_limits)
        if any(entry.path not in candidates for entry in entries):
            _error("committed audit ignore metadata returned an unexpected path")

        committed: dict[str, bytes] = {}
        for entry in entries:
            if entry.mode != "100644" or entry.size is None:
                _error("committed audit ignore policy must use regular non-executable files")
            data = self._run(
                location.root,
                ("cat-file", "blob", entry.object_id),
                deadline=deadline,
                command_seconds=HARD_LIMITS.git_command_seconds,
                max_output_bytes=max(1, entry.size),
                description="committed audit ignore policy",
            )
            if len(data) != entry.size or b"\0" in data:
                _error("committed audit ignore policy content is invalid")
            try:
                data.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise AuditWorkspaceError(
                    "committed audit ignore policy is not valid UTF-8"
                ) from exc
            committed[entry.path] = data

        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        for boundary in (location.root, location.git_dir, location.common_git_dir):
            if _path_is_within(temporary_root, boundary):
                _error("audit ignore policy staging root overlaps repository boundaries")
        with tempfile.TemporaryDirectory(
            prefix="zeus-audit-ignore-",
            dir=temporary_root,
        ) as temporary:
            policy_root = Path(temporary)
            for path, data in committed.items():
                destination = policy_root / path
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                current = destination.parent
                while current != policy_root:
                    current.chmod(0o700)
                    current = current.parent
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    os.close(descriptor)
            output = self._run(
                policy_root,
                (
                    "-c",
                    f"core.excludesFile={os.devnull}",
                    f"--git-dir={location.git_dir}",
                    f"--work-tree={policy_root}",
                    "check-ignore",
                    "-v",
                    "-z",
                    "--no-index",
                    "--stdin",
                ),
                deadline=deadline,
                command_seconds=HARD_LIMITS.git_command_seconds,
                max_output_bytes=_IGNORE_POLICY_OUTPUT_BYTES,
                description="committed audit ignore evaluation",
                input_data=b"".join(
                    path.encode("utf-8", errors="strict") + b"\0" for path in ignored_paths
                ),
                literal_pathspecs=False,
            )

        fields = output.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        if len(fields) % 4 != 0:
            _error("committed audit ignore evaluation returned ambiguous output")
        matched: dict[str, str] = {}
        try:
            for offset in range(0, len(fields), 4):
                source, _line, _pattern, pathname = (
                    field.decode("utf-8", errors="strict") for field in fields[offset : offset + 4]
                )
                if _pattern.startswith("!"):
                    _error("committed audit ignore policy contains a matching negation")
                if pathname in matched:
                    _error("committed audit ignore evaluation returned duplicate output")
                matched[pathname] = source
        except UnicodeDecodeError as exc:
            raise AuditWorkspaceError(
                "committed audit ignore evaluation returned invalid output"
            ) from exc
        if set(matched) != set(ignored_paths) or any(
            source not in committed for source in matched.values()
        ):
            _error("audit state path is not ignored by committed repository policy")
        self._validate_location_bindings(location)
        return matched

    def _resolve_path(
        self,
        cwd: Path,
        argument: str,
        *,
        deadline: float,
        command_seconds: int,
        description: str,
    ) -> Path:
        output = self._run(
            cwd,
            ("rev-parse", "--path-format=absolute", argument),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description=description,
        )
        value = _single_line(output, description)
        path = Path(value)
        if not path.is_absolute():
            _error(f"{description} is not absolute")
        return _absolute_lexical_path(path, description)

    def _resolve_head(
        self,
        cwd: Path,
        *,
        deadline: float,
        command_seconds: int,
    ) -> str:
        output = self._run(
            cwd,
            ("rev-parse", "--verify", "HEAD^{commit}"),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description="committed HEAD discovery",
        )
        return _single_oid(output, "committed HEAD")

    def _discover(
        self,
        cwd: Path,
        *,
        deadline: float,
        command_seconds: int,
    ) -> RepositoryLocation:
        _validate_deadline(deadline)
        safe_cwd = _absolute_lexical_path(cwd, "repository discovery directory")
        _capture_safe_directory(safe_cwd, "repository discovery directory")
        root = self._resolve_path(
            safe_cwd,
            "--show-toplevel",
            deadline=deadline,
            command_seconds=command_seconds,
            description="repository root discovery",
        )
        git_dir = self._resolve_path(
            safe_cwd,
            "--absolute-git-dir",
            deadline=deadline,
            command_seconds=command_seconds,
            description="Git directory discovery",
        )
        common_git_dir = self._resolve_path(
            safe_cwd,
            "--git-common-dir",
            deadline=deadline,
            command_seconds=command_seconds,
            description="common Git directory discovery",
        )
        root_identity = _capture_safe_directory(root, "repository root")
        git_dir_identity = _capture_safe_directory(git_dir, "repository Git directory")
        common_git_dir_identity = _capture_safe_directory(
            common_git_dir, "repository common Git directory"
        )
        git_marker_identity = _capture_repository_marker(root)
        _validate_repository_metadata(git_dir, common_git_dir)
        head = self._resolve_head(
            root,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        repository_id = hashlib.sha256(str(root).encode("utf-8", errors="strict")).hexdigest()
        return RepositoryLocation(
            root=root,
            git_dir=git_dir,
            common_git_dir=common_git_dir,
            repository_id=repository_id,
            head=head,
            _root_identity=root_identity,
            _git_marker_identity=git_marker_identity,
            _git_dir_identity=git_dir_identity,
            _common_git_dir_identity=common_git_dir_identity,
        )

    def discover(self, cwd: Path, *, deadline: float) -> RepositoryLocation:
        return self._discover(
            cwd,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )

    def _revalidate(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
        command_seconds: int,
    ) -> RepositoryLocation:
        if not isinstance(location, RepositoryLocation):
            _error("repository location is invalid")
        _validate_deadline(deadline)
        self._validate_location_bindings(location)
        self._reject_external_object_sources(
            location,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        current = self._discover(
            location.root,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        if current != location:
            _error("repository binding or committed HEAD changed")
        self._reject_external_object_sources(
            current,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        return current

    def revalidate(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
    ) -> RepositoryLocation:
        return self._revalidate(
            location,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )

    def _validate_location_bindings(self, location: RepositoryLocation) -> None:
        _validate_identity(
            location.root,
            location._root_identity,
            "repository root",
        )
        _validate_identity(
            location.git_dir,
            location._git_dir_identity,
            "repository Git directory",
        )
        _validate_identity(
            location.common_git_dir,
            location._common_git_dir_identity,
            "repository common Git directory",
        )
        marker = _capture_repository_marker(location.root)
        if marker != location._git_marker_identity:
            _error("repository Git administration marker binding changed")
        _validate_repository_metadata(location.git_dir, location.common_git_dir)

    def _reject_external_object_sources(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
        command_seconds: int,
    ) -> None:
        checked: set[Path] = set()
        for git_directory in (location.git_dir, location.common_git_dir):
            if git_directory in checked:
                continue
            checked.add(git_directory)
            for relative_path, description in (
                (Path("objects/info/alternates"), "Git object alternate"),
                (Path("objects/info/http-alternates"), "Git HTTP object alternate"),
                (Path("info/grafts"), "Git graft replacement"),
            ):
                path = git_directory / relative_path
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise AuditWorkspaceError(f"{description} could not be inspected") from exc
                _error(f"{description} is not allowed")
        replacements = self._run(
            location.root,
            ("for-each-ref", "--format=%(refname)", "refs/replace/"),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description="Git replacement reference inspection",
        )
        if replacements:
            _error("Git replacement references are not allowed")

    def inspect(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
    ) -> RepositoryInspection:
        _validate_deadline(deadline)
        self._revalidate(
            location,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )
        index_data = self._run(
            location.root,
            (
                "ls-files",
                "--stage",
                "--debug",
                "-z",
                "--full-name",
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git index metadata",
        )
        head_data = self._run(
            location.root,
            (
                "ls-tree",
                "-rz",
                "--full-tree",
                location.head,
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git HEAD metadata",
        )
        untracked_data = self._run(
            location.root,
            (
                "ls-files",
                "--others",
                "--directory",
                "-z",
                "--full-name",
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git untracked metadata",
        )
        index_entries = _parse_index_metadata(index_data, HARD_LIMITS)
        head_entries = _parse_head_index_metadata(head_data, HARD_LIMITS)
        stage_zero = {
            entry.path: (entry.mode, entry.object_id) for entry in index_entries if entry.stage == 0
        }
        staged = any(entry.stage != 0 for entry in index_entries) or stage_zero != head_entries
        changes = RepositoryChanges(
            dirty=_tracked_worktree_is_dirty(
                location,
                index_entries,
                deadline=deadline,
            ),
            staged=staged,
            untracked=_parse_untracked_metadata(untracked_data),
        )
        self._validate_location_bindings(location)
        self._reject_external_object_sources(
            location,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )
        if (
            self._resolve_head(
                location.root,
                deadline=deadline,
                command_seconds=HARD_LIMITS.git_command_seconds,
            )
            != location.head
        ):
            _error("committed HEAD changed during repository inspection")
        return RepositoryInspection(location=location, changes=changes)

    def _tree_entries(
        self,
        inspection: RepositoryInspection,
        *,
        limits: AuditLimits,
        deadline: float,
        command_seconds: int,
    ) -> tuple[tuple[_TreeEntry, ...], int]:
        output = self._run(
            inspection.location.root,
            (
                "ls-tree",
                "-rz",
                "--full-tree",
                "--long",
                inspection.location.head,
            ),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=limits.git_metadata_bytes,
            description="Git tree metadata",
        )
        return _parse_tree(output, limits)

    def _prepare_destination(
        self,
        location: RepositoryLocation,
        destination: Path,
    ) -> _OpenedSnapshotDestination:
        safe_destination = Path(os.path.abspath(destination))
        _strict_utf8_path_text(str(safe_destination), "snapshot destination")
        if safe_destination.name in {"", ".", ".."}:
            _error("snapshot destination must have a confined leaf name")
        for boundary in {
            location.root,
            location.git_dir,
            location.common_git_dir,
        }:
            if _path_is_within(safe_destination, boundary):
                _error("snapshot destination is inside repository boundaries")
        parent = _absolute_lexical_path(safe_destination.parent, "snapshot destination parent")
        for boundary in {
            location.root,
            location.git_dir,
            location.common_git_dir,
        }:
            if _existing_directory_is_within(parent, boundary):
                _error("snapshot destination is inside repository boundaries")
        parent_identity = _capture_safe_directory(
            parent,
            "snapshot destination parent",
            private=True,
        )
        directory_flags = _required_posix_open_flags(
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        try:
            parent_descriptor = os.open(parent, directory_flags)
        except OSError as exc:
            raise AuditWorkspaceError(
                "snapshot destination parent could not be opened safely"
            ) from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError(
                "snapshot destination parent cannot be opened safely"
            ) from exc
        root_descriptor: int | None = None
        try:
            parent_opened = os.fstat(parent_descriptor)
            try:
                parent_current = _capture_safe_directory(
                    parent,
                    "snapshot destination parent",
                    private=True,
                )
            except AuditWorkspaceError as exc:
                raise AuditWorkspaceError("snapshot destination parent binding changed") from exc
            if (
                _path_identity(parent_opened) != parent_identity
                or parent_current != parent_identity
            ):
                _error("snapshot destination parent binding changed")
            self._validate_location_bindings(location)
            os.mkdir(
                safe_destination.name,
                _PRIVATE_DIRECTORY_MODE,
                dir_fd=parent_descriptor,
            )
        except FileExistsError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("snapshot destination already exists") from exc
        except OSError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("snapshot destination could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("snapshot destination cannot be created safely") from exc
        except BaseException:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise
        try:
            before = os.lstat(safe_destination.name, dir_fd=parent_descriptor)
            root_descriptor = os.open(
                safe_destination.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            os.fchmod(root_descriptor, _PRIVATE_DIRECTORY_MODE)
            opened = os.fstat(root_descriptor)
            after = os.lstat(safe_destination.name, dir_fd=parent_descriptor)
            before_identity = _path_identity(before)
            root_identity = _path_identity(opened)
            if (
                not stat.S_ISDIR(before.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(after.st_mode)
                or before.st_uid != os.geteuid()
                or root_identity.owner != os.geteuid()
                or root_identity.permissions != _PRIVATE_DIRECTORY_MODE
                or not _same_identity(before_identity, root_identity)
                or _path_identity(after) != root_identity
            ):
                _error("snapshot destination binding changed")
            opened_destination = _OpenedSnapshotDestination(
                root=safe_destination,
                parent=parent,
                name=safe_destination.name,
                parent_descriptor=parent_descriptor,
                root_descriptor=root_descriptor,
                parent_identity=parent_identity,
                root_identity=root_identity,
            )
            self._validate_opened_destination(location, opened_destination)
            return opened_destination
        except BaseException:
            if root_descriptor is not None:
                with suppress(OSError):
                    os.fchmod(root_descriptor, _PRIVATE_DIRECTORY_MODE)
                with suppress(OSError):
                    os.close(root_descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)
            raise

    def _validate_opened_destination(
        self,
        location: RepositoryLocation,
        opened_destination: _OpenedSnapshotDestination,
    ) -> None:
        try:
            parent_opened = os.fstat(opened_destination.parent_descriptor)
            root_opened = os.fstat(opened_destination.root_descriptor)
            root_relative = os.lstat(
                opened_destination.name,
                dir_fd=opened_destination.parent_descriptor,
            )
        except OSError as exc:
            raise AuditWorkspaceError("snapshot destination binding changed") from exc
        if _path_identity(parent_opened) != opened_destination.parent_identity:
            _error("snapshot destination parent binding changed")
        try:
            parent_current = _capture_safe_directory(
                opened_destination.parent,
                "snapshot destination parent",
                private=True,
            )
        except AuditWorkspaceError as exc:
            raise AuditWorkspaceError("snapshot destination parent binding changed") from exc
        if parent_current != opened_destination.parent_identity:
            _error("snapshot destination parent binding changed")
        for boundary in {
            location.root,
            location.git_dir,
            location.common_git_dir,
        }:
            if _existing_directory_is_within(opened_destination.parent, boundary):
                _error("snapshot destination is inside repository boundaries")
        self._validate_location_bindings(location)
        root_identity = opened_destination.root_identity
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or not stat.S_ISDIR(root_relative.st_mode)
            or _path_identity(root_opened) != root_identity
            or _path_identity(root_relative) != root_identity
        ):
            _error("snapshot destination binding changed")
        try:
            root_current = _capture_safe_directory(
                opened_destination.root,
                "snapshot destination",
                private=True,
            )
        except AuditWorkspaceError as exc:
            raise AuditWorkspaceError("snapshot destination binding changed") from exc
        if root_current != root_identity:
            _error("snapshot destination binding changed")
        try:
            parent_final = _capture_safe_directory(
                opened_destination.parent,
                "snapshot destination parent",
                private=True,
            )
        except AuditWorkspaceError as exc:
            raise AuditWorkspaceError("snapshot destination parent binding changed") from exc
        if parent_final != opened_destination.parent_identity:
            _error("snapshot destination parent binding changed")

    def _open_snapshot_subdirectory(
        self,
        parent_descriptor: int,
        component: str,
        *,
        create: bool = True,
    ) -> int:
        created = False
        try:
            before = os.lstat(component, dir_fd=parent_descriptor)
        except FileNotFoundError as exc:
            if not create:
                raise AuditWorkspaceError(
                    "snapshot manifest parent directory is unavailable"
                ) from exc
            try:
                os.mkdir(
                    component,
                    _PRIVATE_DIRECTORY_MODE,
                    dir_fd=parent_descriptor,
                )
                created = True
                before = os.lstat(component, dir_fd=parent_descriptor)
            except FileExistsError as exc:
                raise AuditWorkspaceError(
                    "snapshot parent directory appeared while it was created"
                ) from exc
            except OSError as exc:
                raise AuditWorkspaceError("snapshot parent directory could not be created") from exc
            except (TypeError, ValueError, NotImplementedError) as exc:
                raise AuditWorkspaceError(
                    "snapshot parent directory cannot be created safely"
                ) from exc
        except OSError as exc:
            raise AuditWorkspaceError("snapshot parent directory could not be inspected") from exc
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            _error("snapshot parent directory is unsafe")
        directory_flags = _required_posix_open_flags(
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        try:
            descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise AuditWorkspaceError(
                "snapshot parent directory could not be opened safely"
            ) from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError("snapshot parent directory cannot be opened safely") from exc
        try:
            if created:
                os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
            opened = os.fstat(descriptor)
            after = os.lstat(component, dir_fd=parent_descriptor)
            opened_identity = _path_identity(opened)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(after.st_mode)
                or opened_identity.owner != os.geteuid()
                or opened_identity.permissions != _PRIVATE_DIRECTORY_MODE
                or not _same_identity(_path_identity(before), opened_identity)
                or _path_identity(after) != opened_identity
            ):
                _error("snapshot parent directory binding changed")
            return descriptor
        except AuditWorkspaceError:
            with suppress(OSError):
                os.close(descriptor)
            raise
        except (OSError, TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(descriptor)
            raise AuditWorkspaceError(
                "snapshot parent directory binding could not be validated"
            ) from exc
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise

    def _prepare_parent_directories(self, root_descriptor: int, path: str) -> int:
        try:
            current_descriptor = os.dup(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot root descriptor could not be duplicated") from exc
        try:
            for component in path.split("/")[:-1]:
                next_descriptor = self._open_snapshot_subdirectory(
                    current_descriptor,
                    component,
                )
                os.close(current_descriptor)
                current_descriptor = next_descriptor
            return current_descriptor
        except BaseException:
            with suppress(OSError):
                os.close(current_descriptor)
            raise

    def _open_manifest_directory(
        self,
        root_descriptor: int,
        path: str,
    ) -> int:
        try:
            current_descriptor = os.dup(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot root descriptor could not be duplicated") from exc
        try:
            components = () if not path else tuple(path.split("/"))
            for component in components:
                next_descriptor = self._open_snapshot_subdirectory(
                    current_descriptor,
                    component,
                    create=False,
                )
                os.close(current_descriptor)
                current_descriptor = next_descriptor
            return current_descriptor
        except BaseException:
            with suppress(OSError):
                os.close(current_descriptor)
            raise

    def _open_manifest_parent_directory(
        self,
        root_descriptor: int,
        path: str,
    ) -> int:
        components = path.split("/")
        return self._open_manifest_directory(
            root_descriptor,
            "/".join(components[:-1]),
        )

    def _write_small_regular_file(
        self,
        root_descriptor: int,
        entry: _TreeEntry,
        data: bytes,
    ) -> SnapshotManifestEntry:
        mode = _PRIVATE_EXECUTABLE_MODE if entry.mode == "100755" else _PRIVATE_FILE_MODE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        parent_descriptor = self._prepare_parent_directories(root_descriptor, entry.path)
        name = entry.path.rsplit("/", 1)[-1]
        try:
            descriptor = os.open(
                name,
                flags,
                mode,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("materialized snapshot file could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError(
                "materialized snapshot file cannot be created safely"
            ) from exc
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _error("materialized snapshot file write made no progress")
                view = view[written:]
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot file could not be written") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)
        return SnapshotManifestEntry(
            path=entry.path,
            object_id=entry.object_id,
            git_mode=entry.mode,
            mode=mode,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def _write_streamed_regular_file(
        self,
        root_descriptor: int,
        entry: _TreeEntry,
        reader: _BoundedPipeReader,
    ) -> SnapshotManifestEntry:
        entry_size = _blob_size(entry)
        mode = _PRIVATE_EXECUTABLE_MODE if entry.mode == "100755" else _PRIVATE_FILE_MODE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        parent_descriptor = self._prepare_parent_directories(root_descriptor, entry.path)
        name = entry.path.rsplit("/", 1)[-1]
        try:
            descriptor = os.open(
                name,
                flags,
                mode,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("materialized snapshot file could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError(
                "materialized snapshot file cannot be created safely"
            ) from exc
        digest = hashlib.sha256()
        git_digest = _git_blob_digest(entry.object_id, entry_size)
        try:
            os.fchmod(descriptor, mode)
            reader.copy_exact(entry_size, descriptor, (digest, git_digest))
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot file could not be written") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)
        if git_digest.hexdigest() != entry.object_id:
            _error("Git blob content does not match its object ID")
        return SnapshotManifestEntry(
            path=entry.path,
            object_id=entry.object_id,
            git_mode=entry.mode,
            mode=mode,
            size=entry_size,
            sha256=digest.hexdigest(),
        )

    def _write_symlink(
        self,
        root_descriptor: int,
        entry: _TreeEntry,
        data: bytes,
    ) -> SnapshotManifestEntry:
        target = _decode_symlink_target(data, entry.path)
        parent_descriptor = self._prepare_parent_directories(root_descriptor, entry.path)
        name = entry.path.rsplit("/", 1)[-1]
        try:
            os.symlink(target, name, dir_fd=parent_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot symlink could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError(
                "materialized snapshot symlink cannot be created safely"
            ) from exc
        finally:
            with suppress(OSError):
                os.close(parent_descriptor)
        return SnapshotManifestEntry(
            path=entry.path,
            object_id=entry.object_id,
            git_mode=entry.mode,
            mode=0o777,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            symlink_target=target,
        )

    def _read_batch_header(self, reader: _BoundedPipeReader, entry: _TreeEntry) -> None:
        line = reader.read_until(b"\n", _BATCH_HEADER_BYTES)
        try:
            object_id_bytes, object_type, size_bytes = line[:-1].split()
            object_id = object_id_bytes.decode("ascii", errors="strict")
            size = int(size_bytes.decode("ascii", errors="strict"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditWorkspaceError("Git blob stream returned an invalid header") from exc
        if (
            object_id != entry.object_id
            or object_type != b"blob"
            or entry.size is None
            or size != entry.size
        ):
            _error("Git blob stream returned an unexpected object")

    def _materialize_blobs(
        self,
        location: RepositoryLocation,
        entries: tuple[_TreeEntry, ...],
        root_descriptor: int,
        exclusions: tuple[str, ...],
        limits: AuditLimits,
        deadline: float,
    ) -> tuple[tuple[SnapshotManifestEntry, ...], tuple[SkippedContent, ...]]:
        command_deadline = _bounded_deadline(deadline, limits.git_command_seconds)
        manifest: list[SnapshotManifestEntry] = []
        skipped = [
            SkippedContent(path=entry.path, reason="gitlink")
            for entry in entries
            if entry.mode == "160000"
        ]
        skipped.extend(
            SkippedContent(path=path, reason="excluded by audit configuration")
            for path in exclusions
        )
        process = self._spawn(
            location.root,
            ("cat-file", "--batch"),
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if process.stdin is None or process.stdout is None:
            _stop_process(process)
            _error("Git blob process pipes are unavailable")
        requested = tuple(
            entry
            for entry in entries
            if entry.mode != "160000" and not _is_excluded(entry.path, exclusions)
        )
        header_allowance = min(
            limits.git_metadata_bytes,
            max(1, len(requested)) * _BATCH_HEADER_BYTES,
        )
        reader = _BoundedPipeReader(
            process.stdout,
            deadline=command_deadline,
            byte_limit=limits.snapshot_blob_bytes + header_allowance + len(requested),
        )
        try:
            for entry in requested:
                _remaining(command_deadline)
                try:
                    process.stdin.write(f"{entry.object_id}\n".encode("ascii"))
                    process.stdin.flush()
                except (BrokenPipeError, OSError) as exc:
                    raise AuditWorkspaceError("Git blob request could not be written") from exc
                self._read_batch_header(reader, entry)
                entry_size = _blob_size(entry)
                if entry.mode == "120000":
                    if entry_size > _SYMLINK_TARGET_BYTES:
                        _error(f"snapshot symlink target for {entry.path} is too large")
                    data = reader.read_exact(entry_size)
                    if reader.read_exact(1) != b"\n":
                        _error("Git blob stream returned an invalid object terminator")
                    _verify_small_git_blob(entry, data)
                    manifest.append(self._write_symlink(root_descriptor, entry, data))
                    continue
                if entry_size < _LFS_POINTER_MAX_BYTES:
                    data = reader.read_exact(entry_size)
                    if reader.read_exact(1) != b"\n":
                        _error("Git blob stream returned an invalid object terminator")
                    _verify_small_git_blob(entry, data)
                    if _looks_like_lfs_pointer(data):
                        skipped.append(SkippedContent(path=entry.path, reason="git-lfs-pointer"))
                        continue
                    manifest.append(self._write_small_regular_file(root_descriptor, entry, data))
                    continue
                manifest.append(self._write_streamed_regular_file(root_descriptor, entry, reader))
                if reader.read_exact(1) != b"\n":
                    _error("Git blob stream returned an invalid object terminator")
            try:
                process.stdin.close()
                reader.ensure_eof()
                return_code = wait_process_exit(process, deadline=command_deadline)
            except (AuditProcessError, subprocess.TimeoutExpired):
                _stop_process(process)
                _error("Git blob stream exceeded its deadline")
            if return_code != 0:
                _error("Git blob stream failed")
            return tuple(manifest), tuple(sorted(skipped, key=lambda item: item.path))
        finally:
            reader.close()
            with suppress(OSError):
                process.stdin.close()
            with suppress(OSError):
                process.stdout.close()
            if process.returncode is None:
                _stop_process(process)

    def _cleanup_opened_snapshot(
        self,
        opened_destination: _OpenedSnapshotDestination,
    ) -> None:
        try:
            root_opened = os.fstat(opened_destination.root_descriptor)
        except OSError:
            return
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or root_opened.st_uid != os.geteuid()
            or not _same_identity(
                _path_identity(root_opened),
                opened_destination.root_identity,
            )
        ):
            return
        with suppress(OSError):
            os.fchmod(
                opened_destination.root_descriptor,
                _PRIVATE_DIRECTORY_MODE,
            )

    def materialize(
        self,
        inspection: RepositoryInspection,
        destination: Path,
        *,
        exclude_paths: tuple[str, ...],
        limits: AuditLimits,
        deadline: float,
    ) -> MaterializedSnapshot:
        if not isinstance(inspection, RepositoryInspection):
            _error("repository inspection is invalid")
        if not isinstance(destination, Path):
            _error("snapshot destination must be a pathlib.Path")
        _validate_limits(limits)
        exclusions = _validate_exclusions(exclude_paths)
        materialization_deadline = _bounded_deadline(deadline, limits.materialization_seconds)
        location = inspection.location
        self._revalidate(
            location,
            deadline=materialization_deadline,
            command_seconds=limits.git_command_seconds,
        )
        entries, blob_bytes = self._tree_entries(
            inspection,
            limits=limits,
            deadline=materialization_deadline,
            command_seconds=limits.git_command_seconds,
        )
        self._validate_location_bindings(location)
        if (
            self._resolve_head(
                location.root,
                deadline=materialization_deadline,
                command_seconds=limits.git_command_seconds,
            )
            != location.head
        ):
            _error("committed HEAD changed during tree enumeration")

        opened_destination = self._prepare_destination(location, destination)
        try:
            manifest, skipped = self._materialize_blobs(
                location,
                entries,
                opened_destination.root_descriptor,
                exclusions,
                limits,
                materialization_deadline,
            )
            self._validate_opened_destination(location, opened_destination)
            self._validate_location_bindings(location)
            self._reject_external_object_sources(
                location,
                deadline=materialization_deadline,
                command_seconds=limits.git_command_seconds,
            )
            final_head = self._resolve_head(
                location.root,
                deadline=materialization_deadline,
                command_seconds=limits.git_command_seconds,
            )
            if final_head != location.head:
                _error("committed HEAD changed during snapshot materialization")
            snapshot = MaterializedSnapshot(
                root=opened_destination.root,
                repository_id=location.repository_id,
                head=location.head,
                manifest=manifest,
                skipped_content=skipped,
                source_entry_count=len(entries),
                source_blob_bytes=blob_bytes,
                excluded_paths=exclusions,
                _root_identity=opened_destination.root_identity,
            )
            self._validate_snapshot_fd(
                snapshot,
                opened_destination.root_descriptor,
                deadline=materialization_deadline,
            )
            self._validate_opened_destination(location, opened_destination)
            return snapshot
        except BaseException:
            self._cleanup_opened_snapshot(opened_destination)
            raise
        finally:
            with suppress(OSError):
                os.close(opened_destination.root_descriptor)
            with suppress(OSError):
                os.close(opened_destination.parent_descriptor)

    def _hash_regular_file_at(
        self,
        parent_descriptor: int,
        name: str,
        expected: os.stat_result,
        *,
        deadline: float | None = None,
    ) -> str:
        _check_optional_deadline(deadline)
        flags = _required_posix_open_flags("O_NOFOLLOW", "O_CLOEXEC")
        try:
            descriptor = os.open(
                name,
                flags,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file could not be opened") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError("snapshot manifest file cannot be opened safely") from exc
        digest = hashlib.sha256()
        try:
            _check_optional_deadline(deadline)
            opened = os.fstat(descriptor)
            _check_optional_deadline(deadline)
            if (
                opened.st_dev != expected.st_dev
                or opened.st_ino != expected.st_ino
                or opened.st_size != expected.st_size
            ):
                _error("snapshot manifest file binding changed")
            while True:
                _check_optional_deadline(deadline)
                chunk = os.read(descriptor, _PROCESS_READ_CHUNK)
                _check_optional_deadline(deadline)
                if not chunk:
                    break
                digest.update(chunk)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file could not be read") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
        try:
            _check_optional_deadline(deadline)
            current = os.lstat(name, dir_fd=parent_descriptor)
            _check_optional_deadline(deadline)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file binding changed") from exc
        if (
            current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
            or current.st_size != expected.st_size
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(expected.st_mode)
        ):
            _error("snapshot manifest file binding changed")
        return digest.hexdigest()

    def _validate_snapshot_fd(
        self,
        snapshot: MaterializedSnapshot,
        root_descriptor: int,
        *,
        deadline: float | None = None,
    ) -> None:
        _check_optional_deadline(deadline)
        try:
            root_opened = os.fstat(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot root could not be inspected") from exc
        _check_optional_deadline(deadline)
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or _path_identity(root_opened) != snapshot._root_identity
        ):
            _error("materialized snapshot root binding changed")

        expected_entries: dict[str, SnapshotManifestEntry] = {}
        expected_directories: set[str] = set()
        for entry in snapshot.manifest:
            _check_optional_deadline(deadline)
            if not isinstance(entry, SnapshotManifestEntry):
                _error("snapshot manifest contains an invalid entry")
            path = _validate_relative_path_text(entry.path, "snapshot manifest path")
            if path in expected_entries:
                _error("snapshot manifest contains a duplicate path")
            expected_entries[path] = entry
            components = path.split("/")
            expected_directories.update(
                "/".join(components[:index]) for index in range(1, len(components))
            )
            _check_optional_deadline(deadline)

        actual_paths: set[str] = set()
        pending = [""]
        while pending:
            _check_optional_deadline(deadline)
            relative_directory = pending.pop()
            directory_descriptor = self._open_manifest_directory(
                root_descriptor,
                relative_directory,
            )
            try:
                _check_optional_deadline(deadline)
                directory_result = os.fstat(directory_descriptor)
                _check_optional_deadline(deadline)
                try:
                    with os.scandir(directory_descriptor) as iterator:
                        children = list(iterator)
                    _check_optional_deadline(deadline)
                except OSError as exc:
                    raise AuditWorkspaceError(
                        "snapshot manifest directory could not be read"
                    ) from exc
                if relative_directory:
                    if (
                        not stat.S_ISDIR(directory_result.st_mode)
                        or directory_result.st_uid != os.geteuid()
                        or stat.S_IMODE(directory_result.st_mode) != _PRIVATE_DIRECTORY_MODE
                    ):
                        _error("snapshot manifest directory validation failed")
                    actual_paths.add(relative_directory)
                elif _path_identity(directory_result) != snapshot._root_identity:
                    _error("materialized snapshot root binding changed")
                for child in children:
                    _check_optional_deadline(deadline)
                    relative = (
                        child.name
                        if not relative_directory
                        else f"{relative_directory}/{child.name}"
                    )
                    _validate_relative_path_text(relative, "snapshot manifest path")
                    try:
                        result = child.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise AuditWorkspaceError(
                            "snapshot manifest entry could not be inspected"
                        ) from exc
                    _check_optional_deadline(deadline)
                    actual_paths.add(relative)
                    if stat.S_ISDIR(result.st_mode):
                        pending.append(relative)
            finally:
                with suppress(OSError):
                    os.close(directory_descriptor)

        _check_optional_deadline(deadline)
        expected_paths = set(expected_entries) | expected_directories
        if actual_paths != expected_paths:
            _error("snapshot manifest paths do not match materialized content")

        for path, entry in expected_entries.items():
            _check_optional_deadline(deadline)
            parent_descriptor = self._open_manifest_parent_directory(
                root_descriptor,
                path,
            )
            name = path.rsplit("/", 1)[-1]
            try:
                try:
                    result = os.lstat(name, dir_fd=parent_descriptor)
                except OSError as exc:
                    raise AuditWorkspaceError("snapshot manifest entry is unavailable") from exc
                _check_optional_deadline(deadline)
                if result.st_uid != os.geteuid():
                    _error("snapshot manifest entry has an unexpected owner")
                if entry.is_symlink:
                    if not stat.S_ISLNK(result.st_mode):
                        _error("snapshot manifest symlink type does not match")
                    try:
                        _check_optional_deadline(deadline)
                        target = os.readlink(name, dir_fd=parent_descriptor)
                        _check_optional_deadline(deadline)
                    except OSError as exc:
                        raise AuditWorkspaceError(
                            "snapshot manifest symlink could not be read"
                        ) from exc
                    if target != entry.symlink_target:
                        _error("snapshot manifest symlink target does not match")
                    _decode_symlink_target(target.encode("utf-8"), path)
                    try:
                        _check_optional_deadline(deadline)
                        current = os.lstat(name, dir_fd=parent_descriptor)
                        _check_optional_deadline(deadline)
                    except OSError as exc:
                        raise AuditWorkspaceError(
                            "snapshot manifest symlink binding changed"
                        ) from exc
                    if (
                        current.st_dev != result.st_dev
                        or current.st_ino != result.st_ino
                        or not stat.S_ISLNK(current.st_mode)
                    ):
                        _error("snapshot manifest symlink binding changed")
                    if (
                        entry.size != len(target.encode("utf-8"))
                        or hashlib.sha256(target.encode("utf-8")).hexdigest() != entry.sha256
                    ):
                        _error("snapshot manifest symlink digest does not match")
                    continue
                if (
                    not stat.S_ISREG(result.st_mode)
                    or result.st_nlink != 1
                    or stat.S_IMODE(result.st_mode) != entry.mode
                    or result.st_size != entry.size
                ):
                    _error("snapshot manifest regular file metadata does not match")
                if (
                    self._hash_regular_file_at(
                        parent_descriptor,
                        name,
                        result,
                        deadline=deadline,
                    )
                    != entry.sha256
                ):
                    _error("snapshot manifest regular file digest does not match")
                _check_optional_deadline(deadline)
            finally:
                with suppress(OSError):
                    os.close(parent_descriptor)

        _check_optional_deadline(deadline)
        try:
            root_final = os.fstat(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot root could not be inspected") from exc
        _check_optional_deadline(deadline)
        if (
            not stat.S_ISDIR(root_final.st_mode)
            or _path_identity(root_final) != snapshot._root_identity
        ):
            _error("materialized snapshot root binding changed")

    def validate_snapshot(
        self,
        snapshot: MaterializedSnapshot,
        *,
        deadline: float | None = None,
    ) -> None:
        if not isinstance(snapshot, MaterializedSnapshot):
            _error("materialized snapshot is invalid")
        validation_deadline = None if deadline is None else _validate_deadline(deadline)
        _check_optional_deadline(validation_deadline)
        _validate_identity(
            snapshot.root,
            snapshot._root_identity,
            "materialized snapshot root",
            private=True,
        )
        _check_optional_deadline(validation_deadline)
        directory_flags = _required_posix_open_flags(
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        try:
            root_descriptor = os.open(snapshot.root, directory_flags)
        except OSError as exc:
            raise AuditWorkspaceError(
                "materialized snapshot root could not be opened safely"
            ) from exc
        try:
            _check_optional_deadline(validation_deadline)
            opened = os.fstat(root_descriptor)
            _check_optional_deadline(validation_deadline)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _path_identity(opened) != snapshot._root_identity
            ):
                _error("materialized snapshot root binding changed")
            self._validate_snapshot_fd(
                snapshot,
                root_descriptor,
                deadline=validation_deadline,
            )
            _check_optional_deadline(validation_deadline)
            _validate_identity(
                snapshot.root,
                snapshot._root_identity,
                "materialized snapshot root",
                private=True,
            )
            _check_optional_deadline(validation_deadline)
        finally:
            with suppress(OSError):
                os.close(root_descriptor)
