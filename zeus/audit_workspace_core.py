from __future__ import annotations

import errno
import hashlib
import math
import os
import posixpath
import re
import selectors
import stat
import subprocess  # nosec B404
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
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
# Keep one-fd-per-component walks inside RLIMIT_NOFILE and bound tree metadata.
_MAX_RELATIVE_PATH_COMPONENTS = 64
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


def _contains_forbidden_path_character(component: str) -> bool:
    return any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in component)


def _validate_relative_path_text(value: str, description: str) -> str:
    _strict_utf8_path_text(value, description)
    if not value or value.startswith("/") or "\\" in value or "\0" in value:
        _error(f"{description} is not a confined relative POSIX path")
    components = value.split("/")
    # Control characters (ESC/CSI/OSC via hostile committed filenames) must not
    # flow into reports or operator terminals; deep nesting exhausts the
    # one-fd-per-component walks, so both are rejected here.
    if (
        len(components) > _MAX_RELATIVE_PATH_COMPONENTS
        or any(_contains_forbidden_path_character(component) for component in components)
        or any(component in {"", ".", ".."} for component in components)
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
