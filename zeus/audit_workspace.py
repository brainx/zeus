from __future__ import annotations

import hashlib
import math
import os
import posixpath
import re
import selectors
import shutil
import signal
import stat
import subprocess  # nosec B404
import time
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, NoReturn, Protocol

from zeus.audit_models import HARD_LIMITS, AuditLimits, SkippedContent

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_EXECUTABLE_MODE = 0o700
_DISCOVERY_OUTPUT_BYTES = 64 * 1024
_BATCH_HEADER_BYTES = 256
_LFS_POINTER_BYTES = 8 * 1024
_PROCESS_READ_CHUNK = 64 * 1024
_OBJECT_ID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:\Z")
_LFS_VERSION = b"version https://git-lfs.github.com/spec/v1"
_LFS_OID_RE = re.compile(rb"oid sha256:[0-9a-f]{64}\Z")
_LFS_SIZE_RE = re.compile(rb"size [0-9]+\Z")


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
class _TreeEntry:
    mode: str
    object_type: str
    object_id: str
    size: int | None
    path: str


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


def _git_environment() -> dict[str, str]:
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
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PAGER": "cat",
    }


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=1)


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
            return_code = process.wait(timeout=_remaining(deadline))
        except subprocess.TimeoutExpired:
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
        if process.poll() is None:
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
        or _WINDOWS_DRIVE_RE.fullmatch(components[0]) is not None
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


def _parse_status(data: bytes) -> RepositoryChanges:
    if not data:
        return RepositoryChanges(dirty=False, staged=False, untracked=False)
    if not data.endswith(b"\0"):
        _error("Git status metadata is not NUL terminated")
    records = data[:-1].split(b"\0")
    dirty = False
    staged = False
    untracked = False
    skip_rename_source = False
    for record in records:
        if skip_rename_source:
            skip_rename_source = False
            continue
        if record.startswith((b"1 ", b"2 ")):
            if len(record) < 5:
                _error("Git status metadata has an invalid tracked record")
            staged = staged or record[2:3] != b"."
            dirty = dirty or record[3:4] != b"."
            skip_rename_source = record.startswith(b"2 ")
        elif record.startswith(b"u "):
            if len(record) < 5:
                _error("Git status metadata has an invalid unmerged record")
            staged = True
            dirty = True
        elif record.startswith(b"? "):
            untracked = True
        elif record.startswith(b"! "):
            continue
        else:
            _error("Git status metadata contains an unsupported record")
    if skip_rename_source:
        _error("Git status metadata has an incomplete rename record")
    return RepositoryChanges(dirty=dirty, staged=staged, untracked=untracked)


def _looks_like_lfs_pointer(data: bytes) -> bool:
    if len(data) > _LFS_POINTER_BYTES:
        return False
    lines = data.rstrip(b"\n").splitlines()
    if not lines or lines[0].rstrip(b"\r") != _LFS_VERSION:
        return False
    normalized = [line.rstrip(b"\r") for line in lines[1:]]
    return (
        sum(_LFS_OID_RE.fullmatch(line) is not None for line in normalized) == 1
        and sum(_LFS_SIZE_RE.fullmatch(line) is not None for line in normalized) == 1
        and all(
            line.startswith(b"ext-")
            or _LFS_OID_RE.fullmatch(line) is not None
            or _LFS_SIZE_RE.fullmatch(line) is not None
            for line in normalized
        )
    )


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
    if len(data) > _LFS_POINTER_BYTES:
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
        or _WINDOWS_DRIVE_RE.fullmatch(target.split("/", 1)[0]) is not None
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

    def _argv(self, cwd: Path, arguments: tuple[str, ...]) -> tuple[str, ...]:
        return (
            str(self._git_executable),
            *GIT_HARDENING_ARGUMENTS,
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
    ) -> subprocess.Popen[bytes]:
        self._validate_git_executable()
        try:
            return subprocess.Popen(  # nosec B603
                self._argv(cwd, arguments),
                cwd=cwd,
                env=_git_environment(),
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
        max_output_bytes: int,
        description: str,
    ) -> bytes:
        process = self._spawn(
            cwd,
            arguments,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        return _collect_bounded_process(
            process,
            deadline=deadline,
            max_output_bytes=max_output_bytes,
            description=description,
        )

    def _resolve_path(
        self,
        cwd: Path,
        argument: str,
        *,
        deadline: float,
        description: str,
    ) -> Path:
        output = self._run(
            cwd,
            ("rev-parse", "--path-format=absolute", argument),
            deadline=deadline,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description=description,
        )
        value = _single_line(output, description)
        path = Path(value)
        if not path.is_absolute():
            _error(f"{description} is not absolute")
        return _absolute_lexical_path(path, description)

    def _resolve_head(self, cwd: Path, *, deadline: float) -> str:
        output = self._run(
            cwd,
            ("rev-parse", "--verify", "HEAD^{commit}"),
            deadline=deadline,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description="committed HEAD discovery",
        )
        return _single_oid(output, "committed HEAD")

    def discover(self, cwd: Path, *, deadline: float) -> RepositoryLocation:
        command_deadline = _bounded_deadline(deadline, HARD_LIMITS.git_command_seconds)
        safe_cwd = _absolute_lexical_path(cwd, "repository discovery directory")
        _capture_safe_directory(safe_cwd, "repository discovery directory")
        root = self._resolve_path(
            safe_cwd,
            "--show-toplevel",
            deadline=command_deadline,
            description="repository root discovery",
        )
        git_dir = self._resolve_path(
            safe_cwd,
            "--absolute-git-dir",
            deadline=command_deadline,
            description="Git directory discovery",
        )
        common_git_dir = self._resolve_path(
            safe_cwd,
            "--git-common-dir",
            deadline=command_deadline,
            description="common Git directory discovery",
        )
        root_identity = _capture_safe_directory(root, "repository root")
        git_dir_identity = _capture_safe_directory(git_dir, "repository Git directory")
        common_git_dir_identity = _capture_safe_directory(
            common_git_dir, "repository common Git directory"
        )
        git_marker_identity = _capture_repository_marker(root)
        _validate_repository_metadata(git_dir, common_git_dir)
        head = self._resolve_head(root, deadline=command_deadline)
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

    def revalidate(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
    ) -> RepositoryLocation:
        if not isinstance(location, RepositoryLocation):
            _error("repository location is invalid")
        current = self.discover(location.root, deadline=deadline)
        if current != location:
            _error("repository binding or committed HEAD changed")
        return current

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
        command_deadline = _bounded_deadline(deadline, HARD_LIMITS.git_command_seconds)
        self.revalidate(location, deadline=command_deadline)
        self._reject_external_object_sources(location, deadline=command_deadline)
        status = self._run(
            location.root,
            (
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=normal",
                "--ignore-submodules=all",
            ),
            deadline=command_deadline,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git status metadata",
        )
        changes = _parse_status(status)
        self._validate_location_bindings(location)
        if self._resolve_head(location.root, deadline=command_deadline) != location.head:
            _error("committed HEAD changed during repository inspection")
        return RepositoryInspection(location=location, changes=changes)

    def _tree_entries(
        self,
        inspection: RepositoryInspection,
        *,
        limits: AuditLimits,
        deadline: float,
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
            max_output_bytes=limits.git_metadata_bytes,
            description="Git tree metadata",
        )
        return _parse_tree(output, limits)

    def _prepare_destination(
        self,
        destination: Path,
    ) -> tuple[Path, _PathIdentity]:
        safe_destination = Path(os.path.abspath(destination))
        _strict_utf8_path_text(str(safe_destination), "snapshot destination")
        parent = _absolute_lexical_path(safe_destination.parent, "snapshot destination parent")
        _capture_safe_directory(parent, "snapshot destination parent", private=True)
        try:
            os.mkdir(safe_destination, _PRIVATE_DIRECTORY_MODE)
        except FileExistsError as exc:
            raise AuditWorkspaceError("snapshot destination already exists") from exc
        except OSError as exc:
            raise AuditWorkspaceError("snapshot destination could not be created") from exc
        try:
            os.chmod(safe_destination, _PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
            identity = _capture_safe_directory(
                safe_destination,
                "snapshot destination",
                private=True,
            )
        except BaseException:
            with suppress(OSError):
                safe_destination.rmdir()
            raise
        return safe_destination, identity

    def _prepare_parent_directories(self, root: Path, path: str) -> Path:
        current = root
        for component in path.split("/")[:-1]:
            current = current / component
            try:
                os.mkdir(current, _PRIVATE_DIRECTORY_MODE)
                os.chmod(current, _PRIVATE_DIRECTORY_MODE, follow_symlinks=False)
            except FileExistsError:
                pass
            except OSError as exc:
                raise AuditWorkspaceError("snapshot parent directory could not be created") from exc
            _capture_safe_directory(
                current,
                "snapshot parent directory",
                private=True,
            )
        return current

    def _write_small_regular_file(
        self,
        root: Path,
        entry: _TreeEntry,
        data: bytes,
    ) -> SnapshotManifestEntry:
        parent = self._prepare_parent_directories(root, entry.path)
        mode = _PRIVATE_EXECUTABLE_MODE if entry.mode == "100755" else _PRIVATE_FILE_MODE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        path = parent / entry.path.rsplit("/", 1)[-1]
        try:
            descriptor = os.open(path, flags, mode)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot file could not be created") from exc
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
        root: Path,
        entry: _TreeEntry,
        reader: _BoundedPipeReader,
    ) -> SnapshotManifestEntry:
        entry_size = _blob_size(entry)
        parent = self._prepare_parent_directories(root, entry.path)
        mode = _PRIVATE_EXECUTABLE_MODE if entry.mode == "100755" else _PRIVATE_FILE_MODE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        path = parent / entry.path.rsplit("/", 1)[-1]
        try:
            descriptor = os.open(path, flags, mode)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot file could not be created") from exc
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
        root: Path,
        entry: _TreeEntry,
        data: bytes,
    ) -> SnapshotManifestEntry:
        target = _decode_symlink_target(data, entry.path)
        parent = self._prepare_parent_directories(root, entry.path)
        path = parent / entry.path.rsplit("/", 1)[-1]
        try:
            os.symlink(target, path)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot symlink could not be created") from exc
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
        root: Path,
        exclusions: tuple[str, ...],
        limits: AuditLimits,
        deadline: float,
    ) -> tuple[tuple[SnapshotManifestEntry, ...], tuple[SkippedContent, ...]]:
        manifest: list[SnapshotManifestEntry] = []
        skipped = [
            SkippedContent(path=entry.path, reason="gitlink")
            for entry in entries
            if entry.mode == "160000"
        ]
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
            deadline=deadline,
            byte_limit=limits.snapshot_blob_bytes + header_allowance + len(requested),
        )
        try:
            for entry in requested:
                _remaining(deadline)
                try:
                    process.stdin.write(f"{entry.object_id}\n".encode("ascii"))
                    process.stdin.flush()
                except (BrokenPipeError, OSError) as exc:
                    raise AuditWorkspaceError("Git blob request could not be written") from exc
                self._read_batch_header(reader, entry)
                entry_size = _blob_size(entry)
                if entry.mode == "120000" or entry_size <= _LFS_POINTER_BYTES:
                    data = reader.read_exact(entry_size)
                    if reader.read_exact(1) != b"\n":
                        _error("Git blob stream returned an invalid object terminator")
                    _verify_small_git_blob(entry, data)
                    if entry.mode != "120000" and _looks_like_lfs_pointer(data):
                        skipped.append(SkippedContent(path=entry.path, reason="git-lfs-pointer"))
                        continue
                    if entry.mode == "120000":
                        manifest.append(self._write_symlink(root, entry, data))
                    else:
                        manifest.append(self._write_small_regular_file(root, entry, data))
                    continue
                manifest.append(self._write_streamed_regular_file(root, entry, reader))
                if reader.read_exact(1) != b"\n":
                    _error("Git blob stream returned an invalid object terminator")
            try:
                process.stdin.close()
                reader.ensure_eof()
                return_code = process.wait(timeout=_remaining(deadline))
            except subprocess.TimeoutExpired:
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
            if process.poll() is None:
                _stop_process(process)

    def _cleanup_owned_snapshot(self, root: Path, identity: _PathIdentity) -> None:
        try:
            current = _capture_safe_directory(root, "snapshot cleanup directory", private=True)
        except AuditWorkspaceError:
            return
        if current != identity:
            return
        if not shutil.rmtree.avoids_symlink_attacks:
            return
        with suppress(OSError):
            shutil.rmtree(root)

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
        self.revalidate(location, deadline=materialization_deadline)
        self._reject_external_object_sources(location, deadline=materialization_deadline)
        entries, blob_bytes = self._tree_entries(
            inspection,
            limits=limits,
            deadline=materialization_deadline,
        )
        self._validate_location_bindings(location)
        if self._resolve_head(location.root, deadline=materialization_deadline) != location.head:
            _error("committed HEAD changed during tree enumeration")

        root, root_identity = self._prepare_destination(destination)
        try:
            manifest, skipped = self._materialize_blobs(
                location,
                entries,
                root,
                exclusions,
                limits,
                materialization_deadline,
            )
            self._validate_location_bindings(location)
            self._reject_external_object_sources(
                location,
                deadline=materialization_deadline,
            )
            final_head = self._resolve_head(
                location.root,
                deadline=materialization_deadline,
            )
            if final_head != location.head:
                _error("committed HEAD changed during snapshot materialization")
            snapshot = MaterializedSnapshot(
                root=root,
                repository_id=location.repository_id,
                head=location.head,
                manifest=manifest,
                skipped_content=skipped,
                source_entry_count=len(entries),
                source_blob_bytes=blob_bytes,
                excluded_paths=exclusions,
                _root_identity=root_identity,
            )
            self.validate_snapshot(snapshot)
            return snapshot
        except BaseException:
            self._cleanup_owned_snapshot(root, root_identity)
            raise

    def _hash_regular_file(
        self,
        path: Path,
        expected: os.stat_result,
    ) -> str:
        flags = os.O_RDONLY
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file could not be opened") from exc
        digest = hashlib.sha256()
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != expected.st_dev
                or opened.st_ino != expected.st_ino
                or opened.st_size != expected.st_size
            ):
                _error("snapshot manifest file binding changed")
            while True:
                chunk = os.read(descriptor, _PROCESS_READ_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file could not be read") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
        try:
            current = path.lstat()
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

    def validate_snapshot(self, snapshot: MaterializedSnapshot) -> None:
        if not isinstance(snapshot, MaterializedSnapshot):
            _error("materialized snapshot is invalid")
        _validate_identity(
            snapshot.root,
            snapshot._root_identity,
            "materialized snapshot root",
            private=True,
        )
        expected_entries: dict[str, SnapshotManifestEntry] = {}
        expected_directories: set[str] = set()
        for entry in snapshot.manifest:
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

        actual_paths: set[str] = set()
        pending = [snapshot.root]
        while pending:
            directory = pending.pop()
            relative_directory = (
                ""
                if directory == snapshot.root
                else directory.relative_to(snapshot.root).as_posix()
            )
            if relative_directory:
                result = directory.lstat()
                if (
                    not stat.S_ISDIR(result.st_mode)
                    or result.st_uid != os.geteuid()
                    or stat.S_IMODE(result.st_mode) != _PRIVATE_DIRECTORY_MODE
                ):
                    _error("snapshot manifest directory validation failed")
                actual_paths.add(relative_directory)
            try:
                children = list(os.scandir(directory))
            except OSError as exc:
                raise AuditWorkspaceError("snapshot manifest directory could not be read") from exc
            for child in children:
                relative = (
                    child.name if not relative_directory else f"{relative_directory}/{child.name}"
                )
                _validate_relative_path_text(relative, "snapshot manifest path")
                result = child.stat(follow_symlinks=False)
                actual_paths.add(relative)
                if stat.S_ISDIR(result.st_mode):
                    pending.append(Path(child.path))

        expected_paths = set(expected_entries) | expected_directories
        if actual_paths != expected_paths:
            _error("snapshot manifest paths do not match materialized content")

        for path, entry in expected_entries.items():
            materialized = snapshot.root / path
            try:
                result = materialized.lstat()
            except OSError as exc:
                raise AuditWorkspaceError("snapshot manifest entry is unavailable") from exc
            if result.st_uid != os.geteuid():
                _error("snapshot manifest entry has an unexpected owner")
            if entry.is_symlink:
                if not stat.S_ISLNK(result.st_mode):
                    _error("snapshot manifest symlink type does not match")
                try:
                    target = os.readlink(materialized)
                except OSError as exc:
                    raise AuditWorkspaceError(
                        "snapshot manifest symlink could not be read"
                    ) from exc
                if target != entry.symlink_target:
                    _error("snapshot manifest symlink target does not match")
                _decode_symlink_target(target.encode("utf-8"), path)
                current = materialized.lstat()
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
            if self._hash_regular_file(materialized, result) != entry.sha256:
                _error("snapshot manifest regular file digest does not match")
        _validate_identity(
            snapshot.root,
            snapshot._root_identity,
            "materialized snapshot root",
            private=True,
        )
