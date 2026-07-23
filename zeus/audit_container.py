"""Fail-closed lifecycle for the single isolated audit command container."""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NoReturn, Protocol, cast

from zeus.audit_config import AuditConfigError, parse_audit_config
from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.audit_workspace import MaterializedSnapshot, SnapshotManifestEntry
from zeus.private_io import ensure_private_directory, inspect_private_directory

AUDIT_UID = 65532
AUDIT_GID = 65532

_PRIVATE_DIRECTORY_MODE = 0o700
_DOCKER_STDOUT_LIMIT = 1024 * 1024
_DOCKER_STDERR_LIMIT = 256 * 1024
_ARCHIVE_OUTPUT_LIMIT = 64 * 1024
_PROCESS_CHUNK = 64 * 1024
_RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_MINIMAL_DOCKER_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
_ENTRYPOINT = ("/bin/sh",)
_COMMAND = ("-c", "trap : TERM INT; sleep infinity & wait")
_TEMP_PATH = "/t" + "mp"
_WORKSPACE_TMPFS = (
    f"rw,nosuid,nodev,size={HARD_LIMITS.workspace_bytes},uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
)
_TEMP_TMPFS = (
    f"rw,noexec,nosuid,nodev,size={HARD_LIMITS.temp_bytes},"
    f"uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
)
_VALIDATION_SCRIPT = r"""
import hashlib, json, os, stat, sys
if len(sys.argv) != 8:
    raise RuntimeError("workspace validation arguments are invalid")
expected_uid = int(sys.argv[1])
expected_gid = int(sys.argv[2])
expected_entry_uid = int(sys.argv[3])
expected_entry_gid = int(sys.argv[4])
expected_groups = json.loads(sys.argv[5])
status_path = sys.argv[6]
probe_root = sys.argv[7]
if (
    not isinstance(expected_groups, list)
    or any(
        isinstance(group, bool) or not isinstance(group, int)
        for group in expected_groups
    )
):
    raise RuntimeError("workspace validation supplementary groups are invalid")
if os.getuid() != expected_uid or os.getgid() != expected_gid:
    raise RuntimeError("workspace validation process identity mismatch")
if os.getgroups() != expected_groups:
    raise RuntimeError("workspace validation supplementary groups mismatch")
expected = {item["path"]: item for item in json.load(sys.stdin)}
expected_dirs = set()
for path in expected:
    parts = path.split("/")
    expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
actual = set()
root = os.stat(".", follow_symlinks=False)
if (
    not stat.S_ISDIR(root.st_mode)
    or stat.S_IMODE(root.st_mode) != 0o700
    or root.st_uid != expected_entry_uid
    or root.st_gid != expected_entry_gid
):
    raise RuntimeError("workspace root metadata mismatch")
with open(status_path, encoding="ascii") as source:
    process_status = dict(
        line.rstrip("\n").split(":\t", 1)
        for line in source
        if ":\t" in line
    )
if process_status.get("NoNewPrivs") != "1":
    raise RuntimeError("no-new-privileges is not effective")
if process_status.get("Seccomp") != "2":
    raise RuntimeError("the Docker seccomp filter is not effective")
if int(process_status.get("CapEff", "-1"), 16) != 0:
    raise RuntimeError("effective Linux capabilities were not fully dropped")
pending = [("", os.open(".", os.O_RDONLY | os.O_DIRECTORY))]
try:
    while pending:
        prefix, descriptor = pending.pop()
        try:
            for name in os.listdir(descriptor):
                path = name if not prefix else prefix + "/" + name
                item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                actual.add(path)
                if stat.S_ISDIR(item.st_mode):
                    if path in expected:
                        raise RuntimeError("workspace entry type mismatch")
                    if (
                        stat.S_IMODE(item.st_mode) != 0o700
                        or item.st_uid != expected_entry_uid
                        or item.st_gid != expected_entry_gid
                    ):
                        raise RuntimeError("workspace directory metadata mismatch")
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    pending.append((path, child))
                    continue
                wanted = expected.get(path)
                if wanted is None:
                    raise RuntimeError("unexpected workspace entry")
                if item.st_uid != expected_entry_uid or item.st_gid != expected_entry_gid:
                    raise RuntimeError("workspace entry ownership mismatch")
                if wanted["type"] == "symlink":
                    if not stat.S_ISLNK(item.st_mode):
                        raise RuntimeError("workspace entry type mismatch")
                    if os.readlink(name, dir_fd=descriptor) != wanted["target"]:
                        raise RuntimeError("workspace symlink target mismatch")
                    continue
                if not stat.S_ISREG(item.st_mode):
                    raise RuntimeError("workspace entry type mismatch")
                if stat.S_IMODE(item.st_mode) != wanted["mode"] or item.st_size != wanted["size"]:
                    raise RuntimeError("workspace file metadata mismatch")
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(opened, 65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                finally:
                    os.close(opened)
                if digest.hexdigest() != wanted["sha256"]:
                    raise RuntimeError("workspace file digest mismatch")
        finally:
            os.close(descriptor)
finally:
    while pending:
        os.close(pending.pop()[1])
if actual != set(expected) | expected_dirs:
    raise RuntimeError("workspace path set mismatch")
probe = os.path.join(probe_root, ".zeus-audit-write-probe")
descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    probe_stat = os.fstat(descriptor)
    if (
        not stat.S_ISREG(probe_stat.st_mode)
        or stat.S_IMODE(probe_stat.st_mode) != 0o600
        or probe_stat.st_uid != expected_entry_uid
        or probe_stat.st_gid != expected_entry_gid
    ):
        raise RuntimeError("workspace write probe metadata mismatch")
    os.write(descriptor, b"probe")
finally:
    os.close(descriptor)
os.unlink(probe)
try:
    os.lstat(probe)
except FileNotFoundError:
    pass
else:
    raise RuntimeError("workspace write probe could not be deleted")
""".strip()


class AuditContainerError(RuntimeError):
    """Raised when an audit container control cannot be proven safe."""


@dataclass(frozen=True)
class DockerCommandResult:
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class PreparedAuditContainer:
    container_id: str
    container_name: str
    profile_name: str
    image_ref: str
    image_id: str
    broker_dir: Path
    state_path: Path


@dataclass(frozen=True)
class CleanupResult:
    removed: bool
    ambiguous: bool
    observation: str


class DockerCommandRunner(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_stream: BinaryIO | None,
        deadline: float,
        stdout_limit: int,
        stderr_limit: int,
        env: dict[str, str],
    ) -> DockerCommandResult: ...


@dataclass(frozen=True)
class _PreparedRecord:
    prepared: PreparedAuditContainer
    limits: AuditLimits
    deadline: float
    labels: dict[str, str]
    image_environment: tuple[str, ...]


def _error(message: str) -> NoReturn:
    raise AuditContainerError(message)


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        _error("audit container deadline has expired")
    return value


def _validate_deadline(deadline: float) -> float:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
    ):
        _error("audit container deadline must be a finite monotonic timestamp")
    result = float(deadline)
    _remaining(result)
    return result


def _command_deadline(deadline: float, limits: AuditLimits) -> float:
    _remaining(deadline)
    return min(deadline, time.monotonic() + limits.docker_control_seconds)


def _validate_limits(limits: AuditLimits) -> None:
    if not isinstance(limits, AuditLimits):
        _error("audit container limits are invalid")
    for field in (
        "cpu_count",
        "memory_bytes",
        "pids",
        "workspace_bytes",
        "temp_bytes",
    ):
        if getattr(limits, field) != getattr(HARD_LIMITS, field):
            _error("audit container isolation limits cannot be configured")
    if (
        isinstance(limits.docker_control_seconds, bool)
        or not isinstance(limits.docker_control_seconds, int)
        or not 1 <= limits.docker_control_seconds <= HARD_LIMITS.docker_control_seconds
    ):
        _error("audit Docker control deadline is outside its hard limit")


def _safe_private_directory(path: Path) -> None:
    try:
        ensure_private_directory(path)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditContainerError("audit container control directory is unavailable") from exc


def _decode_json_list(data: bytes, description: str) -> list[object]:
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditContainerError(f"{description} returned invalid JSON") from exc
    if not isinstance(value, list) or len(value) != 1:
        _error(f"{description} returned an ambiguous result")
    return value


def _single_line(data: bytes, description: str, pattern: re.Pattern[str]) -> str:
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        _error(f"{description} returned ambiguous output")
    try:
        value = data[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditContainerError(f"{description} returned invalid output") from exc
    if pattern.fullmatch(value) is None:
        _error(f"{description} returned an invalid identity")
    return value


def _validated_image_reference(image_ref: str) -> tuple[str, str]:
    try:
        validated = parse_audit_config({"schema_version": 1, "image": image_ref}).image
    except AuditConfigError as exc:
        raise AuditContainerError(
            "audit image must be an immutable digest-qualified reference"
        ) from exc
    if _DIGEST_RE.fullmatch(validated):
        return validated, validated
    repository, digest = validated.rsplit("@sha256:", 1)
    prefix, separator, last_component = repository.rpartition("/")
    if ":" in last_component:
        last_component = last_component.rsplit(":", 1)[0]
    canonical_repository = f"{prefix}{separator}{last_component}"
    return validated, f"{canonical_repository}@sha256:{digest}"


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    group_id = process.pid
    with suppress(OSError):
        os.killpg(group_id, signal.SIGTERM)
    term_deadline = time.monotonic() + 0.2
    while time.monotonic() < term_deadline:
        try:
            os.killpg(group_id, 0)
        except ProcessLookupError:
            break
        except OSError:
            break
        time.sleep(0.01)
    with suppress(OSError):
        os.killpg(group_id, signal.SIGKILL)
    if process.poll() is None:
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=1)


class _SubprocessDockerRunner:
    def run(
        self,
        argv: tuple[str, ...],
        *,
        input_stream: BinaryIO | None,
        deadline: float,
        stdout_limit: int,
        stderr_limit: int,
        env: dict[str, str],
    ) -> DockerCommandResult:
        try:
            process = subprocess.Popen(  # nosec B603
                argv,
                stdin=subprocess.PIPE if input_stream is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            raise AuditContainerError("Docker control process could not be started") from exc
        writer_error: list[BaseException] = []

        def write_input() -> None:
            if process.stdin is None or input_stream is None:
                return
            try:
                while True:
                    chunk = input_stream.read(_PROCESS_CHUNK)
                    if not chunk:
                        break
                    process.stdin.write(chunk)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError) as exc:
                writer_error.append(exc)
                with suppress(OSError):
                    process.stdin.close()

        writer = threading.Thread(target=write_input, daemon=True)
        if input_stream is not None:
            writer.start()
        if process.stdout is None or process.stderr is None:
            _stop_process(process)
            _error("Docker control process pipes are unavailable")
        selector = selectors.DefaultSelector()
        outputs = {process.stdout: bytearray(), process.stderr: bytearray()}
        limits = {process.stdout: stdout_limit, process.stderr: stderr_limit}
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                events = selector.select(_remaining(deadline))
                if not events:
                    _stop_process(process)
                    _error("Docker control process exceeded its deadline")
                for key, _mask in events:
                    stream = cast(BinaryIO, key.fileobj)
                    try:
                        chunk = os.read(key.fd, _PROCESS_CHUNK)
                    except OSError as exc:
                        _stop_process(process)
                        raise AuditContainerError(
                            "Docker control output could not be read"
                        ) from exc
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    outputs[stream].extend(chunk)
                    if len(outputs[stream]) > limits[stream]:
                        _stop_process(process)
                        _error("Docker control output exceeded its byte limit")
            try:
                return_code = process.wait(timeout=_remaining(deadline))
            except subprocess.TimeoutExpired:
                _stop_process(process)
                _error("Docker control process exceeded its deadline")
            if input_stream is not None:
                writer.join(timeout=min(1.0, _remaining(deadline)))
                if writer.is_alive():
                    _stop_process(process)
                    _error("Docker control input did not terminate")
            if return_code != 0:
                _error("Docker control command failed")
            if writer_error:
                _error("Docker control input could not be written")
            return DockerCommandResult(
                stdout=bytes(outputs[process.stdout]),
                stderr=bytes(outputs[process.stderr]),
            )
        finally:
            selector.close()
            for close_stream in (process.stdin, process.stdout, process.stderr):
                if close_stream is not None:
                    with suppress(OSError):
                        close_stream.close()
            if process.poll() is None:
                _stop_process(process)


def _open_directory_at(parent: int, name: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        result = os.fstat(descriptor)
    except OSError as exc:
        raise AuditContainerError("snapshot directory binding changed") from exc
    if not stat.S_ISDIR(result.st_mode):
        os.close(descriptor)
        _error("snapshot directory binding changed")
    return descriptor


def _open_parent(root_descriptor: int, path: str) -> tuple[int, str]:
    components = path.split("/")
    current = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            child = _open_directory_at(current, component)
            os.close(current)
            current = child
        return current, components[-1]
    except BaseException:
        with suppress(OSError):
            os.close(current)
        raise


def _actual_snapshot_paths(
    root_descriptor: int,
    *,
    deadline: float,
) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    pending: list[tuple[str, int]] = [("", os.dup(root_descriptor))]
    try:
        while pending:
            _remaining(deadline)
            prefix, descriptor = pending.pop()
            try:
                names = os.listdir(descriptor)
                _remaining(deadline)
                for name in names:
                    _remaining(deadline)
                    if name in {".", ".."}:
                        _error("snapshot contains an ambiguous path")
                    path = name if not prefix else f"{prefix}/{name}"
                    result = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(result.st_mode):
                        directories.add(path)
                        pending.append((path, _open_directory_at(descriptor, name)))
                    elif stat.S_ISREG(result.st_mode) or stat.S_ISLNK(result.st_mode):
                        files.add(path)
                    else:
                        _error("snapshot contains an unsupported entry")
                    _remaining(deadline)
            finally:
                os.close(descriptor)
        return files, directories
    except BaseException:
        for _prefix, descriptor in pending:
            with suppress(OSError):
                os.close(descriptor)
        raise


def _manifest_directories(manifest: tuple[SnapshotManifestEntry, ...]) -> set[str]:
    directories: set[str] = set()
    for entry in manifest:
        parts = entry.path.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return directories


def _tar_info(name: str, mode: int, entry_type: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = entry_type
    info.mode = mode
    info.uid = AUDIT_UID
    info.gid = AUDIT_GID
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


class _DeadlineReader:
    def __init__(self, stream: BinaryIO, deadline: float) -> None:
        self._stream = stream
        self._deadline = deadline
        self._digest = hashlib.sha256()
        self._bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        _remaining(self._deadline)
        value = self._stream.read(size)
        self._digest.update(value)
        self._bytes_read += len(value)
        _remaining(self._deadline)
        return value

    @property
    def bytes_read(self) -> int:
        return self._bytes_read

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _has_isolated_none_network(networks: object) -> bool:
    if not isinstance(networks, dict) or set(networks) != {"none"}:
        return False
    endpoint = networks.get("none")
    if not isinstance(endpoint, dict):
        return False
    expected_values = {
        "Aliases": None,
        "DriverOpts": None,
        "Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "IPAMConfig": None,
        "IPAddress": "",
        "IPPrefixLen": 0,
        "IPv6Gateway": "",
        "Links": None,
        "MacAddress": "",
    }
    if any(endpoint.get(key) != value for key, value in expected_values.items()):
        return False
    if endpoint.get("DNSNames") not in (None, []):
        return False
    if endpoint.get("GwPriority", 0) != 0:
        return False
    return all(isinstance(endpoint.get(key), str) for key in ("EndpointID", "NetworkID"))


def _validate_snapshot_archive_limits(snapshot: MaterializedSnapshot, limits: AuditLimits) -> None:
    for field in ("snapshot_entries", "snapshot_blob_bytes"):
        value = getattr(limits, field)
        hard = getattr(HARD_LIMITS, field)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hard:
            _error("snapshot archive limit is outside its hard ceiling")
    if (
        len(snapshot.manifest) > limits.snapshot_entries
        or snapshot.source_entry_count > limits.snapshot_entries
    ):
        _error("snapshot archive exceeds its entry limit")
    manifest_bytes = sum(entry.size for entry in snapshot.manifest)
    if (
        manifest_bytes > limits.snapshot_blob_bytes
        or snapshot.source_blob_bytes > limits.snapshot_blob_bytes
    ):
        _error("snapshot archive exceeds its blob byte limit")


def _build_seed_archive(
    snapshot: MaterializedSnapshot,
    deadline: float,
    *,
    limits: AuditLimits,
    spool_dir: Path,
) -> BinaryIO:
    _remaining(deadline)
    if not isinstance(snapshot, MaterializedSnapshot):
        _error("materialized snapshot is invalid")
    if not isinstance(limits, AuditLimits):
        _error("snapshot archive limits are invalid")
    if not isinstance(spool_dir, Path) or not spool_dir.is_absolute():
        _error("snapshot archive spool directory is invalid")
    try:
        private_spool = inspect_private_directory(spool_dir)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditContainerError("snapshot archive spool directory is unsafe") from exc
    if not private_spool:
        _error("snapshot archive spool directory is unavailable")
    _validate_snapshot_archive_limits(snapshot, limits)
    try:
        root_result = snapshot.root.lstat()
    except OSError as exc:
        raise AuditContainerError("materialized snapshot root is unavailable") from exc
    identity = snapshot._root_identity
    if (
        not stat.S_ISDIR(root_result.st_mode)
        or root_result.st_dev != identity.device
        or root_result.st_ino != identity.inode
        or root_result.st_uid != identity.owner
        or stat.S_IMODE(root_result.st_mode) != identity.permissions
    ):
        _error("materialized snapshot root binding changed")
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_descriptor = os.open(snapshot.root, root_flags)
    except OSError as exc:
        raise AuditContainerError("materialized snapshot root could not be opened") from exc
    # The caller owns and closes this bounded archive after Docker consumes it.
    archive = tempfile.SpooledTemporaryFile(  # noqa: SIM115
        max_size=8 * 1024 * 1024,
        mode="w+b",
        dir=str(spool_dir),
    )
    try:
        opened_root = os.fstat(root_descriptor)
        if (
            opened_root.st_dev != identity.device
            or opened_root.st_ino != identity.inode
            or opened_root.st_uid != identity.owner
        ):
            _error("materialized snapshot root binding changed")
        expected_paths = {entry.path for entry in snapshot.manifest}
        if len(expected_paths) != len(snapshot.manifest):
            _error("snapshot manifest contains duplicate paths")
        expected_directories = _manifest_directories(snapshot.manifest)
        actual_paths, actual_directories = _actual_snapshot_paths(
            root_descriptor,
            deadline=deadline,
        )
        if actual_paths != expected_paths or actual_directories != expected_directories:
            _error("snapshot path set changed before container seeding")
        with tarfile.open(fileobj=archive, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for directory in sorted(expected_directories):
                _remaining(deadline)
                info = _tar_info(directory, _PRIVATE_DIRECTORY_MODE, tarfile.DIRTYPE)
                tar.addfile(info)
            for entry in sorted(snapshot.manifest, key=lambda value: value.path):
                _remaining(deadline)
                parent, name = _open_parent(root_descriptor, entry.path)
                try:
                    result = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if entry.is_symlink:
                        if not stat.S_ISLNK(result.st_mode):
                            _error("snapshot manifest entry type changed")
                        target = os.readlink(name, dir_fd=parent)
                        if target != entry.symlink_target or result.st_size != entry.size:
                            _error("snapshot symlink metadata changed")
                        info = _tar_info(entry.path, 0o777, tarfile.SYMTYPE)
                        info.linkname = target
                        tar.addfile(info)
                        continue
                    if (
                        not stat.S_ISREG(result.st_mode)
                        or result.st_nlink != 1
                        or stat.S_IMODE(result.st_mode) != entry.mode
                        or result.st_size != entry.size
                    ):
                        _error("snapshot file metadata changed")
                    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                    descriptor = os.open(name, flags, dir_fd=parent)
                    try:
                        opened = os.fstat(descriptor)
                        if (
                            opened.st_dev != result.st_dev
                            or opened.st_ino != result.st_ino
                            or opened.st_size != result.st_size
                        ):
                            _error("snapshot file binding changed")
                        digest = hashlib.sha256()
                        while True:
                            _remaining(deadline)
                            chunk = os.read(descriptor, _PROCESS_CHUNK)
                            if not chunk:
                                break
                            digest.update(chunk)
                        if digest.hexdigest() != entry.sha256:
                            _error("snapshot file digest changed")
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        info = _tar_info(entry.path, entry.mode, tarfile.REGTYPE)
                        info.size = entry.size
                        with os.fdopen(os.dup(descriptor), "rb") as source:
                            reader = _DeadlineReader(source, deadline)
                            tar.addfile(info, reader)
                            if (
                                reader.bytes_read != entry.size
                                or reader.hexdigest() != entry.sha256
                            ):
                                _error("snapshot file changed while archive was streamed")
                    finally:
                        os.close(descriptor)
                    final = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (
                        final.st_dev != result.st_dev
                        or final.st_ino != result.st_ino
                        or final.st_size != result.st_size
                        or stat.S_IMODE(final.st_mode) != entry.mode
                    ):
                        _error("snapshot file binding changed")
                finally:
                    os.close(parent)
        final_root = os.fstat(root_descriptor)
        if final_root.st_dev != identity.device or final_root.st_ino != identity.inode:
            _error("materialized snapshot root binding changed")
        _remaining(deadline)
        archive.seek(0)
        _remaining(deadline)
        return cast(BinaryIO, archive)
    except BaseException:
        archive.close()
        raise
    finally:
        os.close(root_descriptor)


def _validation_manifest(snapshot: MaterializedSnapshot) -> bytes:
    entries: list[dict[str, object]] = []
    for entry in sorted(snapshot.manifest, key=lambda value: value.path):
        if entry.is_symlink:
            entries.append(
                {
                    "path": entry.path,
                    "type": "symlink",
                    "target": entry.symlink_target,
                }
            )
        else:
            entries.append(
                {
                    "mode": entry.mode,
                    "path": entry.path,
                    "sha256": entry.sha256,
                    "size": entry.size,
                    "type": "file",
                }
            )
    return json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


class AuditContainerRuntime:
    """Create, seed, prove, and clean one exact audit-owned container."""

    def __init__(
        self,
        docker_executable: Path,
        control_dir: Path,
        *,
        runner: DockerCommandRunner | None = None,
    ) -> None:
        if not isinstance(docker_executable, Path) or not docker_executable.is_absolute():
            _error("Docker executable must be an absolute pathlib.Path")
        if not isinstance(control_dir, Path) or not control_dir.is_absolute():
            _error("audit container control directory must be absolute")
        self._docker = docker_executable
        self._control_dir = control_dir
        self._runner: DockerCommandRunner = _SubprocessDockerRunner() if runner is None else runner
        self._records: dict[str, _PreparedRecord] = {}

    def _run(
        self,
        arguments: tuple[str, ...],
        *,
        limits: AuditLimits,
        deadline: float,
        input_stream: BinaryIO | None = None,
        stdout_limit: int = _DOCKER_STDOUT_LIMIT,
        stderr_limit: int = _DOCKER_STDERR_LIMIT,
    ) -> DockerCommandResult:
        return self._runner.run(
            (str(self._docker), *arguments),
            input_stream=input_stream,
            deadline=_command_deadline(deadline, limits),
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            env=dict(_MINIMAL_DOCKER_ENV),
        )

    def _inspect_image(
        self,
        image_ref: str,
        canonical_digest: str,
        *,
        limits: AuditLimits,
        deadline: float,
    ) -> tuple[str, tuple[str, ...], dict[str, str]]:
        result = self._run(
            ("image", "inspect", "--format", "{{json .}}", image_ref),
            limits=limits,
            deadline=deadline,
        )
        try:
            item = json.loads(result.stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditContainerError("Docker image inspection returned invalid JSON") from exc
        if not isinstance(item, dict):
            _error("Docker image inspection returned an invalid result")
        image_id = item.get("Id")
        repo_digests = item.get("RepoDigests")
        image_config = item.get("Config")
        if not isinstance(image_config, dict):
            _error("Docker image inspection omitted image configuration")
        if image_config.get("Volumes") not in (None, {}):
            _error("audit image declares an inherited volume")
        image_environment = image_config.get("Env")
        if image_environment is None:
            normalized_environment: tuple[str, ...] = ()
        elif isinstance(image_environment, list) and all(
            isinstance(value, str) for value in image_environment
        ):
            normalized_environment = tuple(image_environment)
        else:
            _error("Docker image inspection returned an invalid environment")
        image_labels = image_config.get("Labels")
        if image_labels is None:
            normalized_labels: dict[str, str] = {}
        elif isinstance(image_labels, dict) and all(
            isinstance(key, str) and isinstance(value, str) for key, value in image_labels.items()
        ):
            normalized_labels = dict(image_labels)
        else:
            _error("Docker image inspection returned invalid labels")
        if not isinstance(image_id, str) or _DIGEST_RE.fullmatch(image_id) is None:
            _error("Docker image inspection returned an invalid image ID")
        if image_ref.startswith("sha256:"):
            if image_id != image_ref:
                _error("local image ID does not match the configured digest")
        elif (
            not isinstance(repo_digests, list)
            or canonical_digest not in repo_digests
            or not all(isinstance(value, str) for value in repo_digests)
        ):
            _error("local image digest binding does not match the configured image")
        return image_id, normalized_environment, normalized_labels

    def _create_arguments(
        self,
        *,
        name: str,
        profile: str,
        run_id: str,
        image_ref: str,
        limits: AuditLimits,
    ) -> tuple[str, ...]:
        return (
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            "com.zeus.audit=true",
            "--label",
            f"com.zeus.audit.run-id={run_id}",
            "--label",
            f"com.zeus.audit.profile={profile}",
            "--network=none",
            f"--user={AUDIT_UID}:{AUDIT_GID}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--read-only",
            "--no-healthcheck",
            "--ipc=none",
            f"--pids-limit={limits.pids}",
            f"--cpus={limits.cpu_count}",
            f"--memory={limits.memory_bytes}",
            f"--memory-swap={limits.memory_bytes}",
            f"--tmpfs=/workspace:{_WORKSPACE_TMPFS}",
            f"--tmpfs={_TEMP_PATH}:{_TEMP_TMPFS}",
            "--workdir=/workspace",
            "--entrypoint=/bin/sh",
            image_ref,
            *_COMMAND,
        )

    def prepare(
        self,
        *,
        run_id: str,
        snapshot: MaterializedSnapshot,
        image_ref: str,
        limits: AuditLimits,
        deadline: float,
    ) -> PreparedAuditContainer:
        active_deadline = _validate_deadline(deadline)
        _validate_limits(limits)
        if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
            _error("audit container run ID is invalid")
        if not isinstance(image_ref, str):
            _error("audit image must be an immutable digest-qualified reference")
        validated_image_ref, canonical_digest = _validated_image_reference(image_ref)
        if not isinstance(snapshot, MaterializedSnapshot):
            _error("materialized snapshot is invalid")
        _safe_private_directory(self._control_dir)
        broker_dir = self._control_dir / "broker"
        _safe_private_directory(broker_dir)
        state_path = broker_dir / "state.json"
        name = f"zeus-audit-{run_id}"
        profile = f"audit-{run_id}"
        ownership_labels = {
            "com.zeus.audit": "true",
            "com.zeus.audit.run-id": run_id,
            "com.zeus.audit.profile": profile,
        }
        image_id, image_environment, image_labels = self._inspect_image(
            validated_image_ref,
            canonical_digest,
            limits=limits,
            deadline=active_deadline,
        )
        labels = dict(image_labels)
        labels.update(ownership_labels)
        create_result = self._run(
            self._create_arguments(
                name=name,
                profile=profile,
                run_id=run_id,
                image_ref=validated_image_ref,
                limits=limits,
            ),
            limits=limits,
            deadline=active_deadline,
        )
        container_id = _single_line(create_result.stdout, "Docker create", _CONTAINER_ID_RE)
        prepared = PreparedAuditContainer(
            container_id=container_id,
            container_name=name,
            profile_name=profile,
            image_ref=validated_image_ref,
            image_id=image_id,
            broker_dir=broker_dir,
            state_path=state_path,
        )
        record = _PreparedRecord(
            prepared=prepared,
            limits=limits,
            deadline=active_deadline,
            labels=labels,
            image_environment=image_environment,
        )
        self._records[container_id] = record
        archive: BinaryIO | None = None
        try:
            self._run(("start", container_id), limits=limits, deadline=active_deadline)
            archive = _build_seed_archive(
                snapshot,
                active_deadline,
                limits=limits,
                spool_dir=broker_dir,
            )
            self._run(
                ("cp", "--archive", "-", f"{container_id}:/workspace"),
                limits=limits,
                deadline=active_deadline,
                input_stream=archive,
                stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
            )
            manifest_stream = io.BytesIO(_validation_manifest(snapshot))
            self._run(
                (
                    "exec",
                    "-i",
                    f"--user={AUDIT_UID}:{AUDIT_GID}",
                    "--workdir=/workspace",
                    container_id,
                    "python3",
                    "-I",
                    "-c",
                    _VALIDATION_SCRIPT,
                    str(AUDIT_UID),
                    str(AUDIT_GID),
                    str(AUDIT_UID),
                    str(AUDIT_GID),
                    "[]",
                    "/proc/self/status",
                    ".",
                ),
                limits=limits,
                deadline=active_deadline,
                input_stream=manifest_stream,
                stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
            )
            self._validate_record(record)
            return prepared
        except BaseException:
            self._cleanup_record(record)
            self._records.pop(container_id, None)
            raise
        finally:
            if archive is not None:
                archive.close()

    def _inspect(
        self,
        record: _PreparedRecord,
        *,
        deadline: float | None = None,
    ) -> dict[str, object]:
        result = self._run(
            ("inspect", record.prepared.container_id),
            limits=record.limits,
            deadline=record.deadline if deadline is None else deadline,
        )
        value = _decode_json_list(result.stdout, "Docker container inspection")[0]
        if not isinstance(value, dict):
            _error("Docker container inspection returned an invalid result")
        return cast(dict[str, object], value)

    def _validate_record(self, record: _PreparedRecord) -> None:
        item = self._inspect(record)
        self._validate_inspected_record(record, item)

    def _validate_inspected_record(
        self,
        record: _PreparedRecord,
        item: dict[str, object],
        *,
        require_running: bool = True,
    ) -> None:
        prepared = record.prepared
        config = item.get("Config")
        host = item.get("HostConfig")
        mounts = item.get("Mounts")
        network = item.get("NetworkSettings")
        if not isinstance(config, dict) or not isinstance(host, dict):
            _error("Docker container inspection omitted mandatory controls")
        if not isinstance(network, dict):
            _error("Docker container inspection omitted network controls")
        expected_tmpfs = {"/workspace": _WORKSPACE_TMPFS, _TEMP_PATH: _TEMP_TMPFS}
        expected_mounts = {
            ("/workspace", "tmpfs", True),
            (_TEMP_PATH, "tmpfs", True),
        }
        if not isinstance(mounts, list):
            _error("Docker container inspection omitted mount controls")
        observed_mounts: set[tuple[object, object, object]] = set()
        for mount in mounts:
            if not isinstance(mount, dict):
                _error("Docker container inspection returned an invalid mount")
            observed_mounts.add((mount.get("Destination"), mount.get("Type"), mount.get("RW")))
        checks = (
            (item.get("Id") == prepared.container_id, "container identity"),
            (item.get("Name") == f"/{prepared.container_name}", "container name"),
            (item.get("Image") == prepared.image_id, "container image ID"),
            (config.get("Image") == prepared.image_ref, "container image reference"),
            (config.get("User") == f"{AUDIT_UID}:{AUDIT_GID}", "container user"),
            (config.get("WorkingDir") == "/workspace", "container workdir"),
            (config.get("Entrypoint") == list(_ENTRYPOINT), "container entrypoint"),
            (config.get("Cmd") == list(_COMMAND), "container command"),
            (
                tuple(config.get("Env") or ()) == record.image_environment,
                "container environment",
            ),
            (config.get("Volumes") in (None, {}), "container volumes"),
            (config.get("Labels") == record.labels, "container labels"),
            (
                config.get("Healthcheck") == {"Test": ["NONE"]},
                "container healthcheck",
            ),
            (host.get("NetworkMode") == "none", "container network"),
            (host.get("Binds") in (None, []), "container binds"),
            (host.get("Mounts") in (None, []), "container host mounts"),
            (host.get("CapAdd") in (None, []), "container added capabilities"),
            (host.get("CapDrop") == ["ALL"], "container dropped capabilities"),
            (host.get("GroupAdd") in (None, []), "container supplementary groups"),
            (
                host.get("SecurityOpt") == ["no-new-privileges:true"],
                "container security options",
            ),
            (host.get("ReadonlyRootfs") is True, "container root filesystem"),
            (host.get("PidsLimit") == record.limits.pids, "container PID limit"),
            (
                host.get("NanoCpus") == record.limits.cpu_count * 1_000_000_000,
                "container CPU limit",
            ),
            (host.get("Memory") == record.limits.memory_bytes, "container memory limit"),
            (
                host.get("MemorySwap") == record.limits.memory_bytes,
                "container swap limit",
            ),
            (host.get("Privileged") is False, "container privileged mode"),
            (host.get("PidMode") in ("", "private"), "container PID namespace"),
            (host.get("IpcMode") == "none", "container IPC namespace"),
            (host.get("UTSMode") in ("", "private"), "container UTS namespace"),
            (host.get("UsernsMode") in ("", "private"), "container user namespace"),
            (
                host.get("CgroupnsMode") == "private",
                "container cgroup namespace",
            ),
            (host.get("Devices") in (None, []), "container devices"),
            (host.get("DeviceRequests") in (None, []), "container device requests"),
            (
                host.get("DeviceCgroupRules") in (None, []),
                "container device cgroup rules",
            ),
            (host.get("PortBindings") in (None, {}), "container port bindings"),
            (host.get("Tmpfs") == expected_tmpfs, "container tmpfs controls"),
            (observed_mounts == expected_mounts, "container effective mounts"),
            (network.get("Ports") in (None, {}), "container effective ports"),
            (
                _has_isolated_none_network(network.get("Networks")),
                "container effective network attachments",
            ),
            (network.get("IPAddress") == "", "container effective IP address"),
            (network.get("Gateway") == "", "container effective gateway"),
            (network.get("MacAddress") == "", "container effective MAC address"),
        )
        for accepted, description in checks:
            if not accepted:
                _error(f"{description} does not match the required isolation policy")
        if require_running and (
            not isinstance(item.get("State"), dict)
            or cast(dict[object, object], item["State"]).get("Running") is not True
        ):
            _error("container running state does not match the required isolation policy")

    def validate(self, prepared: PreparedAuditContainer) -> None:
        record = self._records.get(prepared.container_id)
        if record is None or record.prepared != prepared:
            _error("audit container is not owned by this runtime")
        self._validate_record(record)

    def _cleanup_record(self, record: _PreparedRecord) -> CleanupResult:
        cleanup_deadline = time.monotonic() + record.limits.docker_control_seconds
        try:
            item = self._inspect(record, deadline=cleanup_deadline)
            self._validate_inspected_record(record, item, require_running=False)
        except AuditContainerError:
            return CleanupResult(
                removed=False,
                ambiguous=True,
                observation="container identity or ownership could not be proven",
            )
        remove_result = self._run(
            ("rm", "-f", record.prepared.container_id),
            limits=record.limits,
            deadline=cleanup_deadline,
            stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
        )
        removed_id = _single_line(remove_result.stdout, "Docker remove", _CONTAINER_ID_RE)
        if removed_id != record.prepared.container_id:
            _error("Docker remove returned an unexpected container identity")
        return CleanupResult(
            removed=True,
            ambiguous=False,
            observation="exact audit-owned container removed",
        )

    def cleanup(self, prepared: PreparedAuditContainer) -> CleanupResult:
        record = self._records.get(prepared.container_id)
        if record is None or record.prepared != prepared:
            return CleanupResult(
                removed=False,
                ambiguous=True,
                observation="container is not owned by this runtime",
            )
        try:
            return self._cleanup_record(record)
        except AuditContainerError:
            return CleanupResult(
                removed=False,
                ambiguous=True,
                observation="container cleanup could not prove safe removal",
            )
        finally:
            self._records.pop(prepared.container_id, None)
