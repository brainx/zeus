"""Bounded process and snapshot helpers for the audit container runtime."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import stat
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, cast

from zeus.audit_config import AuditConfigError, parse_audit_config
from zeus.audit_container_types import (
    AUDIT_GID,
    AUDIT_UID,
    AuditContainerError,
    DockerCommandResult,
    _error,
    _remaining,
)
from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.audit_process import AuditProcessError, stop_process_group, wait_process_exit
from zeus.audit_trusted_snapshot_attest import TRUSTED_EXEC_ENV
from zeus.audit_workspace import MaterializedSnapshot, SnapshotManifestEntry
from zeus.private_io import inspect_private_directory

_PRIVATE_DIRECTORY_MODE = 0o700
_PROCESS_CHUNK = 64 * 1024
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


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
    if not stop_process_group(process):
        _error("Docker control process group cleanup could not be verified")


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
                return_code = wait_process_exit(process, deadline=deadline)
            except (AuditProcessError, subprocess.TimeoutExpired):
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
            if process.returncode is None:
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


def _normalized_environment(environment: tuple[str, ...]) -> tuple[str, ...]:
    values: dict[str, str] = {}
    for item in environment:
        key, separator, value = item.partition("=")
        if not separator or not key or key in values or "\0" in item:
            _error("trusted audit container environment is invalid")
        values[key] = value
    return tuple(f"{key}={values[key]}" for key in sorted(values))


def _trusted_environment(image_environment: tuple[str, ...]) -> tuple[str, ...]:
    """Compute Docker's effective environment semantically, independent of order."""

    values = {
        item.partition("=")[0]: item.partition("=")[2]
        for item in _normalized_environment(image_environment)
    }
    for item in TRUSTED_EXEC_ENV:
        key, _separator, value = item.partition("=")
        values[key] = value
    return tuple(f"{key}={values[key]}" for key in sorted(values))


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
