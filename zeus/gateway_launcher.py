from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import platform
import re
import stat
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import NoReturn
from urllib.parse import urlparse

from zeus.models import ID_RE

if os.name == "posix":
    import fcntl

MAX_PAYLOAD_BYTES = 256 * 1024
MAX_ARGV_PARTS = 64
MAX_ARG_BYTES = 64 * 1024
MAX_ENV_ITEMS = 1024
MAX_ENV_BYTES = 192 * 1024
MARKER_NAME = "zeus-gateway.pid.json"
MARKER_PUBLICATION_LOCK_NAME = ".zeus-gateway-marker.lock"
MARKER_PUBLICATION_LOCK_TIMEOUT_SECONDS = 30.0

_OPERATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class _UnspecifiedProcessStart:
    pass


_UNSPECIFIED_PROCESS_START = _UnspecifiedProcessStart()
_ROOT_KEYS = frozenset({"profile_path", "marker_path", "marker", "argv", "env"})
_MARKER_KEYS = frozenset(
    {
        "schema",
        "bot_id",
        "component",
        "action",
        "operation_id",
        "desired_revision",
        "argv",
        "resolved_hermes_bin",
        "command_fingerprint",
        "readiness_probe",
    }
)
_RUNTIME_MARKER_KEYS = _MARKER_KEYS | frozenset({"pid", "started_at"})
_RUNTIME_MARKER_FINGERPRINT_KEYS = _RUNTIME_MARKER_KEYS | frozenset({"proc_start_fingerprint"})
_PROBE_KEYS = frozenset(
    {"url", "expected_status", "expected_platform", "timeout_seconds", "interval_seconds"}
)


class LaunchPayloadError(ValueError):
    pass


class _ConfirmedMissing(LaunchPayloadError):
    """A missing path component whose absence was rechecked on retained descriptors."""


def command_fingerprint(argv: list[str]) -> str:
    encoded = json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _exact_dict(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise LaunchPayloadError(f"{name} must be an object")
    result = value
    if set(result) != keys or not all(type(key) is str for key in result):
        raise LaunchPayloadError(f"{name} has invalid keys")
    return result


def _exact_string(value: object, name: str, *, max_length: int) -> str:
    if type(value) is not str or not value or len(value) > max_length or "\0" in value:
        raise LaunchPayloadError(f"{name} must be a bounded non-empty string")
    return value


def _validate_argv(value: object) -> list[str]:
    if type(value) is not list or not value or len(value) > MAX_ARGV_PARTS:
        raise LaunchPayloadError("argv must be a bounded non-empty list")
    argv: list[str] = []
    total = 0
    for item in value:
        part = _exact_string(item, "argv item", max_length=16 * 1024)
        total += len(part.encode("utf-8"))
        if total > MAX_ARG_BYTES:
            raise LaunchPayloadError("argv is too large")
        argv.append(part)
    return argv


def _validate_env(value: object) -> dict[str, str]:
    if type(value) is not dict or len(value) > MAX_ENV_ITEMS:
        raise LaunchPayloadError("env must be a bounded object")
    env: dict[str, str] = {}
    total = 0
    for raw_name, raw_value in value.items():
        name = _exact_string(raw_name, "environment name", max_length=255)
        if type(raw_value) is not str or len(raw_value) > 128 * 1024 or "\0" in raw_value:
            raise LaunchPayloadError("environment values must be bounded strings")
        item = raw_value
        if "=" in name:
            raise LaunchPayloadError("environment names must not contain equals")
        total += len(name.encode("utf-8")) + len(item.encode("utf-8"))
        if total > MAX_ENV_BYTES:
            raise LaunchPayloadError("environment is too large")
        env[name] = item
    return env


def _validate_path(value: object, name: str) -> Path:
    raw = _exact_string(value, name, max_length=16 * 1024)
    path = Path(raw)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise LaunchPayloadError(f"{name} must be an absolute path without traversal")
    return path


def _valid_probe_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return math.isfinite(float(value)) and 0 < float(value) <= 3600


def _validate_readiness_probe(value: object) -> object:
    if value is None:
        return None
    probe = _exact_dict(value, _PROBE_KEYS, "readiness_probe")
    url = _exact_string(probe["url"], "readiness URL", max_length=2048)
    parsed = urlparse(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise LaunchPayloadError("readiness URL must be loopback HTTP")
    _exact_string(probe["expected_status"], "expected status", max_length=128)
    _exact_string(probe["expected_platform"], "expected platform", max_length=128)
    if not _valid_probe_number(probe["timeout_seconds"]) or not _valid_probe_number(
        probe["interval_seconds"]
    ):
        raise LaunchPayloadError("readiness timing is invalid")
    return probe


def _validate_payload(value: object) -> tuple[Path, dict[str, object], list[str], dict[str, str]]:
    payload = _exact_dict(value, _ROOT_KEYS, "payload")
    profile_path = _validate_path(payload["profile_path"], "profile_path")
    marker_path = _validate_path(payload["marker_path"], "marker_path")
    marker = _exact_dict(payload["marker"], _MARKER_KEYS, "marker")
    bot_id = _exact_string(marker["bot_id"], "bot_id", max_length=63)
    if ID_RE.fullmatch(bot_id) is None:
        raise LaunchPayloadError("bot_id is invalid")
    if profile_path.name != bot_id or profile_path.parent.name != "profiles":
        raise LaunchPayloadError("profile_path is outside the bot profile boundary")
    if marker_path != profile_path / "logs" / MARKER_NAME:
        raise LaunchPayloadError("marker_path is outside the bot profile boundary")

    if marker["schema"] != 3 or type(marker["schema"]) is not int:
        raise LaunchPayloadError("marker schema is invalid")
    if marker["component"] != "gateway" or marker["action"] != "run":
        raise LaunchPayloadError("marker command intent is invalid")
    operation_id = _exact_string(marker["operation_id"], "operation_id", max_length=32)
    if _OPERATION_ID_RE.fullmatch(operation_id) is None:
        raise LaunchPayloadError("operation_id is invalid")
    revision = marker["desired_revision"]
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise LaunchPayloadError("desired_revision is invalid")

    argv = _validate_argv(payload["argv"])
    marker_argv = _validate_argv(marker["argv"])
    if argv != marker_argv:
        raise LaunchPayloadError("marker argv does not match exec argv")
    if len(argv) != 5 or argv[1:] != ["-p", bot_id, "gateway", "run"]:
        raise LaunchPayloadError("argv is not a Hermes gateway command")
    resolved_hermes = _validate_path(marker["resolved_hermes_bin"], "resolved_hermes_bin")
    if argv[0] != str(resolved_hermes):
        raise LaunchPayloadError("exec argv does not use the resolved Hermes binary")
    fingerprint = _exact_string(marker["command_fingerprint"], "command_fingerprint", max_length=64)
    if _FINGERPRINT_RE.fullmatch(fingerprint) is None or fingerprint != command_fingerprint(argv):
        raise LaunchPayloadError("command fingerprint is invalid")
    _validate_readiness_probe(marker["readiness_probe"])
    env = _validate_env(payload["env"])
    if env.get("HERMES_HOME") != str(profile_path.parent.parent):
        raise LaunchPayloadError("HERMES_HOME does not match the bot profile root")
    return profile_path, marker, argv, env


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LaunchPayloadError("JSON object contains duplicate keys")
        result[key] = value
    return result


def _read_payload(fd: int) -> object:
    chunks: list[bytes] = []
    length = 0
    while True:
        chunk = os.read(fd, min(65536, MAX_PAYLOAD_BYTES + 1 - length))
        if not chunk:
            break
        chunks.append(chunk)
        length += len(chunk)
        if length > MAX_PAYLOAD_BYTES:
            raise LaunchPayloadError("payload is too large")
    if not chunks:
        raise LaunchPayloadError("payload is empty")
    try:
        return json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LaunchPayloadError("payload is not valid JSON") from exc


def _directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return flags | getattr(os, "O_CLOEXEC", 0)


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return before.st_dev == after.st_dev and before.st_ino == after.st_ino


def _caused_by_missing_path(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, FileNotFoundError):
            return True
        current = current.__cause__
    return False


def _validate_open_directory_binding(
    parent_fd: int,
    name: str,
    directory_fd: int,
    description: str,
) -> os.stat_result:
    try:
        opened = os.fstat(directory_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise LaunchPayloadError(f"{description} changed while it was used") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or not _same_file(opened, current)
    ):
        raise LaunchPayloadError(f"{description} changed while it was used")
    return opened


@dataclass
class _OpenedProfile:
    descriptors: list[int]
    names: tuple[str, ...]

    @property
    def fd(self) -> int:
        if not self.descriptors:
            raise LaunchPayloadError("profile descriptor chain is closed")
        return self.descriptors[-1]

    def validate_bindings(self, *, require_profile_owner: bool = True) -> None:
        if len(self.descriptors) != len(self.names) + 1:
            raise LaunchPayloadError("profile descriptor chain is invalid")
        try:
            opened_root = os.fstat(self.descriptors[0])
            current_root = os.stat("/", follow_symlinks=False)
        except OSError as exc:
            raise LaunchPayloadError("filesystem root changed while it was used") from exc
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or not stat.S_ISDIR(current_root.st_mode)
            or not _same_file(opened_root, current_root)
        ):
            raise LaunchPayloadError("filesystem root changed while it was used")
        for parent_fd, name, directory_fd in zip(
            self.descriptors[:-1],
            self.names,
            self.descriptors[1:],
            strict=True,
        ):
            _validate_open_directory_binding(
                parent_fd,
                name,
                directory_fd,
                "profile path component",
            )
        try:
            profile_stat = os.fstat(self.fd)
        except OSError as exc:
            raise LaunchPayloadError("profile directory changed while it was used") from exc
        if require_profile_owner and hasattr(os, "geteuid") and profile_stat.st_uid != os.geteuid():
            raise LaunchPayloadError("profile directory has an unexpected owner")

    def confirm_missing(self, name: str) -> None:
        for _attempt in range(2):
            self.validate_bindings(require_profile_owner=False)
            try:
                os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LaunchPayloadError("missing profile entry cannot be confirmed") from exc
            raise LaunchPayloadError("profile entry appeared while absence was confirmed")
        self.validate_bindings(require_profile_owner=False)

    def detach_fd(self) -> int:
        result = self.fd
        ancestors = self.descriptors[:-1]
        self.descriptors = []
        for descriptor in reversed(ancestors):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        return result

    def close(self) -> None:
        descriptors = self.descriptors
        self.descriptors = []
        for descriptor in reversed(descriptors):
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _open_directory_at(parent_fd: int, name: str) -> int:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise LaunchPayloadError("profile path component is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise LaunchPayloadError("profile path component is not a trusted directory")
    try:
        opened_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise LaunchPayloadError("profile path component cannot be opened safely") from exc
    try:
        after = os.fstat(opened_fd)
        if not stat.S_ISDIR(after.st_mode) or not _same_file(before, after):
            raise LaunchPayloadError("profile path changed while it was opened")
        return opened_fd
    except LaunchPayloadError:
        with contextlib.suppress(OSError):
            os.close(opened_fd)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(opened_fd)
        raise LaunchPayloadError("profile path could not be validated safely") from exc
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(opened_fd)
        raise


def _open_profile_chain(profile_path: Path) -> _OpenedProfile:
    if not profile_path.is_absolute() or not profile_path.parts or profile_path.parts[0] != "/":
        raise LaunchPayloadError("profile path must be absolute")
    try:
        root_fd = os.open("/", _directory_flags())
    except OSError as exc:
        raise LaunchPayloadError("filesystem root cannot be opened safely") from exc
    descriptors = [root_fd]
    names: list[str] = []
    try:
        for component in profile_path.parts[1:]:
            try:
                next_fd = _open_directory_at(descriptors[-1], component)
            except LaunchPayloadError as exc:
                if _caused_by_missing_path(exc):
                    _OpenedProfile(descriptors, tuple(names)).confirm_missing(component)
                    raise _ConfirmedMissing("profile path component is missing") from exc
                raise
            descriptors.append(next_fd)
            names.append(component)
        opened = _OpenedProfile(descriptors, tuple(names))
        opened.validate_bindings()
        return opened
    except BaseException:
        for descriptor in reversed(descriptors):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise


def _open_profile(profile_path: Path) -> int:
    return _open_profile_chain(profile_path).detach_fd()


class _MarkerPublicationLock:
    def __init__(self, profile_path: Path, timeout_seconds: float) -> None:
        self.profile_path = profile_path
        self.timeout_seconds = timeout_seconds
        self._profile_fd = -1
        self._lock_fd = -1

    def __enter__(self) -> _MarkerPublicationLock:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int | float)
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds < 0
        ):
            raise LaunchPayloadError("marker publication lock timeout is invalid")
        if os.name != "posix":
            raise LaunchPayloadError("marker publication locking is unavailable")
        profile_fd = _open_profile(self.profile_path)
        lock_fd = -1
        locked = False
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            try:
                lock_fd = os.open(
                    MARKER_PUBLICATION_LOCK_NAME,
                    flags,
                    0o600,
                    dir_fd=profile_fd,
                )
            except OSError as exc:
                raise LaunchPayloadError("marker publication lock cannot be opened safely") from exc
            opened = os.fstat(lock_fd)
            if not stat.S_ISREG(opened.st_mode):
                raise LaunchPayloadError("marker publication lock is not a regular file")
            if opened.st_nlink != 1:
                raise LaunchPayloadError("marker publication lock has unexpected links")
            if hasattr(os, "geteuid") and opened.st_uid != os.geteuid():
                raise LaunchPayloadError("marker publication lock has an unexpected owner")
            os.fchmod(lock_fd, 0o600)

            deadline = time.monotonic() + float(self.timeout_seconds)
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError as exc:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LaunchPayloadError("marker publication lock timed out") from exc
                    time.sleep(min(0.01, remaining))
                except OSError as exc:
                    raise LaunchPayloadError("marker publication lock failed") from exc

            try:
                current = os.stat(
                    MARKER_PUBLICATION_LOCK_NAME,
                    dir_fd=profile_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise LaunchPayloadError("marker publication lock changed") from exc
            opened = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(current.st_mode)
                or not _same_file(opened, current)
                or opened.st_nlink != 1
                or current.st_nlink != 1
            ):
                raise LaunchPayloadError("marker publication lock changed")
            self._profile_fd = profile_fd
            self._lock_fd = lock_fd
            return self
        except BaseException:
            if locked:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            if lock_fd >= 0:
                os.close(lock_fd)
            os.close(profile_fd)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            if self._lock_fd >= 0:
                lock_fd = self._lock_fd
                self._lock_fd = -1
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        finally:
            if self._profile_fd >= 0:
                profile_fd = self._profile_fd
                self._profile_fd = -1
                os.close(profile_fd)


def marker_publication_lock(
    profile_path: Path,
    *,
    timeout_seconds: float = MARKER_PUBLICATION_LOCK_TIMEOUT_SECONDS,
) -> _MarkerPublicationLock:
    return _MarkerPublicationLock(profile_path, timeout_seconds)


def _open_logs(profile_fd: int, *, create: bool) -> int:
    if create:
        with contextlib.suppress(FileExistsError):
            os.mkdir("logs", mode=0o700, dir_fd=profile_fd)
    try:
        logs_fd = _open_directory_at(profile_fd, "logs")
    except OSError as exc:
        raise LaunchPayloadError("marker directory cannot be opened safely") from exc
    try:
        logs_stat = os.fstat(logs_fd)
        if not stat.S_ISDIR(logs_stat.st_mode):
            raise LaunchPayloadError("marker directory is not a directory")
        if hasattr(os, "geteuid") and logs_stat.st_uid != os.geteuid():
            raise LaunchPayloadError("marker directory has an unexpected owner")
        return logs_fd
    except LaunchPayloadError:
        with contextlib.suppress(OSError):
            os.close(logs_fd)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(logs_fd)
        raise LaunchPayloadError("marker directory could not be validated safely") from exc
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(logs_fd)
        raise


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short marker write")
        offset += written


def _publish_marker(profile_path: Path, marker: dict[str, object]) -> None:
    profile_fd = _open_profile(profile_path)
    logs_fd = -1
    temp_name = f".{MARKER_NAME}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        logs_fd = _open_logs(profile_fd, create=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=logs_fd)
        try:
            os.fchmod(temp_fd, 0o600)
            data = (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
            _write_all(temp_fd, data)
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        os.link(
            temp_name,
            MARKER_NAME,
            src_dir_fd=logs_fd,
            dst_dir_fd=logs_fd,
            follow_symlinks=False,
        )
        os.fsync(logs_fd)
        os.unlink(temp_name, dir_fd=logs_fd)
        os.fsync(logs_fd)
    finally:
        if logs_fd >= 0:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_name, dir_fd=logs_fd)
            os.close(logs_fd)
        os.close(profile_fd)


def _read_bounded_file(fd: int, limit: int = 64 * 1024) -> bytes:
    chunks: list[bytes] = []
    length = 0
    while True:
        chunk = os.read(fd, min(8192, limit + 1 - length))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        length += len(chunk)
        if length > limit:
            raise LaunchPayloadError("marker is too large")


def _strict_json_object(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)


def _is_owned_runtime_marker(
    value: object,
    *,
    bot_id: str,
    operation_id: str,
    desired_revision: int,
    pid: int,
    expected_fingerprint: str,
) -> bool:
    if type(value) is not dict or frozenset(value) not in {
        _RUNTIME_MARKER_KEYS,
        _RUNTIME_MARKER_FINGERPRINT_KEYS,
    }:
        return False
    marker = value
    if (
        type(marker["schema"]) is not int
        or marker["schema"] != 3
        or marker["bot_id"] != bot_id
        or marker["component"] != "gateway"
        or marker["action"] != "run"
        or marker["operation_id"] != operation_id
        or type(marker["desired_revision"]) is not int
        or marker["desired_revision"] != desired_revision
        or type(marker["pid"]) is not int
        or marker["pid"] != pid
        or marker["command_fingerprint"] != expected_fingerprint
    ):
        return False
    started_at = marker["started_at"]
    if (
        isinstance(started_at, bool)
        or not isinstance(started_at, int | float)
        or not math.isfinite(float(started_at))
        or float(started_at) <= 0
    ):
        return False
    if "proc_start_fingerprint" in marker:
        fingerprint = marker["proc_start_fingerprint"]
        if type(fingerprint) is not str or not fingerprint or len(fingerprint) > 512:
            return False
    try:
        argv = _validate_argv(marker["argv"])
        resolved_hermes = _validate_path(marker["resolved_hermes_bin"], "resolved_hermes_bin")
        _validate_readiness_probe(marker["readiness_probe"])
    except LaunchPayloadError:
        return False
    return (
        len(argv) == 5
        and argv[1:] == ["-p", bot_id, "gateway", "run"]
        and argv[0] == str(resolved_hermes)
        and _FINGERPRINT_RE.fullmatch(expected_fingerprint) is not None
        and command_fingerprint(argv) == expected_fingerprint
    )


def _open_regular_marker(logs_fd: int) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(MARKER_NAME, dir_fd=logs_fd, follow_symlinks=False)
    except OSError as exc:
        raise LaunchPayloadError("marker is unavailable") from exc
    if not stat.S_ISREG(before.st_mode):
        raise LaunchPayloadError("marker is not a regular file")
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if type(nonblocking) is not int or nonblocking == 0:
        raise LaunchPayloadError("bounded marker reads are unavailable")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= nonblocking
    try:
        marker_fd = os.open(MARKER_NAME, flags, dir_fd=logs_fd)
    except OSError as exc:
        raise LaunchPayloadError("marker cannot be opened safely") from exc
    try:
        after = os.fstat(marker_fd)
        if not stat.S_ISREG(after.st_mode) or not _same_file(before, after):
            raise LaunchPayloadError("marker changed while it was opened")
        return marker_fd, after
    except LaunchPayloadError:
        with contextlib.suppress(OSError):
            os.close(marker_fd)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(marker_fd)
        raise LaunchPayloadError("marker could not be validated safely") from exc
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(marker_fd)
        raise


def _validate_open_marker_binding(
    logs_fd: int,
    marker_fd: int,
    marker_stat: os.stat_result,
) -> os.stat_result:
    try:
        opened_marker = os.fstat(marker_fd)
        current_marker = os.stat(MARKER_NAME, dir_fd=logs_fd, follow_symlinks=False)
    except OSError as exc:
        raise LaunchPayloadError("marker changed while it was read") from exc
    snapshots = (marker_stat, opened_marker, current_marker)
    if not all(stat.S_ISREG(snapshot.st_mode) for snapshot in snapshots) or not all(
        _same_file(marker_stat, snapshot) for snapshot in snapshots[1:]
    ):
        raise LaunchPayloadError("marker changed while it was read")
    if hasattr(os, "geteuid") and any(snapshot.st_uid != os.geteuid() for snapshot in snapshots):
        raise LaunchPayloadError("marker has an unexpected owner")
    if any(snapshot.st_nlink != 1 for snapshot in snapshots):
        raise LaunchPayloadError("marker has unexpected links")
    return current_marker


def _validate_marker_bindings(
    profile: _OpenedProfile,
    logs_fd: int,
    marker_fd: int,
    marker_stat: os.stat_result,
) -> os.stat_result:
    current_marker = marker_stat
    for _attempt in range(2):
        profile.validate_bindings()
        logs_stat = _validate_open_directory_binding(
            profile.fd,
            "logs",
            logs_fd,
            "marker directory",
        )
        if hasattr(os, "geteuid") and logs_stat.st_uid != os.geteuid():
            raise LaunchPayloadError("marker directory has an unexpected owner")
        current_marker = _validate_open_marker_binding(
            logs_fd,
            marker_fd,
            marker_stat,
        )
    return current_marker


def _confirm_marker_missing(profile: _OpenedProfile, logs_fd: int) -> None:
    for _attempt in range(2):
        profile.validate_bindings()
        _validate_open_directory_binding(
            profile.fd,
            "logs",
            logs_fd,
            "marker directory",
        )
        try:
            os.stat(MARKER_NAME, dir_fd=logs_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LaunchPayloadError("missing marker cannot be confirmed") from exc
        raise LaunchPayloadError("marker appeared while absence was confirmed")
    profile.validate_bindings()
    _validate_open_directory_binding(
        profile.fd,
        "logs",
        logs_fd,
        "marker directory",
    )


def _remove_marker_if_owned_locked(
    profile_path: Path,
    *,
    operation_id: str,
    desired_revision: int,
    pid: int,
    command_fingerprint: str,
    expected_proc_start_fingerprint: str | None | _UnspecifiedProcessStart = (
        _UNSPECIFIED_PROCESS_START
    ),
) -> bool:
    try:
        profile_fd = _open_profile(profile_path)
    except LaunchPayloadError:
        return False
    logs_fd = -1
    quarantine = f".{MARKER_NAME}.cleanup.{pid}.{time.time_ns()}"
    try:
        try:
            logs_fd = _open_logs(profile_fd, create=False)
        except (FileNotFoundError, LaunchPayloadError):
            return False
        try:
            marker_fd, opened_stat = _open_regular_marker(logs_fd)
            try:
                value = _strict_json_object(_read_bounded_file(marker_fd))
            finally:
                os.close(marker_fd)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, LaunchPayloadError):
            return False
        if not _is_owned_runtime_marker(
            value,
            bot_id=profile_path.name,
            operation_id=operation_id,
            desired_revision=desired_revision,
            pid=pid,
            expected_fingerprint=command_fingerprint,
        ):
            return False
        if type(value) is not dict:
            return False
        if (
            not isinstance(expected_proc_start_fingerprint, _UnspecifiedProcessStart)
            and value.get("proc_start_fingerprint") != expected_proc_start_fingerprint
        ):
            return False
        try:
            os.link(
                MARKER_NAME,
                quarantine,
                src_dir_fd=logs_fd,
                dst_dir_fd=logs_fd,
                follow_symlinks=False,
            )
            pinned_stat = os.stat(quarantine, dir_fd=logs_fd, follow_symlinks=False)
            if not stat.S_ISREG(pinned_stat.st_mode) or not _same_file(opened_stat, pinned_stat):
                return False
            current_fd, current_stat = _open_regular_marker(logs_fd)
            os.close(current_fd)
            if not _same_file(opened_stat, current_stat):
                return False
            os.unlink(MARKER_NAME, dir_fd=logs_fd)
            os.fsync(logs_fd)
            return True
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(quarantine, dir_fd=logs_fd)
    except OSError:
        return False
    finally:
        if logs_fd >= 0:
            os.close(logs_fd)
        os.close(profile_fd)


def remove_marker_if_owned(
    profile_path: Path,
    *,
    operation_id: str,
    desired_revision: int,
    pid: int,
    command_fingerprint: str,
    expected_proc_start_fingerprint: str | None | _UnspecifiedProcessStart = (
        _UNSPECIFIED_PROCESS_START
    ),
    lock_timeout_seconds: float = MARKER_PUBLICATION_LOCK_TIMEOUT_SECONDS,
) -> bool:
    try:
        with marker_publication_lock(profile_path, timeout_seconds=lock_timeout_seconds):
            return _remove_marker_if_owned_locked(
                profile_path,
                operation_id=operation_id,
                desired_revision=desired_revision,
                pid=pid,
                command_fingerprint=command_fingerprint,
                expected_proc_start_fingerprint=expected_proc_start_fingerprint,
            )
    except LaunchPayloadError:
        return False


def _process_start_fingerprint() -> str | None:
    if platform.system() == "Linux":
        try:
            raw = Path("/proc/self/stat").read_text(encoding="utf-8")
            fields = raw.rsplit(") ", 1)[1].split()
        except (OSError, UnicodeDecodeError, IndexError):
            return None
        return f"linux:/proc-starttime:{fields[19]}" if len(fields) >= 20 else None
    if platform.system() != "Darwin":
        return None
    try:
        completed = subprocess.run(  # nosec B603
            ["/bin/ps", "-p", str(os.getpid()), "-o", "lstart="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    started = " ".join(completed.stdout.split()) if completed.returncode == 0 else ""
    return f"darwin:ps-lstart:{started}" if started else None


def _parse_fd(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or value.startswith("0"):
        raise LaunchPayloadError("file descriptor arguments must be canonical decimal integers")
    fd = int(value)
    if fd < 3:
        raise LaunchPayloadError("standard descriptors are not accepted")
    try:
        os.fstat(fd)
    except OSError as exc:
        raise LaunchPayloadError("file descriptor is not open") from exc
    return fd


def _exit_failure(payload_fd: int | None, ack_fd: int | None) -> NoReturn:
    for fd in (payload_fd, ack_fd):
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
    with contextlib.suppress(OSError):
        os.write(2, b"gateway launcher failed\n")
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> NoReturn:
    arguments = sys.argv[1:] if argv is None else argv
    payload_fd: int | None = None
    ack_fd: int | None = None
    profile_path: Path | None = None
    marker: dict[str, object] | None = None
    published = False
    try:
        if len(arguments) != 2:
            raise LaunchPayloadError("expected payload and acknowledgment descriptors")
        payload_fd = _parse_fd(arguments[0])
        ack_fd = _parse_fd(arguments[1])
        if payload_fd == ack_fd:
            raise LaunchPayloadError("file descriptors must be distinct")
        raw_payload = _read_payload(payload_fd)
        os.close(payload_fd)
        payload_fd = None
        profile_path, marker, exec_argv, env = _validate_payload(raw_payload)
        marker = dict(marker)
        marker["pid"] = os.getpid()
        marker["started_at"] = time.time()
        start_fingerprint = _process_start_fingerprint()
        if start_fingerprint is not None:
            marker["proc_start_fingerprint"] = start_fingerprint
        with marker_publication_lock(profile_path):
            try:
                _publish_marker(profile_path, marker)
                published = True
                if os.write(ack_fd, b"1") != 1:
                    raise OSError("short acknowledgment write")
                os.close(ack_fd)
                ack_fd = None
                os.execvpe(exec_argv[0], exec_argv, env)  # nosec B606
            except BaseException:
                if published:
                    desired_revision = marker["desired_revision"]
                    if type(desired_revision) is not int:
                        raise LaunchPayloadError("marker revision is invalid") from None
                    marker_process_start = marker.get("proc_start_fingerprint")
                    _remove_marker_if_owned_locked(
                        profile_path,
                        operation_id=str(marker["operation_id"]),
                        desired_revision=desired_revision,
                        pid=os.getpid(),
                        command_fingerprint=str(marker["command_fingerprint"]),
                        expected_proc_start_fingerprint=(
                            marker_process_start if isinstance(marker_process_start, str) else None
                        ),
                    )
                raise
    except BaseException:
        _exit_failure(payload_fd, ack_fd)


if __name__ == "__main__":
    main()
