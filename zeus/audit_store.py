from __future__ import annotations

import ctypes
import errno
import os
import re
import secrets
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from zeus.audit_models import AuditReport
from zeus.audit_report import (
    AuditReportError,
    parse_audit_report,
    render_audit_markdown,
    serialize_audit_report,
)
from zeus.private_io import (
    UnsafeFileError,
    ensure_private_directory,
    inspect_private_directory,
    pin_private_directory,
    read_private_bytes,
)
from zeus.private_io import (
    write_private_bytes_atomic as _write_private_bytes_atomic,
)

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_REPORT_JSON = "report.json"
_REPORT_MARKDOWN = "report.md"
_RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DARWIN_RENAME_EXCL = 0x00000004
_LINUX_RENAME_NOREPLACE = 0x00000001


class AuditStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredAuditArtifacts:
    run_id: str
    json_path: Path
    markdown_path: Path


def _validate_run_id(run_id: object) -> str:
    if type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None:
        raise AuditStoreError("audit run ID must be 32 lowercase hexadecimal characters")
    return run_id


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _directory_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        value = getattr(os, name, None)
        if type(value) is not int or value == 0:
            raise AuditStoreError(f"required POSIX flag {name} is unavailable")
        flags |= value
    return flags


def _validate_directory_snapshot(
    snapshot: os.stat_result,
    *,
    description: str,
) -> None:
    if not stat.S_ISDIR(snapshot.st_mode):
        raise AuditStoreError(f"{description} is not a directory")
    if snapshot.st_uid != os.geteuid():
        raise AuditStoreError(f"{description} has an unexpected owner")
    if stat.S_IMODE(snapshot.st_mode) != _DIRECTORY_MODE:
        raise AuditStoreError(f"{description} does not have private permissions")


def _validate_leaf_snapshot(
    snapshot: os.stat_result,
    *,
    expected_size: int,
) -> None:
    if (
        not stat.S_ISREG(snapshot.st_mode)
        or snapshot.st_uid != os.geteuid()
        or stat.S_IMODE(snapshot.st_mode) != _FILE_MODE
        or snapshot.st_nlink != 1
        or snapshot.st_size != expected_size
    ):
        raise AuditStoreError("staged audit artifact is not a private owned regular file")


def _raise_rename_error(result: int) -> None:
    if result == 0:
        return
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))


def _rename_directory_noreplace(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    platform_name = str(sys.platform)
    if platform_name == "darwin":
        try:
            renameatx_np = libc.renameatx_np
        except AttributeError as exc:
            raise OSError(errno.ENOSYS, "exclusive directory rename is unavailable") from exc
        renameatx_np.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameatx_np.restype = ctypes.c_int
        _raise_rename_error(
            renameatx_np(
                parent_fd,
                source,
                parent_fd,
                destination,
                _DARWIN_RENAME_EXCL,
            )
        )
        return
    if platform_name.startswith("linux"):
        try:
            renameat2 = libc.renameat2
        except AttributeError as exc:
            raise OSError(errno.ENOSYS, "exclusive directory rename is unavailable") from exc
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        _raise_rename_error(
            renameat2(
                parent_fd,
                source,
                parent_fd,
                destination,
                _LINUX_RENAME_NOREPLACE,
            )
        )
        return
    raise OSError(errno.ENOSYS, "exclusive directory rename is unavailable")


def _open_created_staging(
    parent_fd: int,
    staging_name: str,
) -> tuple[int, os.stat_result]:
    created: os.stat_result | None = None
    directory_fd = -1
    try:
        try:
            os.mkdir(staging_name, _DIRECTORY_MODE, dir_fd=parent_fd)
            created = os.lstat(staging_name, dir_fd=parent_fd)
            directory_fd = os.open(staging_name, _directory_flags(), dir_fd=parent_fd)
        except (OSError, TypeError, ValueError) as exc:
            raise AuditStoreError(
                "private audit staging directory could not be created"
            ) from exc
        os.fchmod(directory_fd, _DIRECTORY_MODE)
        opened = os.fstat(directory_fd)
        current = os.lstat(staging_name, dir_fd=parent_fd)
        for snapshot in (created, opened, current):
            _validate_directory_snapshot(snapshot, description="audit staging directory")
        if not (_same_file(created, opened) and _same_file(created, current)):
            raise AuditStoreError("audit staging directory changed while it was opened")
        return directory_fd, opened
    except BaseException:
        if created is not None:
            if directory_fd >= 0:
                _cleanup_owned_staging(
                    parent_fd,
                    staging_name,
                    directory_fd,
                    created,
                    {},
                )
            else:
                _cleanup_owned_empty_staging(parent_fd, staging_name, created)
        if directory_fd >= 0:
            with suppress(OSError):
                os.close(directory_fd)
        raise


def _ensure_private_directory_without_repair(path: Path) -> None:
    for attempt in range(4):
        try:
            ensure_private_directory(path, tighten_existing=False)
            with pin_private_directory(path, tighten=False):
                pass
            return
        except UnsafeFileError as exc:
            if "appeared while it was created" not in str(exc) or attempt == 3:
                raise
    raise AuditStoreError("private directory could not be created")


def _ensure_private_audits_directory(state_dir: Path, audits_dir: Path) -> None:
    try:
        _ensure_private_directory_without_repair(state_dir)
        _ensure_private_directory_without_repair(audits_dir)
    except UnsafeFileError as exc:
        raise AuditStoreError("audit storage hierarchy is unavailable or unsafe") from exc


def _capture_staged_leaf(
    staging_fd: int,
    name: str,
    *,
    expected_size: int,
) -> os.stat_result:
    try:
        snapshot = os.lstat(name, dir_fd=staging_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditStoreError("staged audit artifact could not be inspected") from exc
    _validate_leaf_snapshot(snapshot, expected_size=expected_size)
    return snapshot


def _write_and_capture_staged_leaf(
    path: Path,
    data: bytes,
    max_bytes: int,
    staging_fd: int,
    name: str,
    leaves: dict[str, os.stat_result],
) -> None:
    try:
        _write_private_bytes_atomic(path, data, max_bytes)
        identity = _capture_staged_leaf(
            staging_fd,
            name,
            expected_size=len(data),
        )
    except BaseException:
        if name not in leaves:
            with suppress(AuditStoreError):
                leaves[name] = _capture_staged_leaf(
                    staging_fd,
                    name,
                    expected_size=len(data),
                )
        raise
    leaves[name] = identity


def _validate_staging_binding(
    parent_fd: int,
    staging_name: str,
    staging_fd: int,
    identity: os.stat_result,
) -> None:
    try:
        opened = os.fstat(staging_fd)
        current = os.lstat(staging_name, dir_fd=parent_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditStoreError("audit staging directory binding changed") from exc
    for snapshot in (identity, opened, current):
        _validate_directory_snapshot(snapshot, description="audit staging directory")
    if not (_same_file(identity, opened) and _same_file(identity, current)):
        raise AuditStoreError("audit staging directory binding changed")


def _cleanup_owned_staging(
    parent_fd: int,
    staging_name: str,
    staging_fd: int,
    identity: os.stat_result,
    leaves: dict[str, os.stat_result],
) -> None:
    try:
        opened = os.fstat(staging_fd)
        current = os.lstat(staging_name, dir_fd=parent_fd)
        if not (
            _same_file(identity, opened)
            and _same_file(identity, current)
            and stat.S_ISDIR(opened.st_mode)
            and stat.S_ISDIR(current.st_mode)
            and opened.st_uid == os.geteuid()
            and current.st_uid == os.geteuid()
        ):
            return
    except (OSError, TypeError, ValueError):
        return
    for name, expected in leaves.items():
        try:
            current_leaf = os.lstat(name, dir_fd=staging_fd)
        except (OSError, TypeError, ValueError):
            return
        if not (
            _same_file(expected, current_leaf)
            and stat.S_ISREG(current_leaf.st_mode)
            and current_leaf.st_uid == os.geteuid()
            and stat.S_IMODE(current_leaf.st_mode) == _FILE_MODE
            and current_leaf.st_nlink == 1
        ):
            return
        try:
            os.unlink(name, dir_fd=staging_fd)
        except (OSError, TypeError, ValueError):
            return
    try:
        if os.listdir(staging_fd):
            return
        os.rmdir(staging_name, dir_fd=parent_fd)
    except (OSError, TypeError, ValueError):
        return


def _cleanup_owned_empty_staging(
    parent_fd: int,
    staging_name: str,
    identity: os.stat_result,
) -> None:
    try:
        current = os.lstat(staging_name, dir_fd=parent_fd)
        if not (
            _same_file(identity, current)
            and stat.S_ISDIR(identity.st_mode)
            and stat.S_ISDIR(current.st_mode)
            and identity.st_uid == os.geteuid()
            and current.st_uid == os.geteuid()
        ):
            return
        os.rmdir(staging_name, dir_fd=parent_fd)
    except (OSError, TypeError, ValueError):
        return


def _strict_private_directory_exists(path: Path) -> bool:
    exists = inspect_private_directory(path, missing_ok=True)
    if not exists:
        return False
    with pin_private_directory(path, tighten=False):
        pass
    return True


class AuditStore:
    def __init__(
        self,
        state_dir: Path,
        *,
        max_artifact_bytes: int = 1_048_576,
    ) -> None:
        if not isinstance(state_dir, Path):
            raise TypeError("state_dir must be a pathlib.Path")
        if not state_dir.is_absolute() or state_dir.anchor != "/":
            raise AuditStoreError("state_dir must be an absolute POSIX path")
        if isinstance(max_artifact_bytes, bool) or not isinstance(max_artifact_bytes, int):
            raise TypeError("max_artifact_bytes must be an integer")
        if max_artifact_bytes < 1:
            raise ValueError("max_artifact_bytes must be positive")
        self.state_dir = state_dir
        self.max_artifact_bytes = max_artifact_bytes
        self.audits_dir = state_dir / "audits"

    def _paths(self, run_id: str) -> StoredAuditArtifacts:
        run_id = _validate_run_id(run_id)
        run_dir = self.audits_dir / run_id
        return StoredAuditArtifacts(
            run_id=run_id,
            json_path=run_dir / _REPORT_JSON,
            markdown_path=run_dir / _REPORT_MARKDOWN,
        )

    def install(self, report: AuditReport) -> StoredAuditArtifacts:
        if not isinstance(report, AuditReport):
            raise TypeError("report must be an AuditReport")
        paths = self._paths(report.run_id)
        json_bytes = serialize_audit_report(report)
        markdown_bytes = render_audit_markdown(report).encode("utf-8")
        if (
            len(json_bytes) > self.max_artifact_bytes
            or len(markdown_bytes) > self.max_artifact_bytes
        ):
            raise AuditStoreError("audit report artifact exceeds its byte limit")
        parsed = parse_audit_report(json_bytes, max_bytes=self.max_artifact_bytes)
        if parsed.run_id != report.run_id:
            raise AuditStoreError("serialized audit report run ID changed")
        if render_audit_markdown(parsed).encode("utf-8") != markdown_bytes:
            raise AuditStoreError("audit report Markdown is not deterministic")

        _ensure_private_audits_directory(self.state_dir, self.audits_dir)
        staging_name = f".staging-{report.run_id}-{secrets.token_hex(16)}"
        staging_path = self.audits_dir / staging_name
        with pin_private_directory(self.audits_dir, tighten=False) as audits:
            staging_fd, staging_identity = _open_created_staging(audits.fd, staging_name)
            staging_exists = True
            leaves: dict[str, os.stat_result] = {}
            try:
                json_path = staging_path / _REPORT_JSON
                markdown_path = staging_path / _REPORT_MARKDOWN
                _write_and_capture_staged_leaf(
                    json_path,
                    json_bytes,
                    self.max_artifact_bytes,
                    staging_fd,
                    _REPORT_JSON,
                    leaves,
                )
                _write_and_capture_staged_leaf(
                    markdown_path,
                    markdown_bytes,
                    self.max_artifact_bytes,
                    staging_fd,
                    _REPORT_MARKDOWN,
                    leaves,
                )
                staged_json = read_private_bytes(json_path, self.max_artifact_bytes)
                staged_markdown = read_private_bytes(markdown_path, self.max_artifact_bytes)
                if staged_json != json_bytes or staged_markdown != markdown_bytes:
                    raise AuditStoreError("staged audit artifacts changed during validation")
                staged_report = parse_audit_report(
                    staged_json,
                    max_bytes=self.max_artifact_bytes,
                )
                if (
                    staged_report.run_id != report.run_id
                    or render_audit_markdown(staged_report).encode("utf-8")
                    != staged_markdown
                ):
                    raise AuditStoreError("staged audit artifact pair is inconsistent")
                os.fsync(staging_fd)
                _validate_staging_binding(
                    audits.fd,
                    staging_name,
                    staging_fd,
                    staging_identity,
                )
                audits.validate_at(self.audits_dir)
                try:
                    _rename_directory_noreplace(
                        audits.fd,
                        staging_name,
                        report.run_id,
                    )
                except OSError as exc:
                    if exc.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                        raise AuditStoreError("audit report run already exists") from exc
                    raise AuditStoreError(
                        "audit report directory could not be installed atomically"
                    ) from exc
                staging_exists = False
                installed = os.lstat(report.run_id, dir_fd=audits.fd)
                _validate_directory_snapshot(
                    installed,
                    description="installed audit report directory",
                )
                if not _same_file(staging_identity, installed):
                    raise AuditStoreError("installed audit report directory binding changed")
                os.fsync(audits.fd)
                audits.validate_at(self.audits_dir)
            finally:
                if staging_exists:
                    _cleanup_owned_staging(
                        audits.fd,
                        staging_name,
                        staging_fd,
                        staging_identity,
                        leaves,
                    )
                os.close(staging_fd)
        return paths

    def _read_pair(self, run_id: str) -> tuple[AuditReport, str]:
        paths = self._paths(run_id)
        run_dir = paths.json_path.parent
        try:
            with (
                pin_private_directory(self.state_dir, tighten=False) as state,
                pin_private_directory(self.audits_dir, tighten=False) as audits,
                pin_private_directory(run_dir, tighten=False) as run,
            ):
                json_bytes = read_private_bytes(
                    paths.json_path,
                    self.max_artifact_bytes,
                    tighten=False,
                )
                markdown_bytes = read_private_bytes(
                    paths.markdown_path,
                    self.max_artifact_bytes,
                    tighten=False,
                )
                run.validate_at(run_dir)
                audits.validate_at(self.audits_dir)
                state.validate_at(self.state_dir)
        except UnsafeFileError as exc:
            raise AuditStoreError(
                "stored audit artifact pair is unavailable or unsafe"
            ) from exc
        try:
            report = parse_audit_report(
                json_bytes,
                max_bytes=self.max_artifact_bytes,
            )
        except AuditReportError as exc:
            raise AuditStoreError("stored audit report JSON is invalid") from exc
        if report.run_id != run_id:
            raise AuditStoreError("stored audit report run ID does not match its directory")
        if serialize_audit_report(report) != json_bytes:
            raise AuditStoreError("stored audit report JSON is not canonical")
        expected_markdown = render_audit_markdown(report).encode("utf-8")
        if markdown_bytes != expected_markdown:
            raise AuditStoreError("stored audit report Markdown does not match its JSON")
        try:
            markdown = markdown_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AuditStoreError("stored audit report Markdown is not valid UTF-8") from exc
        return report, markdown

    def list_reports(self) -> tuple[AuditReport, ...]:
        try:
            if not _strict_private_directory_exists(self.state_dir):
                return ()
            if not _strict_private_directory_exists(self.audits_dir):
                return ()
            with (
                pin_private_directory(self.state_dir, tighten=False) as state,
                pin_private_directory(self.audits_dir, tighten=False) as audits,
            ):
                names = tuple(os.listdir(audits.fd))
                run_ids = tuple(sorted(name for name in names if _RUN_ID.fullmatch(name)))
                reports = tuple(self._read_pair(run_id)[0] for run_id in run_ids)
                audits.validate_at(self.audits_dir)
                state.validate_at(self.state_dir)
        except (OSError, TypeError, ValueError, UnsafeFileError) as exc:
            raise AuditStoreError("stored audit reports could not be listed safely") from exc
        return tuple(
            sorted(
                reports,
                key=lambda report: (report.metadata.started_at, report.run_id),
                reverse=True,
            )
        )

    def read_report(self, run_id: str) -> AuditReport:
        return self._read_pair(run_id)[0]

    def read_markdown(self, run_id: str) -> str:
        return self._read_pair(run_id)[1]
