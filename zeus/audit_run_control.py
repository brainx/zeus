from __future__ import annotations

import fcntl
import os
import stat
import sys
import time
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path

from zeus.audit_models import (
    AuditCheck,
    AuditReport,
    AuditStatus,
    CheckDisposition,
)
from zeus.audit_shared import AuditServiceError, _now
from zeus.audit_snapshot import (
    _same_file,
    _same_files,
    _snapshot_open_flags,
)
from zeus.private_io import (
    UnsafeFileError,
    ensure_private_directory,
    pin_private_directory,
)

_RUN_CONTROL_DIRECTORY_MODE = 0o700

_RUN_CONTROL_CLEANUP_SECONDS = 2.0

_RUN_CONTROL_CLEANUP_MAX_ENTRIES = 4096

_RUN_CONTROL_CLEANUP_MAX_DEPTH = 32


@dataclass(frozen=True)
class _AuditRunControl:
    parent_path: Path
    name: str
    parent_identity: os.stat_result
    identity: os.stat_result
    descriptor: int


@dataclass(frozen=True)
class _AuditRunControlCleanup:
    complete: bool
    observation: str


@dataclass
class _AuditRunControlLifecycle:
    handle: _AuditRunControl | None = None
    cleanup: _AuditRunControlCleanup | None = None


@dataclass
class _AuditRunControlCleanupBudget:
    deadline: float
    entries: int = 0


class _AuditRunControlCleanupError(RuntimeError):
    pass


class _AuditRunControlCreationInterrupted(KeyboardInterrupt):
    def __init__(self, cleanup: _AuditRunControlCleanup) -> None:
        super().__init__("audit run control creation was interrupted")
        self.cleanup = cleanup


def _validate_audit_run_control_directory(
    snapshots: tuple[os.stat_result, ...],
    *,
    expected: os.stat_result | None = None,
) -> None:
    if not snapshots or any(
        not stat.S_ISDIR(snapshot.st_mode)
        or snapshot.st_uid != os.geteuid()
        or stat.S_IMODE(snapshot.st_mode) != _RUN_CONTROL_DIRECTORY_MODE
        for snapshot in snapshots
    ):
        raise AuditServiceError("audit run control directory metadata is unsafe")
    if expected is not None and not _same_files((expected, *snapshots)):
        raise AuditServiceError("audit run control directory binding changed")
    if not _same_files(snapshots):
        raise AuditServiceError("audit run control directory binding changed")


def _remove_created_empty_audit_run_control(
    parent_descriptor: int,
    name: str,
    identity: os.stat_result,
) -> bool:
    descriptor = -1
    removed = False
    try:
        current = os.lstat(name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return False
    except (KeyboardInterrupt, OSError, TypeError, ValueError):
        return False
    try:
        _validate_audit_run_control_directory((current,), expected=identity)
        descriptor = os.open(
            name,
            _snapshot_open_flags(directory=True),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        rebound = os.lstat(name, dir_fd=parent_descriptor)
        _validate_audit_run_control_directory(
            (opened, rebound),
            expected=identity,
        )
        with os.scandir(descriptor) as entries:
            if next(entries, None) is not None:
                return False
        _remove_opened_audit_run_control_directory(
            parent_descriptor,
            name,
            descriptor,
            identity,
        )
        removed = True
    except (
        KeyboardInterrupt,
        AuditServiceError,
        _AuditRunControlCleanupError,
        OSError,
        TypeError,
        ValueError,
    ):
        removed = False
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except (KeyboardInterrupt, OSError):
                removed = False
    return removed


def _cleanup_failed_audit_run_control_creation(
    parent_path: Path,
    parent_identity: os.stat_result | None,
    name: str,
    created: bool,
    created_identity: os.stat_result | None,
) -> bool:
    if not created:
        return True
    if created_identity is None:
        return False
    try:
        with pin_private_directory(parent_path, tighten=False) as parent:
            if parent_identity is not None and not _same_files(
                (parent_identity, parent.identity, os.fstat(parent.fd))
            ):
                return False
            if not _remove_created_empty_audit_run_control(
                parent.fd,
                name,
                created_identity,
            ):
                return False
            os.fsync(parent.fd)
            parent.validate_at(parent_path)
            return True
    except (KeyboardInterrupt, OSError, TypeError, ValueError, UnsafeFileError):
        return False


def _create_audit_run_control(
    parent_path: Path,
    control_path: Path,
    run_id: str,
    lifecycle: _AuditRunControlLifecycle,
) -> _AuditRunControl:
    if (
        not isinstance(parent_path, Path)
        or not isinstance(control_path, Path)
        or control_path.parent != parent_path
        or control_path.name != run_id
        or len(run_id) != 32
        or any(character not in "0123456789abcdef" for character in run_id)
    ):
        raise AuditServiceError("audit run control path is invalid")
    parent_identity: os.stat_result | None = None
    creation_attempted = False
    created = False
    created_identity: os.stat_result | None = None
    control_descriptor = -1
    try:
        ensure_private_directory(parent_path)
        with pin_private_directory(parent_path, tighten=False) as parent:
            parent_identity = parent.identity
            creation_attempted = True
            os.mkdir(run_id, _RUN_CONTROL_DIRECTORY_MODE, dir_fd=parent.fd)
            created = True
            created_identity = os.lstat(run_id, dir_fd=parent.fd)
            _validate_audit_run_control_directory((created_identity,))
            control_descriptor = os.open(
                run_id,
                _snapshot_open_flags(directory=True),
                dir_fd=parent.fd,
            )
            opened = os.fstat(control_descriptor)
            current = os.lstat(run_id, dir_fd=parent.fd)
            _validate_audit_run_control_directory(
                (opened, current),
                expected=created_identity,
            )
            os.fchmod(control_descriptor, _RUN_CONTROL_DIRECTORY_MODE)
            final_opened = os.fstat(control_descriptor)
            final_current = os.lstat(run_id, dir_fd=parent.fd)
            _validate_audit_run_control_directory(
                (final_opened, final_current),
                expected=created_identity,
            )
            parent.validate_at(parent_path)
            handle = _AuditRunControl(
                parent_path=parent_path,
                name=run_id,
                parent_identity=parent.identity,
                identity=final_opened,
                descriptor=control_descriptor,
            )
            lifecycle.handle = handle
            return handle
    except KeyboardInterrupt as exc:
        if lifecycle.handle is not None:
            raise
        descriptor_closed = True
        if control_descriptor >= 0:
            try:
                os.close(control_descriptor)
            except (KeyboardInterrupt, OSError):
                descriptor_closed = False
        cleanup_verified = descriptor_closed and _cleanup_failed_audit_run_control_creation(
            parent_path,
            parent_identity,
            run_id,
            creation_attempted,
            created_identity,
        )
        cleanup = _AuditRunControlCleanup(
            cleanup_verified,
            (
                "audit run control directory was removed after interrupted creation"
                if cleanup_verified
                else (
                    "audit run control directory cleanup after interrupted creation "
                    "could not be verified"
                )
            ),
        )
        lifecycle.cleanup = cleanup
        raise _AuditRunControlCreationInterrupted(cleanup) from exc
    except (AuditServiceError, OSError, TypeError, ValueError, UnsafeFileError) as exc:
        if control_descriptor >= 0:
            with suppress(OSError):
                os.close(control_descriptor)
        cleanup_verified = _cleanup_failed_audit_run_control_creation(
            parent_path,
            parent_identity,
            run_id,
            created,
            created_identity,
        )
        if not cleanup_verified:
            raise AuditServiceError(
                "audit run control creation failed and cleanup could not be verified"
            ) from exc
        raise AuditServiceError("audit run control directory could not be created safely") from exc


def _check_audit_run_control_cleanup_budget(budget: _AuditRunControlCleanupBudget) -> None:
    if time.monotonic() >= budget.deadline:
        raise _AuditRunControlCleanupError("audit run control cleanup exceeded its deadline")


def _audit_run_control_entry_names(
    descriptor: int,
    budget: _AuditRunControlCleanupBudget,
) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                _check_audit_run_control_cleanup_budget(budget)
                budget.entries += 1
                if budget.entries > _RUN_CONTROL_CLEANUP_MAX_ENTRIES:
                    raise _AuditRunControlCleanupError(
                        "audit run control cleanup exceeded its entry limit"
                    )
                name = entry.name
                if (
                    not isinstance(name, str)
                    or name in {"", ".", ".."}
                    or "/" in name
                    or "\x00" in name
                ):
                    raise _AuditRunControlCleanupError(
                        "audit run control directory contains an invalid entry"
                    )
                names.append(name)
    except _AuditRunControlCleanupError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise _AuditRunControlCleanupError(
            "audit run control directory could not be enumerated"
        ) from exc
    return tuple(sorted(names))


def _confirm_audit_run_control_entry_missing(parent_descriptor: int, name: str) -> None:
    try:
        os.lstat(name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return
    except (OSError, TypeError, ValueError) as exc:
        raise _AuditRunControlCleanupError(
            "audit run control entry removal could not be verified"
        ) from exc
    raise _AuditRunControlCleanupError("audit run control entry binding changed")


def _remove_opened_audit_run_control_directory(
    parent_descriptor: int,
    name: str,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(name, dir_fd=parent_descriptor)
    except (OSError, TypeError, ValueError) as exc:
        raise _AuditRunControlCleanupError("audit run control directory binding changed") from exc
    if (
        not _same_files((expected, opened, current))
        or not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or opened.st_uid != os.geteuid()
        or current.st_uid != os.geteuid()
    ):
        raise _AuditRunControlCleanupError("audit run control directory binding changed")
    try:
        os.rmdir(name, dir_fd=parent_descriptor)
    except (OSError, TypeError, ValueError) as exc:
        raise _AuditRunControlCleanupError(
            "audit run control directory could not be removed"
        ) from exc
    _confirm_audit_run_control_entry_missing(parent_descriptor, name)
    try:
        unlinked = os.fstat(descriptor)
    except (OSError, TypeError, ValueError) as exc:
        raise _AuditRunControlCleanupError(
            "audit run control directory removal could not be verified"
        ) from exc
    if not _same_file(expected, unlinked):
        raise _AuditRunControlCleanupError(
            "audit run control directory identity changed during removal"
        )
    identity_unlinked = unlinked.st_nlink == 0
    if not identity_unlinked and sys.platform == "darwin":
        try:
            command = fcntl.F_GETPATH
            first_value = fcntl.fcntl(descriptor, command, b"\0" * 1024)
            first_path = Path(os.fsdecode(first_value.split(b"\0", 1)[0]))
            if not first_path.is_absolute():
                raise ValueError("descriptor path is not absolute")
            try:
                first_path.lstat()
            except FileNotFoundError:
                second_value = fcntl.fcntl(descriptor, command, b"\0" * 1024)
                second_path = Path(os.fsdecode(second_value.split(b"\0", 1)[0]))
                if second_path == first_path:
                    try:
                        second_path.lstat()
                    except FileNotFoundError:
                        identity_unlinked = True
        except (OSError, TypeError, ValueError):
            identity_unlinked = False
    if not identity_unlinked:
        raise _AuditRunControlCleanupError(
            "audit run control directory identity remained linked after removal"
        )


def _remove_audit_run_control_entries(
    descriptor: int,
    *,
    depth: int,
    budget: _AuditRunControlCleanupBudget,
) -> None:
    _check_audit_run_control_cleanup_budget(budget)
    if depth > _RUN_CONTROL_CLEANUP_MAX_DEPTH:
        raise _AuditRunControlCleanupError("audit run control cleanup exceeded its depth limit")
    for name in _audit_run_control_entry_names(descriptor, budget):
        _check_audit_run_control_cleanup_budget(budget)
        try:
            before = os.lstat(name, dir_fd=descriptor)
        except (OSError, TypeError, ValueError) as exc:
            raise _AuditRunControlCleanupError(
                "audit run control entry could not be inspected"
            ) from exc
        if stat.S_ISLNK(before.st_mode):
            raise _AuditRunControlCleanupError(
                "audit run control directory contains a symbolic link"
            )
        if before.st_uid != os.geteuid():
            raise _AuditRunControlCleanupError("audit run control entry has an unexpected owner")
        if stat.S_ISDIR(before.st_mode):
            child_descriptor = -1
            try:
                child_descriptor = os.open(
                    name,
                    _snapshot_open_flags(directory=True),
                    dir_fd=descriptor,
                )
                opened = os.fstat(child_descriptor)
                current = os.lstat(name, dir_fd=descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or not _same_files((before, opened, current))
                    or opened.st_uid != os.geteuid()
                ):
                    raise _AuditRunControlCleanupError(
                        "audit run control directory binding changed"
                    )
                _remove_audit_run_control_entries(
                    child_descriptor,
                    depth=depth + 1,
                    budget=budget,
                )
                final_opened = os.fstat(child_descriptor)
                final_current = os.lstat(name, dir_fd=descriptor)
                if not _same_files((before, opened, final_opened, final_current)):
                    raise _AuditRunControlCleanupError(
                        "audit run control directory binding changed"
                    )
                _remove_opened_audit_run_control_directory(
                    descriptor,
                    name,
                    child_descriptor,
                    before,
                )
            except _AuditRunControlCleanupError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise _AuditRunControlCleanupError(
                    "audit run control directory could not be removed safely"
                ) from exc
            finally:
                if child_descriptor >= 0:
                    try:
                        os.close(child_descriptor)
                    except OSError as exc:
                        raise _AuditRunControlCleanupError(
                            "audit run control directory descriptor could not be closed"
                        ) from exc
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise _AuditRunControlCleanupError(
                "audit run control directory contains an unsupported entry"
            )
        try:
            current = os.lstat(name, dir_fd=descriptor)
            if not _same_file(before, current):
                raise _AuditRunControlCleanupError("audit run control entry binding changed")
            os.unlink(name, dir_fd=descriptor)
        except _AuditRunControlCleanupError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise _AuditRunControlCleanupError(
                "audit run control entry could not be removed"
            ) from exc
        _confirm_audit_run_control_entry_missing(descriptor, name)


def _cleanup_audit_run_control(control: _AuditRunControl) -> _AuditRunControlCleanup:
    result = _AuditRunControlCleanup(
        False,
        "audit run control directory cleanup could not be verified",
    )
    try:
        with pin_private_directory(control.parent_path, tighten=False) as parent:
            if not _same_files(
                (
                    control.parent_identity,
                    parent.identity,
                    os.fstat(parent.fd),
                )
            ):
                raise _AuditRunControlCleanupError("audit run control parent binding changed")
            opened = os.fstat(control.descriptor)
            current = os.lstat(control.name, dir_fd=parent.fd)
            try:
                _validate_audit_run_control_directory(
                    (opened, current),
                    expected=control.identity,
                )
            except AuditServiceError as exc:
                raise _AuditRunControlCleanupError(str(exc)) from exc
            parent.validate_at(control.parent_path)
            budget = _AuditRunControlCleanupBudget(
                deadline=time.monotonic() + _RUN_CONTROL_CLEANUP_SECONDS
            )
            _remove_audit_run_control_entries(
                control.descriptor,
                depth=0,
                budget=budget,
            )
            _check_audit_run_control_cleanup_budget(budget)
            final_opened = os.fstat(control.descriptor)
            final_current = os.lstat(control.name, dir_fd=parent.fd)
            try:
                _validate_audit_run_control_directory(
                    (final_opened, final_current),
                    expected=control.identity,
                )
            except AuditServiceError as exc:
                raise _AuditRunControlCleanupError(str(exc)) from exc
            if _audit_run_control_entry_names(control.descriptor, budget):
                raise _AuditRunControlCleanupError("audit run control directory remained nonempty")
            _remove_opened_audit_run_control_directory(
                parent.fd,
                control.name,
                control.descriptor,
                control.identity,
            )
            os.fsync(parent.fd)
            parent.validate_at(control.parent_path)
            result = _AuditRunControlCleanup(
                True,
                "audit run control directory was removed",
            )
    except _AuditRunControlCleanupError as exc:
        result = _AuditRunControlCleanup(False, str(exc))
    except (KeyboardInterrupt, OSError, TypeError, ValueError, UnsafeFileError):
        result = _AuditRunControlCleanup(
            False,
            "audit run control directory could not be removed safely",
        )
    finally:
        try:
            os.close(control.descriptor)
        except (KeyboardInterrupt, OSError):
            result = _AuditRunControlCleanup(
                False,
                "audit run control directory descriptor could not be closed",
            )
    return result


def _retain_audit_run_control_after_incomplete_cleanup(
    control: _AuditRunControl,
    *,
    observation: str = (
        "audit run control directory was retained because process/container cleanup was incomplete"
    ),
) -> _AuditRunControlCleanup:
    try:
        os.close(control.descriptor)
    except (KeyboardInterrupt, OSError):
        return _AuditRunControlCleanup(
            False,
            "audit run control directory descriptor could not be closed",
        )
    return _AuditRunControlCleanup(False, observation)


def _with_audit_run_control_cleanup(
    report: AuditReport,
    cleanup: _AuditRunControlCleanup,
) -> AuditReport:
    check = AuditCheck(
        "control_cleanup",
        CheckDisposition.passed if cleanup.complete else CheckDisposition.failed,
        0.0,
        cleanup.observation,
    )
    checks = tuple(sorted((*report.checks, check), key=lambda item: item.name))
    metadata = replace(report.metadata, finished_at=_now())
    if cleanup.complete:
        return replace(report, metadata=metadata, checks=checks)
    reason = "audit control directory cleanup was incomplete"
    reasons = report.completeness.reasons
    if reason not in reasons:
        reasons = (*reasons, reason)
    status = AuditStatus.partial if report.status is AuditStatus.completed else report.status
    if report.status is AuditStatus.completed:
        metadata = replace(metadata, termination_reason="control_cleanup_failed")
    return replace(
        report,
        status=status,
        metadata=metadata,
        checks=checks,
        completeness=replace(
            report.completeness,
            complete=False,
            reasons=reasons,
        ),
    )
