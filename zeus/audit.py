"""Host-local composition of the bounded native repository audit components."""

from __future__ import annotations

import codecs
import fcntl
import hashlib
import math
import os
import secrets
import shutil
import stat
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from zeus import __version__
from zeus.audit_config import AuditConfigError, load_audit_config
from zeus.audit_container import AuditContainerError, AuditContainerRuntime, PreparedAuditContainer
from zeus.audit_docker_broker import (
    HERMES_VERSION,
    AuditDockerBrokerError,
    install_audit_docker_broker,
)
from zeus.audit_doctor import AuditDoctorCheck, AuditDoctorReport, run_audit_doctor
from zeus.audit_models import (
    AuditCheck,
    AuditCompleteness,
    AuditConfig,
    AuditMetadata,
    AuditReport,
    AuditStatus,
    CheckDisposition,
    ModelAuditResult,
    SkippedContent,
)
from zeus.audit_profile import (
    AuditProfile,
    AuditProfileError,
    build_audit_profile,
    render_audit_profile_config,
)
from zeus.audit_report import AuditReportError, build_audit_report, validate_model_output
from zeus.audit_runner import AuditRunner, AuditRunnerError, AuditRunnerOutcome
from zeus.audit_store import AuditStore, AuditStoreError
from zeus.audit_workspace import (
    GIT_HARDENING_ARGUMENTS,
    AuditWorkspace,
    AuditWorkspaceError,
    MaterializedSnapshot,
    RepositoryLocation,
    audit_git_environment,
)
from zeus.config import Settings
from zeus.private_io import (
    UnsafeFileError,
    ensure_private_directory,
    pin_private_directory,
    read_private_bytes,
    write_private_bytes_atomic,
)
from zeus.process_lock import BotProcessLock, LockTimeoutError


class AuditServiceError(RuntimeError):
    pass


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


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _executable(name: str) -> Path:
    resolved = shutil.which(name)
    if resolved is None:
        raise AuditServiceError(f"required executable is unavailable: {name}")
    try:
        candidate = Path(resolved).resolve(strict=True)
    except OSError as exc:
        raise AuditServiceError(f"required executable is unavailable: {name}") from exc
    if not candidate.is_absolute() or not candidate.is_file():
        raise AuditServiceError(f"required executable is unavailable: {name}")
    return candidate


def _status_for_outcome(outcome: AuditRunnerOutcome) -> AuditStatus:
    if outcome is AuditRunnerOutcome.completed:
        return AuditStatus.completed
    if outcome is AuditRunnerOutcome.cancelled:
        return AuditStatus.cancelled
    if outcome is AuditRunnerOutcome.cleanup_failed:
        return AuditStatus.partial
    return AuditStatus.failed


def snapshot_source_line_counts(
    snapshot: MaterializedSnapshot,
    *,
    deadline: float | None = None,
) -> dict[str, int]:
    """Return line counts from manifest-bound UTF-8 regular snapshot files."""
    _check_snapshot_deadline(deadline)
    directory_flags = _snapshot_open_flags(directory=True)
    file_flags = _snapshot_open_flags(directory=False)
    try:
        _check_snapshot_deadline(deadline)
        root_before = os.lstat(snapshot.root)
        root_descriptor = os.open(snapshot.root, directory_flags)
    except (OSError, TypeError, ValueError) as exc:
        raise AuditServiceError("snapshot source root could not be opened safely") from exc
    counts: dict[str, int] = {}
    seen: set[str] = set()
    try:
        root_opened = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_before.st_mode) or not _same_file(root_before, root_opened):
            raise AuditServiceError("snapshot source root binding changed")
        for entry in snapshot.manifest:
            _check_snapshot_deadline(deadline)
            if entry.path in seen:
                raise AuditServiceError("snapshot source manifest contains duplicate paths")
            seen.add(entry.path)
            if entry.is_symlink:
                continue
            counts.update(
                _snapshot_entry_line_count(
                    root_descriptor,
                    entry,
                    directory_flags=directory_flags,
                    file_flags=file_flags,
                    deadline=deadline,
                )
            )
        _check_snapshot_deadline(deadline)
        root_after = os.fstat(root_descriptor)
        root_current = os.lstat(snapshot.root)
        if not _same_files((root_before, root_opened, root_after, root_current)):
            raise AuditServiceError("snapshot source root binding changed")
    except AuditServiceError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise AuditServiceError("snapshot source content could not be read safely") from exc
    finally:
        with suppress(OSError):
            os.close(root_descriptor)
    return counts


def _check_snapshot_deadline(deadline: float | None) -> None:
    if deadline is None:
        return
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
        or time.monotonic() >= deadline
    ):
        raise AuditServiceError("snapshot source deadline expired")


def _snapshot_open_flags(*, directory: bool) -> int:
    flags = 0
    for name, allow_zero in (
        ("O_RDONLY", True),
        ("O_NOFOLLOW", False),
        ("O_CLOEXEC", False),
        ("O_NONBLOCK", False),
    ):
        value = getattr(os, name, None)
        if type(value) is not int or (not allow_zero and value == 0):
            raise AuditServiceError(f"snapshot source requires POSIX flag {name}")
        flags |= value
    if directory:
        value = getattr(os, "O_DIRECTORY", None)
        if type(value) is not int or value == 0:
            raise AuditServiceError("snapshot source requires POSIX flag O_DIRECTORY")
        flags |= value
    return flags


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _same_files(results: tuple[os.stat_result, ...]) -> bool:
    return all(_same_file(results[0], result) for result in results[1:])


def _snapshot_entry_line_count(
    root_descriptor: int,
    entry: object,
    *,
    directory_flags: int,
    file_flags: int,
    deadline: float | None,
) -> dict[str, int]:
    from zeus.audit_workspace import SnapshotManifestEntry

    if not isinstance(entry, SnapshotManifestEntry):
        raise AuditServiceError("snapshot source manifest entry is invalid")
    components = entry.path.split("/")
    if (
        not components
        or any(component in {"", ".", ".."} or "\x00" in component for component in components)
        or isinstance(entry.size, bool)
        or not isinstance(entry.size, int)
        or entry.size < 0
        or not isinstance(entry.sha256, str)
        or len(entry.sha256) != 64
        or any(character not in "0123456789abcdef" for character in entry.sha256)
    ):
        raise AuditServiceError("snapshot source manifest entry is invalid")

    descriptors = [os.dup(root_descriptor)]
    directory_bindings: list[tuple[int, str, int, os.stat_result]] = []
    file_descriptor = -1
    try:
        for component in components[:-1]:
            _check_snapshot_deadline(deadline)
            parent = descriptors[-1]
            before = os.lstat(component, dir_fd=parent)
            child = os.open(component, directory_flags, dir_fd=parent)
            opened = os.fstat(child)
            current = os.lstat(component, dir_fd=parent)
            if not stat.S_ISDIR(before.st_mode) or not _same_files((before, opened, current)):
                raise AuditServiceError("snapshot source directory binding changed")
            directory_bindings.append((parent, component, child, opened))
            descriptors.append(child)

        parent = descriptors[-1]
        name = components[-1]
        before = os.lstat(name, dir_fd=parent)
        file_descriptor = os.open(name, file_flags, dir_fd=parent)
        opened = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_file(before, opened)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != entry.mode
            or before.st_size != entry.size
        ):
            raise AuditServiceError("snapshot source metadata does not match its manifest")

        digest = hashlib.sha256()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        text_valid = True
        contains_binary_control = False
        newline_count = 0
        last_byte: int | None = None
        remaining = entry.size
        while remaining:
            _check_snapshot_deadline(deadline)
            chunk = os.read(file_descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise AuditServiceError("snapshot source size changed while it was read")
            if len(chunk) > remaining:
                raise AuditServiceError("snapshot source exceeded its manifest size")
            remaining -= len(chunk)
            digest.update(chunk)
            newline_count += chunk.count(b"\n")
            last_byte = chunk[-1]
            contains_binary_control = contains_binary_control or any(
                (byte < 0x20 and byte not in {0x09, 0x0A, 0x0D}) or byte == 0x7F for byte in chunk
            )
            if text_valid:
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeDecodeError:
                    text_valid = False
        if os.read(file_descriptor, 1):
            raise AuditServiceError("snapshot source exceeded its manifest size")
        _check_snapshot_deadline(deadline)
        if text_valid:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                text_valid = False

        after = os.fstat(file_descriptor)
        current = os.lstat(name, dir_fd=parent)
        if (
            not _same_files((before, opened, after, current))
            or after.st_size != entry.size
            or current.st_size != entry.size
            or stat.S_IMODE(current.st_mode) != entry.mode
        ):
            raise AuditServiceError("snapshot source binding changed while it was read")
        for directory_parent, component, descriptor, expected in directory_bindings:
            if not _same_files(
                (
                    expected,
                    os.fstat(descriptor),
                    os.lstat(component, dir_fd=directory_parent),
                )
            ):
                raise AuditServiceError("snapshot source directory binding changed")
        if digest.hexdigest() != entry.sha256:
            raise AuditServiceError("snapshot source digest does not match its manifest")
        if not text_valid or contains_binary_control or entry.size == 0:
            return {}
        return {
            entry.path: newline_count + (1 if last_byte != ord("\n") else 0),
        }
    finally:
        if file_descriptor >= 0:
            with suppress(OSError):
                os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def install_audit_profile(hermes_home: Path, profile_name: str, profile: AuditProfile) -> Path:
    """Install the one-shot sealed profile under the exact name passed to Hermes."""
    if not profile_name.startswith("audit-") or len(profile_name) != len("audit-") + 32:
        raise AuditServiceError("audit profile name is invalid")
    if not all(
        character in "0123456789abcdef" for character in profile_name.removeprefix("audit-")
    ):
        raise AuditServiceError("audit profile name is invalid")
    profile_dir = hermes_home / "profiles" / profile_name
    ensure_private_directory(profile_dir)
    config_path = profile_dir / "config.yaml"
    config = render_audit_profile_config(profile)
    write_private_bytes_atomic(config_path, config, len(config), replace=False)
    if read_private_bytes(config_path, len(config), tighten=False) != config:
        raise AuditServiceError("installed audit profile configuration changed")
    return profile_dir


def _with_cleanup_completeness(
    model_result: ModelAuditResult,
    *,
    cleanup_complete: bool,
) -> ModelAuditResult:
    if cleanup_complete:
        return model_result
    return replace(
        model_result,
        completeness=AuditCompleteness(
            complete=False,
            rejected_findings=model_result.completeness.rejected_findings,
            truncated_findings=model_result.completeness.truncated_findings,
            reasons=(
                *model_result.completeness.reasons,
                "audit cleanup was incomplete",
            ),
        ),
    )


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


class AuditService:
    def __init__(
        self,
        *,
        workspace: AuditWorkspace,
        location: RepositoryLocation,
        settings: Settings,
        env: Mapping[str, str],
        started_monotonic: float,
        deadline: float,
    ) -> None:
        self.workspace = workspace
        self.location = location
        self.settings = settings
        self.env = dict(env)
        self.started_monotonic = started_monotonic
        self.deadline = deadline

    @classmethod
    def from_cwd(
        cls,
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> AuditService:
        source_env = dict(os.environ if env is None else env)
        started_monotonic = time.monotonic()
        deadline = started_monotonic + 3600
        workspace = AuditWorkspace()
        location = workspace.discover(Path.cwd() if cwd is None else cwd, deadline=deadline)
        configured_state = source_env.get("ZEUS_STATE_DIR")
        source_env["ZEUS_STATE_DIR"] = (
            configured_state if configured_state else str(location.root / ".zeus")
        )
        settings = Settings.from_env(source_env, include_dotenv=False)
        return cls(
            workspace=workspace,
            location=location,
            settings=settings,
            env=source_env,
            started_monotonic=started_monotonic,
            deadline=deadline,
        )

    def doctor(self) -> AuditDoctorReport:
        config = None
        with suppress(AuditConfigError, OSError, TypeError, ValueError, UnsafeFileError):
            config = load_audit_config(self.settings.state_dir)
        report = run_audit_doctor(
            workspace=self.workspace,
            location=self.location,
            settings=self.settings,
            env=self.env,
            deadline=self.deadline,
            config=config,
        )
        try:
            self._validate_state_path()
        except AuditServiceError as exc:
            state_check = AuditDoctorCheck("state_repository", False, str(exc))
        else:
            state_check = AuditDoctorCheck(
                "state_repository",
                True,
                "state path is outside the repository or ignored and untracked",
            )
        return AuditDoctorReport((*report.checks, state_check))

    def _report(
        self,
        *,
        run_id: str,
        status: AuditStatus,
        started_at: str,
        checks: tuple[AuditCheck, ...],
        model_result: ModelAuditResult,
        termination_reason: str | None,
        config: AuditConfig | None = None,
        skipped_content: tuple[SkippedContent, ...] = (),
    ) -> AuditReport:
        metadata = AuditMetadata(
            zeus_version=__version__,
            hermes_version=HERMES_VERSION,
            skill_version="1.0.0",
            image_digest=config.image if config is not None else None,
            target_commit=self.location.head,
            started_at=started_at,
            finished_at=_now(),
            termination_reason=termination_reason,
            provider=config.provider if config is not None else None,
            model=config.model if config is not None else None,
            worktree_changes_excluded=True,
        )
        return build_audit_report(
            run_id=run_id,
            repository_id=self.location.repository_id,
            status=status,
            metadata=metadata,
            checks=checks,
            skipped_content=skipped_content,
            model_result=model_result,
        )

    def _empty_result(
        self,
        summary: str,
        *,
        complete: bool,
        reason: str | None = None,
    ) -> ModelAuditResult:
        return ModelAuditResult(
            summary=summary,
            findings=(),
            skipped_checks=(),
            checks=(),
            completeness=AuditCompleteness(
                complete=complete,
                reasons=() if reason is None else (reason,),
            ),
        )

    def _validate_state_path(self, *, deadline: float | None = None) -> None:
        """Allow in-repository state only when Git says it is ignored and untracked."""
        try:
            relative = self.settings.state_dir.relative_to(self.location.root)
        except ValueError:
            return
        if relative == Path("."):
            raise AuditServiceError("audit state directory cannot be the repository root")
        pathspec = relative.as_posix()
        if any(component.startswith(":") for component in relative.parts):
            raise AuditServiceError("audit state path contains unsupported Git pathspec syntax")
        probe_run_id = "0" * 32
        ignored_paths = (
            pathspec.rstrip("/") + "/",
            f"{pathspec}/audit/config.json",
            f"{pathspec}/audit/runs/{probe_run_id}/control",
            f"{pathspec}/locks/audits/{self.location.repository_id}.lock",
            f"{pathspec}/audits/{probe_run_id}/report.json",
        )
        git = str(self.workspace._git_executable)
        base = (git, *GIT_HARDENING_ARGUMENTS, "-C", str(self.location.root))
        environment = audit_git_environment()
        active_deadline = self.deadline if deadline is None else deadline

        def remaining_timeout() -> float:
            timeout = min(30.0, active_deadline - time.monotonic())
            if timeout <= 0:
                raise AuditServiceError("audit state path deadline expired")
            return timeout

        try:
            tracked = subprocess.run(  # nosec B603
                (*base, "ls-files", "--error-unmatch", "--", pathspec),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                shell=False,
                check=False,
                timeout=remaining_timeout(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AuditServiceError("audit state path could not be checked safely") from exc
        if tracked.returncode == 0:
            raise AuditServiceError("in-repository audit state path is tracked")
        if tracked.returncode not in {0, 1}:
            raise AuditServiceError("in-repository audit state path must be ignored and untracked")
        try:
            self.workspace.committed_ignore_matches(
                self.location,
                state_relative=relative,
                ignored_paths=ignored_paths,
                deadline=active_deadline,
            )
        except AuditWorkspaceError as exc:
            raise AuditServiceError(
                "in-repository audit state path must be ignored and untracked"
            ) from exc

    def run(self) -> AuditReport:
        started_at = _now()
        try:
            self.workspace.revalidate(self.location, deadline=self.deadline)
            self._validate_state_path(deadline=self.deadline)
            ensure_private_directory(self.settings.state_dir)
            config = load_audit_config(self.settings.state_dir)
        except (
            AuditWorkspaceError,
            AuditConfigError,
            OSError,
            TypeError,
            ValueError,
            UnsafeFileError,
        ) as exc:
            raise AuditServiceError("audit pre-run validation failed") from exc

        active_deadline = min(
            self.deadline,
            self.started_monotonic + config.limits.overall_seconds,
        )
        store = AuditStore(self.settings.state_dir, max_artifact_bytes=config.limits.artifact_bytes)
        lock_path = (
            self.settings.state_dir / "locks" / "audits" / f"{self.location.repository_id}.lock"
        )
        try:
            with BotProcessLock(lock_path, timeout_seconds=0):
                return self._run_locked(store, config, active_deadline, started_at)
        except LockTimeoutError as exc:
            raise AuditServiceError("an audit is already running for this repository") from exc

    def _run_locked(
        self,
        store: AuditStore,
        config: AuditConfig,
        deadline: float,
        started_at: str,
    ) -> AuditReport:
        run_id = secrets.token_hex(16)
        checks: list[AuditCheck] = []
        try:
            self.workspace.revalidate(self.location, deadline=deadline)
            self._validate_state_path(deadline=deadline)
        except AuditWorkspaceError as exc:
            raise AuditServiceError("repository changed while waiting for audit lock") from exc

        doctor = run_audit_doctor(
            workspace=self.workspace,
            location=self.location,
            settings=self.settings,
            env=self.env,
            deadline=deadline,
            config=config,
        )
        for check in doctor.checks:
            checks.append(
                AuditCheck(
                    check.name,
                    CheckDisposition.passed if check.ok else CheckDisposition.failed,
                    0.0,
                    check.observation,
                )
            )
        if not doctor.ok:
            report = self._report(
                run_id=run_id,
                status=AuditStatus.blocked,
                started_at=started_at,
                checks=tuple(checks),
                model_result=self._empty_result(
                    "Audit preflight was blocked.",
                    complete=False,
                    reason="audit preflight failed",
                ),
                termination_reason="audit preflight failed",
                config=config,
            )
            self._validate_state_path(deadline=deadline)
            store.install(report)
            return report

        control_parent = self.settings.state_dir / "audit" / "runs"
        control = control_parent / run_id
        control_lifecycle = _AuditRunControlLifecycle()
        control_removal_safe = False
        control_retention_observation = (
            "audit run control directory was retained because process/container cleanup "
            "was incomplete"
        )
        prepared: PreparedAuditContainer | None = None
        runtime: AuditContainerRuntime | None = None
        external_setup_started = False
        try:
            _create_audit_run_control(
                control_parent,
                control,
                run_id,
                control_lifecycle,
            )
            for directory in (control / "home", control / "hermes", control / "launch"):
                ensure_private_directory(directory)
            docker = _executable("docker")
            hermes = _executable(self.settings.hermes_bin)
            runtime = AuditContainerRuntime(docker, control)
            temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
            with tempfile.TemporaryDirectory(
                prefix="zeus-audit-snapshot-",
                dir=temporary_root,
            ) as temporary:
                snapshot = self.workspace.materialize(
                    self.workspace.inspect(self.location, deadline=deadline),
                    Path(temporary) / "snapshot",
                    exclude_paths=config.exclude_paths,
                    limits=config.limits,
                    deadline=deadline,
                )
                self.workspace.validate_snapshot(snapshot, deadline=deadline)
                source_line_counts = snapshot_source_line_counts(snapshot, deadline=deadline)
                external_setup_started = True
                prepared = runtime.prepare(
                    run_id=run_id,
                    snapshot=snapshot,
                    image_ref=config.image,
                    limits=config.limits,
                    deadline=deadline,
                )
            broker = install_audit_docker_broker(
                prepared,
                docker_executable=docker,
                limits=config.limits,
                deadline=deadline,
                python_executable=Path(sys.executable).resolve(),
            )
            profile = build_audit_profile(config)
            install_audit_profile(control / "hermes", prepared.profile_name, profile)
            runner = AuditRunner(hermes)
            result = runner.run(
                profile_name=prepared.profile_name,
                prompt=profile.prompt,
                config=config,
                control_dir=control,
                broker_executable=broker,
                broker_state_path=prepared.state_path,
                deadline=deadline,
                source_env=self.env,
                validate_output=lambda data: validate_model_output(
                    data,
                    run_id=run_id,
                    allowed_categories=config.categories,
                    source_line_counts=source_line_counts,
                    checks=tuple(checks),
                    configured_check_names=tuple(
                        command.name for command in config.suggested_commands
                    ),
                    limits=config.limits,
                ),
            )
            control_removal_safe = result.cleanup_complete
            if isinstance(result.model_result, ModelAuditResult):
                model_result = result.model_result
                checks.extend(model_result.checks)
            else:
                model_result = self._empty_result(
                    result.diagnostic or "Audit did not produce a valid result.",
                    complete=False,
                    reason=result.outcome.value,
                )
            model_result = _with_cleanup_completeness(
                model_result,
                cleanup_complete=result.cleanup_complete,
            )
            checks.append(
                AuditCheck(
                    "audit_runner",
                    (
                        CheckDisposition.passed
                        if result.outcome is AuditRunnerOutcome.completed
                        else CheckDisposition.failed
                    ),
                    0.0,
                    result.diagnostic or result.outcome.value,
                )
            )
            report = self._report(
                run_id=run_id,
                status=_status_for_outcome(result.outcome),
                started_at=started_at,
                checks=tuple(checks),
                model_result=model_result,
                termination_reason=None
                if result.outcome is AuditRunnerOutcome.completed
                else result.outcome.value,
                config=config,
                skipped_content=snapshot.skipped_content,
            )
        except KeyboardInterrupt as exc:
            cleanup_reason = ""
            control_retention_observation = (
                "audit run control directory was retained because external resource cleanup "
                "was incomplete"
            )
            if isinstance(exc, _AuditRunControlCreationInterrupted):
                cleanup_reason = (
                    "" if exc.cleanup.complete else "; control cleanup could not be verified"
                )
            elif prepared is not None and runtime is not None:
                try:
                    cleanup = runtime.cleanup(prepared)
                except (
                    KeyboardInterrupt,
                    AuditContainerError,
                    OSError,
                    TypeError,
                    ValueError,
                    RuntimeError,
                ):
                    control_removal_safe = False
                    cleanup_reason = "; external resource cleanup could not be verified"
                else:
                    control_removal_safe = cleanup.removed and not cleanup.ambiguous
                    if not control_removal_safe:
                        cleanup_reason = "; external resource cleanup could not be verified"
            elif external_setup_started:
                control_removal_safe = False
                cleanup_reason = "; external resource cleanup could not be verified"
            else:
                control_removal_safe = True
            checks.append(
                AuditCheck(
                    "execution",
                    CheckDisposition.failed,
                    0.0,
                    "audit execution was interrupted" + cleanup_reason,
                )
            )
            report = self._report(
                run_id=run_id,
                status=AuditStatus.cancelled,
                started_at=started_at,
                checks=tuple(checks),
                model_result=self._empty_result(
                    "Audit execution was cancelled.",
                    complete=False,
                    reason="audit execution was interrupted",
                ),
                termination_reason="audit execution was interrupted",
                config=config,
            )
        except (
            AuditServiceError,
            AuditWorkspaceError,
            AuditContainerError,
            AuditDockerBrokerError,
            AuditRunnerError,
            AuditProfileError,
            AuditReportError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            if prepared is not None and runtime is not None:
                try:
                    cleanup = runtime.cleanup(prepared)
                except (
                    KeyboardInterrupt,
                    AuditContainerError,
                    OSError,
                    TypeError,
                    ValueError,
                    RuntimeError,
                ):
                    control_removal_safe = False
                    cleanup_reason = "; cleanup could not be verified"
                else:
                    control_removal_safe = cleanup.removed and not cleanup.ambiguous
                    cleanup_reason = (
                        ""
                        if cleanup.removed and not cleanup.ambiguous
                        else "; cleanup could not be verified"
                    )
            elif external_setup_started:
                control_removal_safe = False
                control_retention_observation = (
                    "audit run control directory was retained because external resource cleanup "
                    "was incomplete"
                )
                cleanup_reason = "; external resource cleanup could not be verified"
            else:
                control_removal_safe = True
                cleanup_reason = ""
            checks.append(
                AuditCheck("execution", CheckDisposition.failed, 0.0, str(exc) + cleanup_reason)
            )
            report = self._report(
                run_id=run_id,
                status=AuditStatus.failed,
                started_at=started_at,
                checks=tuple(checks),
                model_result=self._empty_result(
                    "Audit execution failed.",
                    complete=False,
                    reason="audit execution failed",
                ),
                termination_reason="audit execution failed",
                config=config,
            )
        finally:
            if control_lifecycle.handle is not None:
                control_lifecycle.cleanup = _AuditRunControlCleanup(
                    False,
                    "audit run control directory cleanup could not be verified",
                )
                with suppress(KeyboardInterrupt):
                    control_lifecycle.cleanup = (
                        _cleanup_audit_run_control(control_lifecycle.handle)
                        if control_removal_safe
                        else _retain_audit_run_control_after_incomplete_cleanup(
                            control_lifecycle.handle,
                            observation=control_retention_observation,
                        )
                    )
        if control_lifecycle.cleanup is not None:
            report = _with_audit_run_control_cleanup(report, control_lifecycle.cleanup)
        try:
            self._validate_state_path(deadline=deadline)
            store.install(report)
        except AuditStoreError as exc:
            raise AuditServiceError("audit report could not be persisted") from exc
        return report

    def list_reports(self) -> tuple[AuditReport, ...]:
        return AuditStore(self.settings.state_dir).list_reports()

    def show(self, run_id: str) -> AuditReport:
        return AuditStore(self.settings.state_dir).read_report(run_id)

    def show_markdown(self, run_id: str) -> str:
        return AuditStore(self.settings.state_dir).read_markdown(run_id)
