"""Host-local composition of the bounded native repository audit components."""

from __future__ import annotations

import codecs
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
from dataclasses import replace
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
)
from zeus.config import Settings
from zeus.private_io import (
    UnsafeFileError,
    ensure_private_directory,
    read_private_bytes,
    write_private_bytes_atomic,
)
from zeus.process_lock import BotProcessLock, LockTimeoutError


class AuditServiceError(RuntimeError):
    pass


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
        ignored_pathspec = pathspec.rstrip("/") + "/.zeus-audit-ignore-probe"
        git = str(self.workspace._git_executable)
        base = (git, *GIT_HARDENING_ARGUMENTS, "-C", str(self.location.root))
        ignore_base = (
            git,
            *(
                argument
                for argument in GIT_HARDENING_ARGUMENTS
                if argument != "--literal-pathspecs"
            ),
            "-C",
            str(self.location.root),
        )
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
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
            ignored = subprocess.run(  # nosec B603
                (*ignore_base, "check-ignore", "-q", "--no-index", "--", ignored_pathspec),
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
        if tracked.returncode not in {0, 1} or ignored.returncode != 0:
            raise AuditServiceError("in-repository audit state path must be ignored and untracked")

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

        control = self.settings.state_dir / "audit" / "runs" / run_id
        prepared: PreparedAuditContainer | None = None
        runtime: AuditContainerRuntime | None = None
        try:
            for directory in (control, control / "home", control / "hermes", control / "launch"):
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
                    limits=config.limits,
                ),
            )
            if isinstance(result.model_result, ModelAuditResult):
                model_result = result.model_result
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
                cleanup = runtime.cleanup(prepared)
                cleanup_reason = (
                    ""
                    if cleanup.removed and not cleanup.ambiguous
                    else "; cleanup could not be verified"
                )
            else:
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
