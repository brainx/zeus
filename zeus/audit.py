"""Host-local composition of the bounded native repository audit components."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess  # nosec B404
import sys
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
from zeus.audit_profile import AuditProfileError, build_audit_profile
from zeus.audit_report import AuditReportError, build_audit_report, validate_model_output
from zeus.audit_runner import AuditRunner, AuditRunnerError, AuditRunnerOutcome
from zeus.audit_store import AuditStore, AuditStoreError
from zeus.audit_workspace import (
    GIT_HARDENING_ARGUMENTS,
    AuditWorkspace,
    AuditWorkspaceError,
    RepositoryLocation,
)
from zeus.config import Settings
from zeus.private_io import UnsafeFileError, ensure_private_directory
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


class AuditService:
    def __init__(
        self,
        *,
        workspace: AuditWorkspace,
        location: RepositoryLocation,
        settings: Settings,
        env: Mapping[str, str],
        deadline: float,
    ) -> None:
        self.workspace = workspace
        self.location = location
        self.settings = settings
        self.env = dict(env)
        self.deadline = deadline

    @classmethod
    def from_cwd(
        cls,
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> AuditService:
        source_env = dict(os.environ if env is None else env)
        deadline = time.monotonic() + 3600
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

    def _validate_state_path(self) -> None:
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
        try:
            tracked = subprocess.run(  # nosec B603
                (*base, "ls-files", "--error-unmatch", "--", pathspec),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                shell=False,
                check=False,
                timeout=30,
            )
            ignored = subprocess.run(  # nosec B603
                (*ignore_base, "check-ignore", "-q", "--no-index", "--", ignored_pathspec),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                shell=False,
                check=False,
                timeout=30,
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
            self._validate_state_path()
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

        active_deadline = min(self.deadline, time.monotonic() + config.limits.overall_seconds)
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
            store.install(report)
            return report

        control = self.settings.state_dir / "audit" / "runs" / run_id
        prepared: PreparedAuditContainer | None = None
        runtime: AuditContainerRuntime | None = None
        try:
            for directory in (control, control / "home", control / "hermes", control / "launch"):
                ensure_private_directory(directory)
            snapshot = self.workspace.materialize(
                self.workspace.inspect(self.location, deadline=deadline),
                control / "snapshot",
                exclude_paths=config.exclude_paths,
                limits=config.limits,
                deadline=deadline,
            )
            docker = _executable("docker")
            hermes = _executable(self.settings.hermes_bin)
            runtime = AuditContainerRuntime(docker, control)
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
                    source_line_counts={},
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
            if not result.cleanup_complete:
                model_result = replace(
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
