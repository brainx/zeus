"""Fail-closed lifecycle for the single isolated audit command container."""

from __future__ import annotations

import io
import json
import os
import re
import stat
import tempfile as tempfile
import time
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO, cast

from zeus.audit_container_seed import SEED_SCRIPT as _SEED_SCRIPT
from zeus.audit_container_support import _actual_snapshot_paths as _actual_snapshot_paths
from zeus.audit_container_support import (
    _build_seed_archive,
    _manifest_directories,
    _normalized_environment,
    _trusted_environment,
    _validated_image_reference,
    _validation_manifest,
)
from zeus.audit_container_support import _DeadlineReader as _DeadlineReader
from zeus.audit_container_support import (
    _has_isolated_none_network as _has_isolated_none_network,
)
from zeus.audit_container_support import _stop_process as _stop_process
from zeus.audit_container_support import _SubprocessDockerRunner as _SubprocessDockerRunner
from zeus.audit_container_types import AUDIT_GID as AUDIT_GID
from zeus.audit_container_types import AUDIT_UID as AUDIT_UID
from zeus.audit_container_types import AuditContainerError as AuditContainerError
from zeus.audit_container_types import CleanupResult as CleanupResult
from zeus.audit_container_types import DockerCommandResult as DockerCommandResult
from zeus.audit_container_types import DockerCommandRunner as DockerCommandRunner
from zeus.audit_container_types import PreparedAuditContainer as PreparedAuditContainer
from zeus.audit_container_types import PreparedRecord as _PreparedRecord
from zeus.audit_container_types import (
    _command_deadline,
    _error,
    _safe_private_directory,
    _validate_deadline,
    _validate_limits,
)
from zeus.audit_container_validate import VALIDATION_SCRIPT as _VALIDATION_SCRIPT
from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.audit_trusted_snapshot_attest import TRUSTED_EXEC_ENV as TRUSTED_EXEC_ENV
from zeus.audit_workspace import MaterializedSnapshot
from zeus.private_io import write_private_bytes_atomic

_DOCKER_STDOUT_LIMIT = 1024 * 1024
_DOCKER_STDERR_LIMIT = 256 * 1024
_ARCHIVE_OUTPUT_LIMIT = 64 * 1024
_TRUSTED_PLAN_FILE = "trusted-container-plan.json"
_TRUSTED_PLAN_LIMIT = 16 * 1024
_RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_MINIMAL_DOCKER_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
_ENTRYPOINT = ("/bin/sh",)
_COMMAND = ("-c", "trap : TERM INT; sleep infinity & wait")
_TEMP_PATH = "/t" + "mp"
_WORKSPACE_TMPFS = (
    f"rw,exec,nosuid,nodev,size={HARD_LIMITS.workspace_bytes},"
    f"uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
)
_TEMP_TMPFS = (
    f"rw,noexec,nosuid,nodev,size={HARD_LIMITS.temp_bytes},"
    f"uid={AUDIT_UID},gid={AUDIT_GID},mode=0700"
)


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

    def _validate_local_docker_endpoint(
        self,
        *,
        limits: AuditLimits,
        deadline: float,
    ) -> None:
        result = self._run(
            (
                "context",
                "inspect",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ),
            limits=limits,
            deadline=deadline,
            stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
        )
        if result.stderr or not result.stdout.endswith(b"\n"):
            _error("effective Docker endpoint could not be proven local")
        try:
            endpoint = json.loads(result.stdout[:-1].decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditContainerError("effective Docker endpoint is invalid") from exc
        if not isinstance(endpoint, str) or not endpoint.startswith(("unix://", "npipe://")):
            _error("trusted audit workspace requires a local Docker endpoint")

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

    def _create_trusted_arguments(
        self,
        *,
        name: str,
        profile: str,
        run_id: str,
        image_ref: str,
        snapshot_path: Path,
        limits: AuditLimits,
    ) -> tuple[str, ...]:
        uid = os.geteuid()
        gid = os.getegid()
        temp_tmpfs = (
            f"rw,noexec,nosuid,nodev,size={limits.temp_bytes},uid={uid},gid={gid},mode=0700"
        )
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
            "--label",
            "com.zeus.audit.trusted-command=true",
            "--network=none",
            f"--user={uid}:{gid}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--read-only",
            "--no-healthcheck",
            "--log-driver=none",
            "--stop-timeout=1",
            "--restart=no",
            "--ipc=none",
            f"--pids-limit={limits.pids}",
            f"--cpus={limits.cpu_count}",
            f"--memory={limits.memory_bytes}",
            f"--memory-swap={limits.memory_bytes}",
            *(f"--env={value}" for value in TRUSTED_EXEC_ENV),
            "--mount",
            f"type=bind,src={snapshot_path},dst=/workspace,readonly,bind-propagation=rprivate",
            f"--tmpfs={_TEMP_PATH}:{temp_tmpfs}",
            "--workdir=/workspace",
            "--entrypoint=/bin/sh",
            image_ref,
            *_COMMAND,
        )

    def _with_trusted_container(
        self,
        record: _PreparedRecord,
        *,
        trusted_id: str,
        trusted_name: str,
        snapshot: MaterializedSnapshot,
        trusted_environment: tuple[str, ...],
        publish: bool = False,
    ) -> _PreparedRecord:
        prepared = replace(
            record.prepared,
            trusted_container_id=trusted_id,
            trusted_container_name=trusted_name,
            trusted_snapshot_path=str(snapshot.root),
            trusted_snapshot_device=snapshot._root_identity.device,
            trusted_snapshot_inode=snapshot._root_identity.inode,
            trusted_snapshot_owner=snapshot._root_identity.owner,
            trusted_snapshot_mode=snapshot._root_identity.permissions,
            trusted_execution_uid=os.geteuid(),
            trusted_execution_gid=os.getegid(),
        )
        updated = replace(
            record,
            prepared=prepared,
            trusted_snapshot_path=str(snapshot.root),
            trusted_environment=trusted_environment,
        )
        if publish:
            self._records[record.prepared.container_id] = updated
        return updated

    def _write_trusted_plan(
        self,
        record: _PreparedRecord,
        *,
        trusted_name: str,
        snapshot: MaterializedSnapshot,
        status: str,
        trusted_id: str | None,
        replace_existing: bool,
    ) -> None:
        value = {
            "schema_version": 1,
            "status": status,
            "container_id": trusted_id,
            "container_name": trusted_name,
            "image_id": record.prepared.image_id,
            "image_ref": record.prepared.image_ref,
            "labels": {
                **record.labels,
                "com.zeus.audit.trusted-command": "true",
            },
            "snapshot_path": str(snapshot.root),
            "snapshot_device": snapshot._root_identity.device,
            "snapshot_inode": snapshot._root_identity.inode,
            "snapshot_owner": snapshot._root_identity.owner,
            "snapshot_mode": snapshot._root_identity.permissions,
        }
        data = (
            json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
                "ascii"
            )
            + b"\n"
        )
        try:
            write_private_bytes_atomic(
                self._control_dir / _TRUSTED_PLAN_FILE,
                data,
                _TRUSTED_PLAN_LIMIT,
                replace=replace_existing,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise AuditContainerError(
                "trusted audit container recovery plan could not be persisted"
            ) from exc

    def _trusted_candidate_id(
        self,
        record: _PreparedRecord,
        *,
        trusted_name: str,
        deadline: float,
    ) -> str | None:
        result = self._run(
            (
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{trusted_name}$",
                "--format",
                "{{.ID}}",
            ),
            limits=record.limits,
            deadline=deadline,
            stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
        )
        if result.stderr:
            _error("trusted Docker create reconciliation returned an error")
        if not result.stdout:
            return None
        return _single_line(
            result.stdout,
            "trusted Docker create reconciliation",
            _CONTAINER_ID_RE,
        )

    def _remove_trusted_candidate(
        self,
        record: _PreparedRecord,
        *,
        trusted_name: str,
        snapshot: MaterializedSnapshot,
        trusted_environment: tuple[str, ...],
        candidate_id: str,
        deadline: float,
    ) -> str:
        candidate = self._with_trusted_container(
            record,
            trusted_id=candidate_id,
            trusted_name=trusted_name,
            snapshot=snapshot,
            trusted_environment=trusted_environment,
        )
        inspected = self._inspect(candidate, deadline=deadline, container_id=candidate_id)
        self._validate_trusted_inspected_record(candidate, inspected, allow_running=True)
        removed = self._run(
            ("rm", "-f", candidate_id),
            limits=record.limits,
            deadline=deadline,
            stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
        )
        removed_id = _single_line(
            removed.stdout,
            "trusted Docker create reconciliation removal",
            _CONTAINER_ID_RE,
        )
        if removed_id != candidate_id:
            _error("trusted Docker create reconciliation removed an unexpected identity")
        return candidate_id

    def _reconcile_uncertain_trusted_create(
        self,
        record: _PreparedRecord,
        *,
        trusted_name: str,
        snapshot: MaterializedSnapshot,
        trusted_environment: tuple[str, ...],
        known_id: str | None = None,
    ) -> str | None:
        """Remove a possibly-created exact-name sandbox without trusting CLI output."""

        cleanup_deadline = time.monotonic() + record.limits.docker_control_seconds
        if known_id is not None:
            return self._remove_trusted_candidate(
                record,
                trusted_name=trusted_name,
                snapshot=snapshot,
                trusted_environment=trusted_environment,
                candidate_id=known_id,
                deadline=cleanup_deadline,
            )
        # A killed Docker CLI can return before the daemon publishes the new name. Poll a
        # bounded quiet window, but treat continued absence as ambiguous rather than proof.
        for attempt in range(4):
            candidate_id = self._trusted_candidate_id(
                record,
                trusted_name=trusted_name,
                deadline=cleanup_deadline,
            )
            if candidate_id is not None:
                return self._remove_trusted_candidate(
                    record,
                    trusted_name=trusted_name,
                    snapshot=snapshot,
                    trusted_environment=trusted_environment,
                    candidate_id=candidate_id,
                    deadline=cleanup_deadline,
                )
            if attempt < 3:
                remaining = cleanup_deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.05, remaining))
        return None

    def prepare(
        self,
        *,
        run_id: str,
        snapshot: MaterializedSnapshot,
        image_ref: str,
        limits: AuditLimits,
        deadline: float,
        prepare_trusted_workspace: bool = False,
    ) -> PreparedAuditContainer:
        active_deadline = _validate_deadline(deadline)
        _validate_limits(limits)
        if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
            _error("audit container run ID is invalid")
        if not isinstance(image_ref, str):
            _error("audit image must be an immutable digest-qualified reference")
        if not isinstance(prepare_trusted_workspace, bool):
            _error("trusted audit workspace selection is invalid")
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
            if prepare_trusted_workspace:
                if os.geteuid() == 0:
                    _error("trusted audit workspace cannot run as root")
                try:
                    snapshot_root = snapshot.root.lstat()
                except OSError as exc:
                    raise AuditContainerError("trusted audit snapshot root is unavailable") from exc
                if (
                    snapshot_root.st_uid != os.geteuid()
                    or snapshot_root.st_gid != os.getegid()
                    or stat.S_IMODE(snapshot_root.st_mode) != 0o700
                ):
                    _error("trusted audit snapshot root ownership is invalid")
                self._validate_local_docker_endpoint(
                    limits=limits,
                    deadline=active_deadline,
                )
                trusted_name = f"zeus-audit-trusted-{run_id}"
                effective_trusted_environment = _trusted_environment(image_environment)
                self._write_trusted_plan(
                    record,
                    trusted_name=trusted_name,
                    snapshot=snapshot,
                    status="planned",
                    trusted_id=None,
                    replace_existing=False,
                )
                trusted_id: str | None = None
                try:
                    trusted_create = self._run(
                        self._create_trusted_arguments(
                            name=trusted_name,
                            profile=profile,
                            run_id=run_id,
                            image_ref=validated_image_ref,
                            snapshot_path=snapshot.root,
                            limits=limits,
                        ),
                        limits=limits,
                        deadline=active_deadline,
                    )
                    trusted_id = _single_line(
                        trusted_create.stdout,
                        "trusted Docker create",
                        _CONTAINER_ID_RE,
                    )
                    if trusted_id == container_id:
                        _error("trusted audit container identity is not unique")
                    record = self._with_trusted_container(
                        record,
                        trusted_id=trusted_id,
                        trusted_name=trusted_name,
                        snapshot=snapshot,
                        trusted_environment=effective_trusted_environment,
                        publish=True,
                    )
                    prepared = record.prepared
                except BaseException as create_error:
                    # The daemon may finish a create after its CLI was interrupted. Reconcile
                    # the reserved exact name and delete only after validating full ownership.
                    try:
                        reconciled_id = self._reconcile_uncertain_trusted_create(
                            record,
                            trusted_name=trusted_name,
                            snapshot=snapshot,
                            trusted_environment=effective_trusted_environment,
                            known_id=trusted_id,
                        )
                    except BaseException as reconciliation_error:
                        with suppress(OSError, TypeError, ValueError, AuditContainerError):
                            self._write_trusted_plan(
                                record,
                                trusted_name=trusted_name,
                                snapshot=snapshot,
                                status="create-ambiguous",
                                trusted_id=None,
                                replace_existing=True,
                            )
                        if isinstance(
                            create_error,
                            KeyboardInterrupt,
                        ) or isinstance(reconciliation_error, KeyboardInterrupt):
                            raise KeyboardInterrupt(
                                "trusted Docker create reconciliation was interrupted"
                            ) from reconciliation_error
                        raise AuditContainerError(
                            "trusted Docker create could not be reconciled safely"
                        ) from reconciliation_error
                    if reconciled_id is None:
                        self._write_trusted_plan(
                            record,
                            trusted_name=trusted_name,
                            snapshot=snapshot,
                            status="create-ambiguous",
                            trusted_id=None,
                            replace_existing=True,
                        )
                        if isinstance(create_error, KeyboardInterrupt):
                            raise KeyboardInterrupt(
                                "trusted Docker create cleanup remained ambiguous"
                            ) from create_error
                        raise AuditContainerError(
                            "trusted Docker create cleanup remained ambiguous; recovery plan "
                            "was retained"
                        ) from create_error
                    self._write_trusted_plan(
                        record,
                        trusted_name=trusted_name,
                        snapshot=snapshot,
                        status="reconciled-removed",
                        trusted_id=reconciled_id,
                        replace_existing=True,
                    )
                    raise
                self._write_trusted_plan(
                    record,
                    trusted_name=trusted_name,
                    snapshot=snapshot,
                    status="created",
                    trusted_id=trusted_id,
                    replace_existing=True,
                )
            self._run(("start", container_id), limits=limits, deadline=active_deadline)
            archive = _build_seed_archive(
                snapshot,
                active_deadline,
                limits=limits,
                spool_dir=broker_dir,
            )
            seed_entries = len(snapshot.manifest) + len(_manifest_directories(snapshot.manifest))
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
                    _SEED_SCRIPT,
                    str(seed_entries),
                    str(limits.snapshot_blob_bytes),
                ),
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
                    f"[{AUDIT_GID}]",
                    "/proc/self/status",
                    "/proc/self/mountinfo",
                    ".",
                    "/workspace",
                    _TEMP_PATH,
                    str(limits.workspace_bytes),
                    str(limits.temp_bytes),
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
        container_id: str | None = None,
    ) -> dict[str, object]:
        result = self._run(
            ("inspect", record.prepared.container_id if container_id is None else container_id),
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
        if record.prepared.trusted_container_id is not None:
            trusted = self._inspect(
                record,
                container_id=record.prepared.trusted_container_id,
            )
            self._validate_trusted_inspected_record(record, trusted)

    def _validate_trusted_inspected_record(
        self,
        record: _PreparedRecord,
        item: dict[str, object],
        *,
        allow_running: bool = False,
    ) -> None:
        prepared = record.prepared
        trusted_id = prepared.trusted_container_id
        trusted_name = prepared.trusted_container_name
        snapshot_path = record.trusted_snapshot_path
        if trusted_id is None or trusted_name is None or snapshot_path is None:
            _error("trusted audit container binding is incomplete")
        config = item.get("Config")
        host = item.get("HostConfig")
        state = item.get("State")
        network = item.get("NetworkSettings")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(state, dict)
            or not isinstance(network, dict)
            or record.trusted_environment is None
        ):
            _error("trusted audit container inspection omitted mandatory controls")
        uid = os.geteuid()
        gid = os.getegid()
        temp_tmpfs = (
            f"rw,noexec,nosuid,nodev,size={record.limits.temp_bytes},uid={uid},gid={gid},mode=0700"
        )
        expected_labels = dict(record.labels)
        expected_labels["com.zeus.audit.trusted-command"] = "true"
        config_environment = config.get("Env")
        observed_environment = (
            _normalized_environment(tuple(config_environment))
            if isinstance(config_environment, list)
            and all(isinstance(value, str) for value in config_environment)
            else ()
        )
        state_running = state.get("Running")
        state_pid = state.get("Pid")
        state_status = state.get("Status")
        state_ok = (
            isinstance(state_running, bool)
            and isinstance(state_pid, int)
            and not isinstance(state_pid, bool)
            and (
                (state_running and allow_running and state_pid > 0 and state_status == "running")
                or (not state_running and state_pid == 0 and state_status in {"created", "exited"})
            )
        )
        requested_mounts = host.get("Mounts")
        requested_mount_ok = False
        if isinstance(requested_mounts, list) and len(requested_mounts) == 1:
            requested = requested_mounts[0]
            if isinstance(requested, dict):
                bind_options = requested.get("BindOptions")
                requested_mount_ok = (
                    requested.get("Type") == "bind"
                    and requested.get("Source") == snapshot_path
                    and requested.get("Target") == "/workspace"
                    and requested.get("ReadOnly") is True
                    and requested.get("Consistency") in (None, "", "default")
                    and isinstance(bind_options, dict)
                    and set(bind_options).issubset(
                        {
                            "Propagation",
                            "NonRecursive",
                            "CreateMountpoint",
                            "ReadOnlyNonRecursive",
                            "ReadOnlyForceRecursive",
                        }
                    )
                    and bind_options.get("Propagation") == "rprivate"
                    and bind_options.get("NonRecursive") in (None, False)
                    and bind_options.get("CreateMountpoint") in (None, False)
                    and bind_options.get("ReadOnlyNonRecursive") in (None, False)
                    and bind_options.get("ReadOnlyForceRecursive") in (None, False, True)
                    and requested.get("VolumeOptions") in (None, {})
                    and requested.get("TmpfsOptions") in (None, {})
                )
        effective_mounts = item.get("Mounts")
        effective_bind_count = 0
        effective_temp_count = 0
        effective_mounts_ok = isinstance(effective_mounts, list)
        if isinstance(effective_mounts, list):
            for mount in effective_mounts:
                if not isinstance(mount, dict):
                    effective_mounts_ok = False
                    continue
                if mount.get("Destination") == "/workspace":
                    effective_bind_count += 1
                    effective_mounts_ok = effective_mounts_ok and (
                        mount.get("Type") == "bind"
                        and mount.get("Source") == snapshot_path
                        and mount.get("RW") is False
                    )
                elif mount.get("Destination") == _TEMP_PATH:
                    effective_temp_count += 1
                    effective_mounts_ok = effective_mounts_ok and (
                        mount.get("Type") == "tmpfs" and mount.get("RW") is True
                    )
                else:
                    effective_mounts_ok = False
        effective_mounts_ok = (
            effective_mounts_ok
            and effective_bind_count == 1
            and effective_temp_count in {0, 1}
            and isinstance(effective_mounts, list)
            and len(effective_mounts) == effective_bind_count + effective_temp_count
        )
        checks = (
            (item.get("Id") == trusted_id, "trusted container identity"),
            (item.get("Name") == f"/{trusted_name}", "trusted container name"),
            (item.get("Image") == prepared.image_id, "trusted container image ID"),
            (config.get("Image") == prepared.image_ref, "trusted container image reference"),
            (config.get("User") == f"{uid}:{gid}", "trusted container user"),
            (config.get("WorkingDir") == "/workspace", "trusted container workdir"),
            (config.get("Entrypoint") == list(_ENTRYPOINT), "trusted container entrypoint"),
            (config.get("Cmd") == list(_COMMAND), "trusted container command"),
            (
                observed_environment == record.trusted_environment,
                "trusted container environment",
            ),
            (config.get("Healthcheck") == {"Test": ["NONE"]}, "trusted healthcheck"),
            (config.get("Volumes") in (None, {}), "trusted inherited volumes"),
            (config.get("Labels") == expected_labels, "trusted container labels"),
            (host.get("NetworkMode") == "none", "trusted container network"),
            (host.get("Binds") in (None, []), "trusted container binds"),
            (requested_mount_ok, "trusted read-only source mount"),
            (host.get("CapAdd") in (None, []), "trusted added capabilities"),
            (host.get("CapDrop") == ["ALL"], "trusted dropped capabilities"),
            (
                host.get("SecurityOpt") == ["no-new-privileges:true"],
                "trusted security options",
            ),
            (host.get("ReadonlyRootfs") is True, "trusted root filesystem"),
            (host.get("PidsLimit") == record.limits.pids, "trusted PID limit"),
            (
                host.get("NanoCpus") == record.limits.cpu_count * 1_000_000_000,
                "trusted CPU limit",
            ),
            (host.get("Memory") == record.limits.memory_bytes, "trusted memory limit"),
            (host.get("MemorySwap") == record.limits.memory_bytes, "trusted swap limit"),
            (host.get("Privileged") is False, "trusted privileged mode"),
            (host.get("PidMode") in (None, "", "private"), "trusted PID namespace"),
            (host.get("IpcMode") == "none", "trusted IPC namespace"),
            (host.get("UTSMode") in (None, "", "private"), "trusted UTS namespace"),
            (host.get("UsernsMode") in (None, "", "private"), "trusted user namespace"),
            (
                host.get("CgroupnsMode") in (None, "", "private"),
                "trusted cgroup namespace",
            ),
            (host.get("Devices") in (None, []), "trusted devices"),
            (host.get("DeviceRequests") in (None, []), "trusted device requests"),
            (
                host.get("DeviceCgroupRules") in (None, []),
                "trusted device cgroup rules",
            ),
            (host.get("GroupAdd") in (None, []), "trusted supplementary groups"),
            (host.get("PortBindings") in (None, {}), "trusted port bindings"),
            (host.get("Tmpfs") == {_TEMP_PATH: temp_tmpfs}, "trusted tmpfs controls"),
            (
                host.get("LogConfig") in ({"Type": "none", "Config": {}}, {"Type": "none"}),
                "trusted log persistence",
            ),
            (
                host.get("RestartPolicy") in (None, {"Name": "no", "MaximumRetryCount": 0}),
                "trusted restart policy",
            ),
            (state_ok, "trusted container state"),
            (effective_mounts_ok, "trusted effective mounts"),
            (network.get("Ports") in (None, {}), "trusted effective ports"),
            (
                _has_isolated_none_network(network.get("Networks")),
                "trusted effective network attachments",
            ),
            (
                network.get("IPAddress") in (None, ""),
                "trusted effective IP address",
            ),
            (
                network.get("Gateway") in (None, ""),
                "trusted effective gateway",
            ),
            (
                network.get("MacAddress") in (None, ""),
                "trusted effective MAC address",
            ),
        )
        for accepted, description in checks:
            if not accepted:
                _error(f"{description} does not match the required isolation policy")

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
        expected_mounts = (
            ("/workspace", "tmpfs", True),
            (_TEMP_PATH, "tmpfs", True),
        )
        if not isinstance(mounts, list):
            _error("Docker container inspection omitted mount controls")
        observed_mounts: list[tuple[object, object, object]] = []
        for mount in mounts:
            if not isinstance(mount, dict):
                _error("Docker container inspection returned an invalid mount")
            observed_mounts.append((mount.get("Destination"), mount.get("Type"), mount.get("RW")))
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
            (
                not observed_mounts
                or (
                    len(observed_mounts) == len(expected_mounts)
                    and set(observed_mounts) == set(expected_mounts)
                ),
                "container effective mounts",
            ),
            (network.get("Ports") in (None, {}), "container effective ports"),
            (
                _has_isolated_none_network(network.get("Networks")),
                "container effective network attachments",
            ),
            (
                "IPAddress" not in network or network.get("IPAddress") == "",
                "container effective IP address",
            ),
            (
                "Gateway" not in network or network.get("Gateway") == "",
                "container effective gateway",
            ),
            (
                "MacAddress" not in network or network.get("MacAddress") == "",
                "container effective MAC address",
            ),
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
        container_ids = tuple(
            container_id
            for container_id in (
                record.prepared.trusted_container_id,
                record.prepared.container_id,
            )
            if container_id is not None
        )
        all_removed = True
        for container_id in container_ids:
            try:
                presence = self._run(
                    (
                        "ps",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        f"id={container_id}",
                        "--format",
                        "{{.ID}}",
                    ),
                    limits=record.limits,
                    deadline=cleanup_deadline,
                    stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
                )
                if presence.stderr:
                    _error("Docker container presence check returned an error")
                if not presence.stdout:
                    continue
                if presence.stdout != f"{container_id}\n".encode("ascii"):
                    _error("Docker container presence check was ambiguous")
                item = self._inspect(
                    record,
                    deadline=cleanup_deadline,
                    container_id=container_id,
                )
                if container_id == record.prepared.trusted_container_id:
                    self._validate_trusted_inspected_record(
                        record,
                        item,
                        allow_running=True,
                    )
                else:
                    self._validate_inspected_record(record, item, require_running=False)
                remove_result = self._run(
                    ("rm", "-f", container_id),
                    limits=record.limits,
                    deadline=cleanup_deadline,
                    stdout_limit=_ARCHIVE_OUTPUT_LIMIT,
                )
                removed_id = _single_line(
                    remove_result.stdout,
                    "Docker remove",
                    _CONTAINER_ID_RE,
                )
                if removed_id != container_id:
                    _error("Docker remove returned an unexpected container identity")
            except AuditContainerError:
                all_removed = False
        if not all_removed:
            return CleanupResult(
                removed=False,
                ambiguous=True,
                observation="one or more audit container cleanups could not be verified",
            )
        return CleanupResult(
            removed=True,
            ambiguous=False,
            observation="exact audit-owned containers removed",
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
