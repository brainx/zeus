"""Stateful Docker compatibility broker for the pinned audit terminal backend."""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

from zeus.audit_container import _has_isolated_none_network
from zeus.audit_docker_broker_control import (
    _breach_control as _breach_control,
)
from zeus.audit_docker_broker_control import (
    _complete_control as _complete_control,
)
from zeus.audit_docker_broker_control import (
    _perform_cleanup as _perform_cleanup,
)
from zeus.audit_docker_broker_control import (
    _release_terminal_reservation as _release_terminal_reservation,
)
from zeus.audit_docker_broker_control import (
    _remove_trusted_container as _remove_trusted_container,
)
from zeus.audit_docker_broker_control import (
    _valid_removal as _valid_removal,
)
from zeus.audit_docker_broker_core import (
    _BROKER_FILE_NAME as _BROKER_FILE_NAME,
)
from zeus.audit_docker_broker_core import (
    _CLEANUP_OWNER_RE as _CLEANUP_OWNER_RE,
)
from zeus.audit_docker_broker_core import (
    _CLEANUP_STATES as _CLEANUP_STATES,
)
from zeus.audit_docker_broker_core import (
    _CONTAINER_ID_RE as _CONTAINER_ID_RE,
)
from zeus.audit_docker_broker_core import (
    _CONTAINER_NAME_RE as _CONTAINER_NAME_RE,
)
from zeus.audit_docker_broker_core import (
    _CONTAINER_TEMP as _CONTAINER_TEMP,
)
from zeus.audit_docker_broker_core import (
    _CONTROL_OUTPUT_LIMIT as _CONTROL_OUTPUT_LIMIT,
)
from zeus.audit_docker_broker_core import (
    _IMAGE_ID_RE as _IMAGE_ID_RE,
)
from zeus.audit_docker_broker_core import (
    _IMAGE_REF_RE as _IMAGE_REF_RE,
)
from zeus.audit_docker_broker_core import (
    _LOCK_FILE_NAME as _LOCK_FILE_NAME,
)
from zeus.audit_docker_broker_core import (
    _LOCK_WAIT_SECONDS as _LOCK_WAIT_SECONDS,
)
from zeus.audit_docker_broker_core import (
    _MAX_ARGV_BYTES as _MAX_ARGV_BYTES,
)
from zeus.audit_docker_broker_core import (
    _MAX_ARGV_ITEMS as _MAX_ARGV_ITEMS,
)
from zeus.audit_docker_broker_core import (
    _MINIMAL_DOCKER_ENV as _MINIMAL_DOCKER_ENV,
)
from zeus.audit_docker_broker_core import (
    _PHASES as _PHASES,
)
from zeus.audit_docker_broker_core import (
    _PROCESS_CHUNK as _PROCESS_CHUNK,
)
from zeus.audit_docker_broker_core import (
    _PROFILE_RE as _PROFILE_RE,
)
from zeus.audit_docker_broker_core import (
    _RUN_ID_RE as _RUN_ID_RE,
)
from zeus.audit_docker_broker_core import (
    _SESSION_ID_RE as _SESSION_ID_RE,
)
from zeus.audit_docker_broker_core import (
    _STATE_FILE_NAME as _STATE_FILE_NAME,
)
from zeus.audit_docker_broker_core import (
    _STATE_KEYS as _STATE_KEYS,
)
from zeus.audit_docker_broker_core import (
    _STATE_LIMIT as _STATE_LIMIT,
)
from zeus.audit_docker_broker_core import (
    _STATE_SCHEMA_VERSION as _STATE_SCHEMA_VERSION,
)
from zeus.audit_docker_broker_core import (
    HERMES_VERSION as HERMES_VERSION,
)
from zeus.audit_docker_broker_core import (
    AuditDockerBrokerError as AuditDockerBrokerError,
)
from zeus.audit_docker_broker_core import (
    AuditDockerBrokerState as AuditDockerBrokerState,
)
from zeus.audit_docker_broker_core import (
    BrokerCommandResult as BrokerCommandResult,
)
from zeus.audit_docker_broker_core import (
    DockerExecutionRunner as DockerExecutionRunner,
)
from zeus.audit_docker_broker_core import (
    _acquire_lock as _acquire_lock,
)
from zeus.audit_docker_broker_core import (
    _Decision as _Decision,
)
from zeus.audit_docker_broker_core import (
    _decode_state as _decode_state,
)
from zeus.audit_docker_broker_core import (
    _DockerExecutionError as _DockerExecutionError,
)
from zeus.audit_docker_broker_core import (
    _error as _error,
)
from zeus.audit_docker_broker_core import (
    _is_int as _is_int,
)
from zeus.audit_docker_broker_core import (
    _locked_state as _locked_state,
)
from zeus.audit_docker_broker_core import (
    _LockedStateDirectory as _LockedStateDirectory,
)
from zeus.audit_docker_broker_core import (
    _lstat_at as _lstat_at,
)
from zeus.audit_docker_broker_core import (
    _open_lock_at as _open_lock_at,
)
from zeus.audit_docker_broker_core import (
    _read_control_file_at as _read_control_file_at,
)
from zeus.audit_docker_broker_core import (
    _read_state_unlocked as _read_state_unlocked,
)
from zeus.audit_docker_broker_core import (
    _same_file as _same_file,
)
from zeus.audit_docker_broker_core import (
    _state_bytes as _state_bytes,
)
from zeus.audit_docker_broker_core import (
    _strict_dict as _strict_dict,
)
from zeus.audit_docker_broker_core import (
    _strict_nonnegative_int as _strict_nonnegative_int,
)
from zeus.audit_docker_broker_core import (
    _strict_positive_int as _strict_positive_int,
)
from zeus.audit_docker_broker_core import (
    _validate_deadline as _validate_deadline,
)
from zeus.audit_docker_broker_core import (
    _validate_executable as _validate_executable,
)
from zeus.audit_docker_broker_core import (
    _validate_limits as _validate_limits,
)
from zeus.audit_docker_broker_core import (
    _validate_prepared as _validate_prepared,
)
from zeus.audit_docker_broker_core import (
    _validate_private_control_file as _validate_private_control_file,
)
from zeus.audit_docker_broker_core import (
    _wrapper_bytes as _wrapper_bytes,
)
from zeus.audit_docker_broker_core import (
    _write_control_file_at as _write_control_file_at,
)
from zeus.audit_docker_broker_core import (
    _write_state_unlocked as _write_state_unlocked,
)
from zeus.audit_docker_broker_core import (
    install_audit_docker_broker as install_audit_docker_broker,
)
from zeus.audit_docker_broker_core import (
    read_audit_docker_broker_state as read_audit_docker_broker_state,
)
from zeus.audit_docker_broker_execution import (
    _command_deadline as _command_deadline,
)
from zeus.audit_docker_broker_execution import (
    _stop_process as _stop_process,
)
from zeus.audit_docker_broker_execution import (
    _SubprocessDockerExecutionRunner as _SubprocessDockerExecutionRunner,
)
from zeus.audit_docker_broker_execution import (
    _valid_image_entrypoint as _valid_image_entrypoint,
)
from zeus.audit_docker_broker_execution import (
    _valid_network as _valid_network,
)
from zeus.audit_docker_broker_protocol import (
    _arguments_are_bounded as _arguments_are_bounded,
)
from zeus.audit_docker_broker_protocol import (
    _bootstrap_session_id as _bootstrap_session_id,
)
from zeus.audit_docker_broker_protocol import (
    _breached as _breached,
)
from zeus.audit_docker_broker_protocol import (
    _claim_cleanup as _claim_cleanup,
)
from zeus.audit_docker_broker_protocol import (
    _decide as _decide,
)
from zeus.audit_docker_broker_protocol import (
    _expected_bootstrap_script as _expected_bootstrap_script,
)
from zeus.audit_docker_broker_protocol import (
    _expected_cgroup_probe as _expected_cgroup_probe,
)
from zeus.audit_docker_broker_protocol import (
    _expected_image_inspect as _expected_image_inspect,
)
from zeus.audit_docker_broker_protocol import (
    _expected_network_inspect as _expected_network_inspect,
)
from zeus.audit_docker_broker_protocol import (
    _expected_removal as _expected_removal,
)
from zeus.audit_docker_broker_protocol import (
    _expected_reuse_probe as _expected_reuse_probe,
)
from zeus.audit_models import HARD_LIMITS
from zeus.audit_trusted_snapshot_attest import (
    ATTEST_SCRIPT,
    TRUSTED_EXEC_ENV,
    TRUSTED_EXEC_PREFIX,
)

_TRUSTED_STATE_FORMAT = (
    "{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t"
    '{{json (index .Config.Labels "com.zeus.audit.run-id")}}\t'
    '{{json (index .Config.Labels "com.zeus.audit.trusted-command")}}\t'
    "{{json .State.Running}}\t{{json .State.Pid}}\t{{json .State.Status}}\t"
    "{{json .Config.User}}\t{{json .Config.WorkingDir}}\t"
    "{{json .Config.Entrypoint}}\t{{json .Config.Cmd}}\t"
    "{{json .Config.Env}}\t{{json .Config.Volumes}}\t{{json .Config.Healthcheck}}\t"
    "{{json .HostConfig.NetworkMode}}\t{{json .HostConfig.ReadonlyRootfs}}\t"
    "{{json .HostConfig.CapAdd}}\t{{json .HostConfig.CapDrop}}\t"
    "{{json .HostConfig.SecurityOpt}}\t{{json .HostConfig.PidMode}}\t"
    "{{json .HostConfig.IpcMode}}\t{{json .HostConfig.UTSMode}}\t"
    "{{json .HostConfig.UsernsMode}}\t{{json .HostConfig.CgroupnsMode}}\t"
    "{{json .HostConfig.Devices}}\t{{json .HostConfig.DeviceRequests}}\t"
    "{{json .HostConfig.DeviceCgroupRules}}\t{{json .HostConfig.GroupAdd}}\t"
    "{{json .HostConfig.PortBindings}}\t{{json .HostConfig.PidsLimit}}\t"
    "{{json .HostConfig.NanoCpus}}\t{{json .HostConfig.Memory}}\t"
    "{{json .HostConfig.MemorySwap}}\t{{json .HostConfig.Privileged}}\t"
    "{{json .HostConfig.Mounts}}\t{{json .HostConfig.Tmpfs}}\t"
    "{{json .HostConfig.LogConfig}}\t{{json .HostConfig.RestartPolicy}}\t"
    "{{json .Mounts}}\t{{json .NetworkSettings.Ports}}\t"
    "{{json .NetworkSettings.Networks}}\t{{json .NetworkSettings.IPAddress}}\t"
    "{{json .NetworkSettings.Gateway}}\t{{json .NetworkSettings.MacAddress}}"
)


def _trusted_state_matches(
    state: AuditDockerBrokerState,
    result: BrokerCommandResult,
    *,
    running: bool,
) -> bool:
    if result.returncode != 0 or result.stderr or not result.stdout.endswith(b"\n"):
        return False
    try:
        fields = tuple(
            json.loads(field)
            for field in result.stdout[:-1].decode("utf-8", errors="strict").split("\t")
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    trusted_id = state.trusted_container_id
    trusted_name = state.trusted_container_name
    if len(fields) != 45:
        return False
    environment = fields[12]
    environment_values: dict[str, str] = {}
    environment_ok = isinstance(environment, list)
    if isinstance(environment, list):
        for item in environment:
            if not isinstance(item, str):
                environment_ok = False
                continue
            key, separator, value = item.partition("=")
            if not separator or not key or key in environment_values or "\0" in item:
                environment_ok = False
                continue
            environment_values[key] = value
    required_environment = {
        item.partition("=")[0]: item.partition("=")[2] for item in TRUSTED_EXEC_ENV
    }
    environment_ok = environment_ok and all(
        environment_values.get(key) == value for key, value in required_environment.items()
    )
    requested_mounts = fields[35]
    requested_mount_ok = False
    if isinstance(requested_mounts, list) and len(requested_mounts) == 1:
        mount = requested_mounts[0]
        bind_options = mount.get("BindOptions") if isinstance(mount, dict) else None
        requested_mount_ok = (
            isinstance(mount, dict)
            and mount.get("Type") == "bind"
            and mount.get("Source") == state.trusted_snapshot_path
            and mount.get("Target") == "/workspace"
            and mount.get("ReadOnly") is True
            and mount.get("Consistency") in (None, "", "default")
            and isinstance(bind_options, dict)
            and set(bind_options).issubset({"Propagation", "NonRecursive", "CreateMountpoint"})
            and bind_options.get("Propagation") in (None, "", "rprivate")
            and bind_options.get("NonRecursive") in (None, False)
            and bind_options.get("CreateMountpoint") in (None, False)
            and mount.get("VolumeOptions") in (None, {})
            and mount.get("TmpfsOptions") in (None, {})
        )
    effective_mounts = fields[39]
    effective_bind_count = 0
    effective_temp_count = 0
    effective_mounts_ok = isinstance(effective_mounts, list)
    if isinstance(effective_mounts, list):
        for mount in effective_mounts:
            if not isinstance(mount, dict):
                effective_mounts_ok = False
            elif mount.get("Destination") == "/workspace":
                effective_bind_count += 1
                effective_mounts_ok = effective_mounts_ok and (
                    mount.get("Type") == "bind"
                    and mount.get("Source") == state.trusted_snapshot_path
                    and mount.get("RW") is False
                )
            elif mount.get("Destination") == _CONTAINER_TEMP:
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
    expected_tmpfs = (
        f"rw,noexec,nosuid,nodev,size={HARD_LIMITS.temp_bytes},"
        f"uid={state.trusted_execution_uid},gid={state.trusted_execution_gid},mode=0700"
    )
    return (
        trusted_id is not None
        and trusted_name is not None
        and fields[:5]
        == (
            trusted_id,
            f"/{trusted_name}",
            state.image_id,
            state.profile_name.removeprefix("audit-"),
            "true",
        )
        and fields[5] is running
        and isinstance(fields[6], int)
        and not isinstance(fields[6], bool)
        and ((fields[6] > 0) if running else (fields[6] == 0))
        and fields[7] in ({"running"} if running else {"created", "exited"})
        and fields[8] == f"{state.trusted_execution_uid}:{state.trusted_execution_gid}"
        and fields[9] == "/workspace"
        and fields[10] == ["/bin/sh"]
        and fields[11] == ["-c", "trap : TERM INT; sleep infinity & wait"]
        and environment_ok
        and fields[13] in (None, {})
        and fields[14] == {"Test": ["NONE"]}
        and fields[15] == "none"
        and fields[16] is True
        and fields[17] in (None, [])
        and fields[18] == ["ALL"]
        and fields[19] == ["no-new-privileges:true"]
        and fields[20] in (None, "", "private")
        and fields[21] == "none"
        and fields[22] in (None, "", "private")
        and fields[23] in (None, "", "private")
        and fields[24] in (None, "", "private")
        and fields[25] in (None, [])
        and fields[26] in (None, [])
        and fields[27] in (None, [])
        and fields[28] in (None, [])
        and fields[29] in (None, {})
        and fields[30] == HARD_LIMITS.pids
        and fields[31] == HARD_LIMITS.cpu_count * 1_000_000_000
        and fields[32] == HARD_LIMITS.memory_bytes
        and fields[33] == HARD_LIMITS.memory_bytes
        and fields[34] is False
        and requested_mount_ok
        and fields[36] == {_CONTAINER_TEMP: expected_tmpfs}
        and fields[37] in ({"Type": "none", "Config": {}}, {"Type": "none"})
        and fields[38] in (None, {"Name": "no", "MaximumRetryCount": 0})
        and effective_mounts_ok
        and fields[40] in (None, {})
        and _has_isolated_none_network(fields[41])
        and fields[42] in (None, "")
        and fields[43] in (None, "")
        and fields[44] in (None, "")
    )


def _inspect_trusted_state(
    state: AuditDockerBrokerState,
    *,
    runner: DockerExecutionRunner,
    deadline: float,
    running: bool,
) -> bool:
    if state.trusted_container_id is None:
        return False
    result = runner.run(
        (
            state.docker_executable,
            "inspect",
            "--format",
            _TRUSTED_STATE_FORMAT,
            state.trusted_container_id,
        ),
        deadline=deadline,
        output_limit=_CONTROL_OUTPUT_LIMIT,
        env=dict(_MINIMAL_DOCKER_ENV),
    )
    return _trusted_state_matches(state, result, running=running)


def _trusted_snapshot_matches(state: AuditDockerBrokerState) -> bool:
    path = state.trusted_snapshot_path
    if path is None:
        return False
    try:
        result = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISDIR(result.st_mode)
        and result.st_dev == state.trusted_snapshot_device
        and result.st_ino == state.trusted_snapshot_inode
        and result.st_uid == state.trusted_snapshot_owner
        and result.st_gid == state.trusted_execution_gid
        and stat.S_IMODE(result.st_mode) == state.trusted_snapshot_mode == 0o700
    )


def _run_isolated_terminal(
    state: AuditDockerBrokerState,
    command_script: str,
    *,
    runner: DockerExecutionRunner,
    deadline: float,
    output_limit: int,
) -> BrokerCommandResult:
    trusted_id = state.trusted_container_id
    if (
        trusted_id is None
        or not _trusted_snapshot_matches(state)
        or not _inspect_trusted_state(
            state,
            runner=runner,
            deadline=deadline,
            running=False,
        )
    ):
        _error("trusted audit container is not pristine and stopped")
    result: BrokerCommandResult | None = None
    failure: BaseException | None = None
    try:
        started = runner.run(
            (state.docker_executable, "start", trusted_id),
            deadline=deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
        if not _valid_removal(started, trusted_id) or not _inspect_trusted_state(
            state,
            runner=runner,
            deadline=deadline,
            running=True,
        ):
            _error("trusted audit container did not start safely")
        attested = runner.run(
            (
                state.docker_executable,
                "exec",
                f"--user={state.trusted_execution_uid}:{state.trusted_execution_gid}",
                "--workdir=/workspace",
                trusted_id,
                *TRUSTED_EXEC_PREFIX,
                "python3",
                "-I",
                "-c",
                ATTEST_SCRIPT,
                state.snapshot_digest or "",
                str(state.trusted_execution_uid),
                str(state.trusted_execution_gid),
                str(HARD_LIMITS.temp_bytes),
            ),
            deadline=deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
        if attested.returncode != 0 or attested.stdout or attested.stderr:
            _error("trusted audit snapshot attestation failed")
        result = runner.run(
            (
                state.docker_executable,
                "exec",
                f"--user={state.trusted_execution_uid}:{state.trusted_execution_gid}",
                "--workdir=/workspace",
                trusted_id,
                *TRUSTED_EXEC_PREFIX,
                "bash",
                "-c",
                command_script,
            ),
            deadline=deadline,
            output_limit=output_limit,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError, KeyboardInterrupt) as exc:
        failure = exc
    reset_ok = False
    reset_deadline = time.monotonic() + state.docker_control_seconds
    try:
        runner.run(
            (state.docker_executable, "kill", "--signal=KILL", trusted_id),
            deadline=reset_deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
        reset_ok = _inspect_trusted_state(
            state,
            runner=runner,
            deadline=reset_deadline,
            running=False,
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError, KeyboardInterrupt) as exc:
        if failure is None:
            failure = exc
    if not reset_ok:
        _error("trusted audit container reset could not be verified")
    if failure is not None:
        raise failure
    if result is None:
        _error("trusted audit command result is unavailable")
    return result


def _refusal() -> BrokerCommandResult:
    return BrokerCommandResult(
        returncode=126,
        stdout=b"",
        stderr=b"audit Docker broker refused request\n",
    )


def invoke_audit_docker_broker(
    state_path: Path,
    arguments: tuple[str, ...],
    *,
    runner: DockerExecutionRunner | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> BrokerCommandResult:
    active_runner: DockerExecutionRunner = (
        _SubprocessDockerExecutionRunner() if runner is None else runner
    )
    try:
        with _locked_state(state_path) as locked:
            state = _read_state_unlocked(locked)
            now = clock()
            decision = _decide(state, arguments, now)
            if decision.state != state:
                _write_state_unlocked(locked, decision.state)
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        raise

    if decision.kind == "refuse":
        return _refusal()
    if decision.kind == "breach":
        _perform_cleanup(
            state_path,
            runner=active_runner,
            clock=clock,
            close_on_success=False,
        )
        return _refusal()
    if decision.kind == "emulated":
        return BrokerCommandResult(returncode=0, stdout=decision.stdout, stderr=b"")

    output_limit = (
        decision.state.per_call_reserved_output_bytes
        if decision.kind in {"bootstrap", "terminal"}
        else _CONTROL_OUTPUT_LIMIT
    )
    try:
        command_deadline = _command_deadline(decision.state, decision.kind, clock())
        if decision.kind == "terminal" and decision.isolated_workspace:
            result = _run_isolated_terminal(
                decision.state,
                arguments[4],
                runner=active_runner,
                deadline=command_deadline,
                output_limit=output_limit,
            )
        else:
            if decision.kind == "remove" and not _remove_trusted_container(
                decision.state,
                runner=active_runner,
                deadline=command_deadline,
            ):
                _error("trusted audit container cleanup failed")
            result = active_runner.run(
                (decision.state.docker_executable, *arguments),
                deadline=command_deadline,
                output_limit=output_limit,
                env=dict(_MINIMAL_DOCKER_ENV),
            )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError, KeyboardInterrupt) as exc:
        if decision.kind == "terminal":
            updated = _release_terminal_reservation(
                state_path,
                receipt_id=decision.receipt_id,
                result=None,
                duration_ms=None,
                output_bytes=None,
                breach_reason="terminal execution failure",
            )
        else:
            with _locked_state(state_path) as locked:
                current = _read_state_unlocked(locked)
                updated = _breach_control(
                    current,
                    decision,
                    "Docker control failure",
                )
                _write_state_unlocked(locked, updated)
        _perform_cleanup(
            state_path,
            runner=active_runner,
            clock=clock,
            close_on_success=False,
        )
        if isinstance(exc, KeyboardInterrupt):
            raise
        return _refusal()

    if decision.kind == "terminal":
        output_bytes = len(result.stdout) + len(result.stderr)
        finished_at = clock()
        duration_ms = (
            None
            if decision.started_at is None
            else max(0, round((finished_at - decision.started_at) * 1000))
        )
        updated = _release_terminal_reservation(
            state_path,
            receipt_id=decision.receipt_id,
            result=result,
            duration_ms=duration_ms,
            output_bytes=output_bytes,
            breach_reason=(
                "terminal output limit"
                if output_bytes > decision.state.per_call_reserved_output_bytes
                else None
            ),
        )
        if updated.limit_breach:
            _perform_cleanup(
                state_path,
                runner=active_runner,
                clock=clock,
                close_on_success=False,
            )
            return _refusal()
        return result

    valid = (
        _valid_image_entrypoint(result)
        if decision.kind == "image"
        else _valid_network(result)
        if decision.kind == "network"
        else result.returncode == 0 and len(result.stdout) + len(result.stderr) <= output_limit
        if decision.kind == "bootstrap"
        else _valid_removal(result, decision.state.container_id)
    )
    if valid:
        completed = _complete_control(state_path, decision)
        if completed.limit_breach:
            _perform_cleanup(
                state_path,
                runner=active_runner,
                clock=clock,
                close_on_success=False,
            )
            return _refusal()
        return result

    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        updated = _breach_control(
            current,
            decision,
            "Docker response drift",
        )
        _write_state_unlocked(locked, updated)
    _perform_cleanup(
        state_path,
        runner=active_runner,
        clock=clock,
        close_on_success=False,
    )
    return _refusal()


def cleanup_audit_docker_broker(
    state_path: Path,
    *,
    runner: DockerExecutionRunner | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> BrokerCommandResult:
    active_runner: DockerExecutionRunner = (
        _SubprocessDockerExecutionRunner() if runner is None else runner
    )
    return _perform_cleanup(
        state_path,
        runner=active_runner,
        clock=clock,
        close_on_success=True,
    )
