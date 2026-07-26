"""Stateful Docker compatibility broker for the pinned audit terminal backend."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

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
        result = active_runner.run(
            (decision.state.docker_executable, *arguments),
            deadline=command_deadline,
            output_limit=output_limit,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        if decision.kind == "terminal":
            updated = _release_terminal_reservation(
                state_path,
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
        return _refusal()

    if decision.kind == "terminal":
        output_bytes = len(result.stdout) + len(result.stderr)
        updated = _release_terminal_reservation(
            state_path,
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
