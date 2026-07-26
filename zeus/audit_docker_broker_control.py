from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from zeus.audit_docker_broker_core import (
    _CONTROL_OUTPUT_LIMIT,
    _MINIMAL_DOCKER_ENV,
    AuditDockerBrokerError,
    AuditDockerBrokerState,
    BrokerCommandResult,
    DockerExecutionRunner,
    _Decision,
    _error,
    _locked_state,
    _read_state_unlocked,
    _write_state_unlocked,
)
from zeus.audit_docker_broker_protocol import (
    _breached,
    _claim_cleanup,
    _expected_removal,
)


def _valid_removal(result: BrokerCommandResult, container_id: str) -> bool:
    return (
        result.returncode == 0
        and result.stdout == f"{container_id}\n".encode("ascii")
        and not result.stderr
    )


def _complete_control(
    state_path: Path,
    decision: _Decision,
) -> AuditDockerBrokerState:
    expected_phase = {
        "image": "image_inflight",
        "network": "network_inflight",
        "bootstrap": "bootstrap_inflight",
        "remove": "remove_inflight",
    }[decision.kind]
    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        if current.limit_breach:
            return current
        if decision.kind == "remove" and current.cleanup_state == "complete":
            return current
        cleanup_owner_changed = (
            decision.kind == "remove" and current.cleanup_owner != decision.state.cleanup_owner
        )
        if current.phase != expected_phase or cleanup_owner_changed:
            updated = _breached(current, "protocol state drift")
        elif decision.kind == "image":
            updated = replace(current, phase="expect_reuse")
        elif decision.kind == "network":
            updated = replace(current, phase="expect_bootstrap")
        elif decision.kind == "bootstrap":
            if decision.session_id is None:
                updated = _breached(current, "bootstrap state drift")
            else:
                updated = replace(
                    current,
                    phase="terminal",
                    bootstrap_complete=True,
                    session_id=decision.session_id,
                )
        else:
            updated = replace(
                current,
                phase="closed",
                cleanup_state="complete",
                cleanup_owner=None,
                cleanup_lease_deadline=None,
            )
        _write_state_unlocked(locked, updated)
        return updated


def _breach_control(
    current: AuditDockerBrokerState,
    decision: _Decision,
    reason: str,
) -> AuditDockerBrokerState:
    if (
        decision.kind == "remove"
        and current.cleanup_state == "running"
        and current.cleanup_owner == decision.state.cleanup_owner
    ):
        current = replace(
            current,
            cleanup_state="requested",
            cleanup_owner=None,
            cleanup_lease_deadline=None,
        )
    return _breached(current, reason)


def _release_terminal_reservation(
    state_path: Path,
    *,
    output_bytes: int | None,
    breach_reason: str | None,
) -> AuditDockerBrokerState:
    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        reservation = current.per_call_reserved_output_bytes
        if (
            current.active_terminal_calls < 1
            or current.aggregate_reserved_output_bytes < reservation
        ):
            _error("audit Docker broker reservation ledger is invalid")
        updated = replace(
            current,
            aggregate_reserved_output_bytes=(current.aggregate_reserved_output_bytes - reservation),
            active_terminal_calls=current.active_terminal_calls - 1,
        )
        if breach_reason is not None:
            updated = _breached(updated, breach_reason)
        elif not updated.limit_breach and output_bytes is not None:
            if (
                output_bytes > updated.per_call_reserved_output_bytes
                or updated.terminal_output_bytes + output_bytes > updated.total_output_limit_bytes
            ):
                updated = _breached(updated, "terminal output limit")
            else:
                updated = replace(
                    updated,
                    terminal_output_bytes=updated.terminal_output_bytes + output_bytes,
                )
        _write_state_unlocked(locked, updated)
        return updated


def _perform_cleanup(
    state_path: Path,
    *,
    runner: DockerExecutionRunner,
    clock: Callable[[], float],
    close_on_success: bool,
) -> BrokerCommandResult:
    with _locked_state(state_path) as locked:
        state = _read_state_unlocked(locked)
        now = clock()
        if state.cleanup_state == "complete":
            return BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
        if state.cleanup_state == "running":
            if state.cleanup_lease_deadline is None or now < state.cleanup_lease_deadline:
                return BrokerCommandResult(
                    returncode=126,
                    stdout=b"",
                    stderr=b"audit Docker broker cleanup is already running\n",
                )
        elif (
            state.phase
            in {
                "image_inflight",
                "network_inflight",
                "bootstrap_inflight",
            }
            or state.active_terminal_calls
        ):
            if now < state.deadline:
                return BrokerCommandResult(
                    returncode=126,
                    stdout=b"",
                    stderr=b"audit Docker broker execution is still running\n",
                )
            state = _breached(
                replace(
                    state,
                    active_terminal_calls=0,
                    aggregate_reserved_output_bytes=0,
                ),
                "orphaned execution",
            )
        claimed = _claim_cleanup(state, now)
        _write_state_unlocked(locked, claimed)
    cleanup_owner = claimed.cleanup_owner
    cleanup_deadline = claimed.cleanup_lease_deadline
    if cleanup_owner is None or cleanup_deadline is None:
        _error("audit Docker broker cleanup claim is invalid")
    try:
        result = runner.run(
            (claimed.docker_executable, *_expected_removal(claimed)),
            deadline=cleanup_deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
        successful = _valid_removal(result, claimed.container_id)
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        result = BrokerCommandResult(returncode=126, stdout=b"", stderr=b"")
        successful = False
    with _locked_state(state_path) as locked:
        current = _read_state_unlocked(locked)
        if current.cleanup_state == "complete":
            cleanup_succeeded = True
        elif current.cleanup_state != "running" or current.cleanup_owner != cleanup_owner:
            return BrokerCommandResult(
                returncode=126,
                stdout=b"",
                stderr=b"audit Docker broker cleanup ownership changed\n",
            )
        else:
            cleanup_succeeded = successful
        phase = (
            "closed"
            if cleanup_succeeded and close_on_success and not current.limit_breach
            else current.phase
        )
        if current.cleanup_state != "complete":
            updated = replace(
                current,
                phase=phase,
                cleanup_state="complete" if cleanup_succeeded else "failed",
                cleanup_owner=None,
                cleanup_lease_deadline=None,
            )
            _write_state_unlocked(locked, updated)
    if cleanup_succeeded:
        return result if successful else BrokerCommandResult(returncode=0, stdout=b"", stderr=b"")
    return BrokerCommandResult(
        returncode=126,
        stdout=b"",
        stderr=b"audit Docker broker cleanup failed\n",
    )
