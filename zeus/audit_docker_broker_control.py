from __future__ import annotations

import json
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
from zeus.audit_models import AuditCommandReceipt
from zeus.audit_receipts import finalize_command_tag

_TRUSTED_CLEANUP_FORMAT = (
    "{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t"
    '{{json (index .Config.Labels "com.zeus.audit.run-id")}}\t'
    '{{json (index .Config.Labels "com.zeus.audit.trusted-command")}}'
)


def _valid_removal(result: BrokerCommandResult, container_id: str) -> bool:
    return (
        result.returncode == 0
        and result.stdout == f"{container_id}\n".encode("ascii")
        and not result.stderr
    )


def _container_presence(
    state: AuditDockerBrokerState,
    container_id: str,
    *,
    runner: DockerExecutionRunner,
    deadline: float,
) -> bool | None:
    try:
        result = runner.run(
            (
                state.docker_executable,
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"id={container_id}",
                "--format",
                "{{.ID}}",
            ),
            deadline=deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        return None
    if result.returncode != 0 or result.stderr:
        return None
    if not result.stdout:
        return False
    if result.stdout == f"{container_id}\n".encode("ascii"):
        return True
    return None


def _remove_trusted_container(
    state: AuditDockerBrokerState,
    *,
    runner: DockerExecutionRunner,
    deadline: float,
) -> bool:
    trusted_id = state.trusted_container_id
    trusted_name = state.trusted_container_name
    if trusted_id is None and trusted_name is None:
        return True
    if trusted_id is None or trusted_name is None:
        return False
    presence = _container_presence(
        state,
        trusted_id,
        runner=runner,
        deadline=deadline,
    )
    if presence is not True:
        return presence is False
    try:
        inspected = runner.run(
            (
                state.docker_executable,
                "inspect",
                "--format",
                _TRUSTED_CLEANUP_FORMAT,
                trusted_id,
            ),
            deadline=deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        return False
    if inspected.returncode != 0:
        return (
            _container_presence(
                state,
                trusted_id,
                runner=runner,
                deadline=deadline,
            )
            is False
        )
    if inspected.stderr or not inspected.stdout.endswith(b"\n"):
        return False
    try:
        fields = tuple(
            json.loads(field)
            for field in inspected.stdout[:-1].decode("utf-8", errors="strict").split("\t")
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if fields != (
        trusted_id,
        f"/{trusted_name}",
        state.image_id,
        state.profile_name.removeprefix("audit-"),
        "true",
    ):
        return False
    try:
        removed = runner.run(
            (state.docker_executable, "rm", "-f", trusted_id),
            deadline=deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
    except (AuditDockerBrokerError, OSError, TypeError, ValueError):
        return False
    return _valid_removal(removed, trusted_id) or (
        _container_presence(
            state,
            trusted_id,
            runner=runner,
            deadline=deadline,
        )
        is False
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
    receipt_id: str | None,
    result: BrokerCommandResult | None,
    duration_ms: int | None,
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
            active_trusted_receipt_id=(
                None
                if current.active_trusted_receipt_id == receipt_id
                else current.active_trusted_receipt_id
            ),
        )
        if current.schema_version >= 2:
            if receipt_id is None or current.receipt_hmac_key is None:
                _error("audit Docker broker terminal receipt is unavailable")
            matches = [
                index
                for index, receipt in enumerate(current.terminal_receipts)
                if receipt.receipt_id == receipt_id and receipt.state == "inflight"
            ]
            if len(matches) != 1:
                _error("audit Docker broker terminal receipt binding is invalid")
            index = matches[0]
            receipt = current.terminal_receipts[index]
            if result is None:
                finalized = replace(
                    receipt,
                    command_tag=finalize_command_tag(
                        key_hex=current.receipt_hmac_key,
                        identity_tag=receipt.command_tag,
                        state="execution_failed",
                        returncode=None,
                        duration_ms=None,
                        stdout_bytes=None,
                        stderr_bytes=None,
                    ),
                    state="execution_failed",
                )
            else:
                if duration_ms is None or output_bytes is None:
                    _error("audit Docker broker terminal receipt result is incomplete")
                finalized = replace(
                    receipt,
                    command_tag=finalize_command_tag(
                        key_hex=current.receipt_hmac_key,
                        identity_tag=receipt.command_tag,
                        state="exited",
                        returncode=result.returncode,
                        duration_ms=duration_ms,
                        stdout_bytes=len(result.stdout),
                        stderr_bytes=len(result.stderr),
                    ),
                    state="exited",
                    returncode=result.returncode,
                    duration_ms=duration_ms,
                    stdout_bytes=len(result.stdout),
                    stderr_bytes=len(result.stderr),
                )
            receipts = list(current.terminal_receipts)
            receipts[index] = finalized
            updated = replace(updated, terminal_receipts=tuple(receipts))
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
            if state.schema_version >= 2 and state.receipt_hmac_key is None:
                _error("audit Docker broker receipt key is unavailable")

            def orphan(receipt: AuditCommandReceipt) -> AuditCommandReceipt:
                if receipt.state != "inflight":
                    return receipt
                if state.receipt_hmac_key is None:
                    _error("audit Docker broker receipt key is unavailable")
                return replace(
                    receipt,
                    command_tag=finalize_command_tag(
                        key_hex=state.receipt_hmac_key,
                        identity_tag=receipt.command_tag,
                        state="orphaned",
                        returncode=None,
                        duration_ms=None,
                        stdout_bytes=None,
                        stderr_bytes=None,
                    ),
                    state="orphaned",
                )

            state = _breached(
                replace(
                    state,
                    active_terminal_calls=0,
                    aggregate_reserved_output_bytes=0,
                    active_trusted_receipt_id=None,
                    terminal_receipts=tuple(orphan(receipt) for receipt in state.terminal_receipts),
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
        trusted_successful = _remove_trusted_container(
            claimed,
            runner=runner,
            deadline=cleanup_deadline,
        )
        result = runner.run(
            (claimed.docker_executable, *_expected_removal(claimed)),
            deadline=cleanup_deadline,
            output_limit=_CONTROL_OUTPUT_LIMIT,
            env=dict(_MINIMAL_DOCKER_ENV),
        )
        successful = trusted_successful and _valid_removal(result, claimed.container_id)
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
