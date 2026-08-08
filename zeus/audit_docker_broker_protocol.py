from __future__ import annotations

import secrets
from dataclasses import replace

from zeus.audit_docker_broker_core import (
    _CONTAINER_TEMP,
    _MAX_ARGV_BYTES,
    _MAX_ARGV_ITEMS,
    _SESSION_ID_RE,
    AuditDockerBrokerState,
    _Decision,
)


def _expected_bootstrap_script(session_id: str) -> str:
    snapshot = f"{_CONTAINER_TEMP}/hermes-snap-{session_id}.sh"
    temporary = f"{snapshot}.tmp.XXXXXXXXXX"
    marker = f"__HERMES_CWD_{session_id}__"
    return (
        "umask 077\n"
        f"__hermes_snap_tmp=$(mktemp {temporary}) || exit 1\n"
        "{ ( unset ${!HERMES_SESSION_*} ${!HERMES_CRON_AUTO_DELIVER_*} "
        'HERMES_UI_SESSION_ID 2>/dev/null; export -p; ) || true; } > "$__hermes_snap_tmp"\n'
        "__hermes_fns=$(declare -F | awk '{print $3}' | grep -vE '^_[^_]') || true\n"
        '[ -n "$__hermes_fns" ] && declare -f $__hermes_fns >> "$__hermes_snap_tmp" '
        "2>/dev/null || true\n"
        'alias -p >> "$__hermes_snap_tmp"\n'
        "echo 'shopt -s expand_aliases' >> \"$__hermes_snap_tmp\"\n"
        "echo 'set +e' >> \"$__hermes_snap_tmp\"\n"
        "echo 'set +u' >> \"$__hermes_snap_tmp\"\n"
        f'mv -f "$__hermes_snap_tmp" {snapshot} || rm -f "$__hermes_snap_tmp"\n'
        "builtin cd -- /workspace 2>/dev/null || true\n"
        f"""printf '\\n{marker}%s{marker}\\n' "$(pwd -P)"\n"""
    )


def _bootstrap_session_id(script: str) -> str | None:
    prefix = "__hermes_snap_tmp=$(mktemp /tmp/hermes-snap-"
    start = script.find(prefix)
    if start < 0:
        return None
    identifier_start = start + len(prefix)
    session_id = script[identifier_start : identifier_start + 12]
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        return None
    if script != _expected_bootstrap_script(session_id):
        return None
    return session_id


def _expected_cgroup_probe(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "run",
        "--rm",
        "--cpus",
        "0.5",
        "--memory",
        "64m",
        "--pids-limit",
        "32",
        state.image_ref,
        "sleep",
        "0",
    )


def _expected_image_inspect(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "image",
        "inspect",
        state.image_ref,
        "--format",
        "{{json .Config.Entrypoint}}",
    )


def _expected_reuse_probe(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "ps",
        "-a",
        "--filter",
        "label=hermes-agent=1",
        "--filter",
        "label=hermes-task-id=default",
        "--filter",
        f"label=hermes-profile={state.profile_name}",
        "--format",
        '{{.ID}}\t{{.State}}\t{{.Label "hermes-egress"}}',
    )


def _expected_network_inspect(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return (
        "inspect",
        "--format",
        "{{.HostConfig.NetworkMode}}",
        state.container_id,
    )


def _expected_removal(state: AuditDockerBrokerState) -> tuple[str, ...]:
    return ("rm", "-f", state.container_id)


def _arguments_are_bounded(arguments: tuple[str, ...]) -> bool:
    if not isinstance(arguments, tuple) or not 1 <= len(arguments) <= _MAX_ARGV_ITEMS:
        return False
    total = 0
    for argument in arguments:
        if not isinstance(argument, str) or "\0" in argument:
            return False
        try:
            total += len(argument.encode("utf-8", errors="strict")) + 1
        except UnicodeEncodeError:
            return False
        if total > _MAX_ARGV_BYTES:
            return False
    return True


def _breached(state: AuditDockerBrokerState, reason: str) -> AuditDockerBrokerState:
    cleanup_state = (
        state.cleanup_state if state.cleanup_state in {"running", "complete"} else "requested"
    )
    return replace(
        state,
        phase="breached",
        limit_breach=True,
        breach_reason=reason,
        cleanup_state=cleanup_state,
        cleanup_owner=(state.cleanup_owner if cleanup_state == "running" else None),
        cleanup_lease_deadline=(
            state.cleanup_lease_deadline if cleanup_state == "running" else None
        ),
    )


def _claim_cleanup(
    state: AuditDockerBrokerState,
    now: float,
) -> AuditDockerBrokerState:
    return replace(
        state,
        cleanup_state="running",
        cleanup_owner=secrets.token_hex(16),
        cleanup_lease_deadline=now + state.docker_control_seconds,
    )


def _decide(
    state: AuditDockerBrokerState,
    arguments: tuple[str, ...],
    now: float,
) -> _Decision:
    if state.phase in {"closed", "breached"}:
        return _Decision("refuse", state)
    if state.cleanup_state == "running":
        return _Decision("refuse", state)
    if (
        state.phase == "terminal"
        and arguments == _expected_removal(state)
        and (state.active_terminal_calls or state.aggregate_reserved_output_bytes)
    ):
        return _Decision("refuse", state)
    if now >= state.deadline:
        return _Decision("breach", _breached(state, "overall deadline"))
    if not _arguments_are_bounded(arguments):
        return _Decision("breach", _breached(state, "invalid argv"))

    if state.phase == "expect_version" and arguments == ("version",):
        return _Decision("emulated", replace(state, phase="expect_cgroup_probe"))
    if state.phase == "expect_cgroup_probe" and arguments == _expected_cgroup_probe(state):
        return _Decision("emulated", replace(state, phase="expect_image_or_info"))
    if state.phase == "expect_image_or_info":
        if arguments == ("info", "--format", "{{.Driver}}"):
            return _Decision("emulated", replace(state, phase="expect_image"), b"vfs\n")
        if arguments == _expected_image_inspect(state):
            return _Decision("image", replace(state, phase="image_inflight"))
    elif state.phase == "expect_image" and arguments == _expected_image_inspect(state):
        return _Decision("image", replace(state, phase="image_inflight"))
    elif state.phase == "expect_reuse" and arguments == _expected_reuse_probe(state):
        output = f"{state.container_id}\trunning\toff\n".encode("ascii")
        return _Decision("emulated", replace(state, phase="expect_network"), output)
    elif state.phase == "expect_network" and arguments == _expected_network_inspect(state):
        return _Decision("network", replace(state, phase="network_inflight"))
    elif (
        state.phase == "expect_bootstrap"
        and len(arguments) == 6
        and arguments[:5] == ("exec", state.container_id, "bash", "-l", "-c")
    ):
        session_id = _bootstrap_session_id(arguments[5])
        if session_id is not None:
            return _Decision(
                "bootstrap",
                replace(state, phase="bootstrap_inflight"),
                session_id=session_id,
            )
    elif state.phase == "terminal":
        if arguments == _expected_removal(state):
            return _Decision(
                "remove",
                _claim_cleanup(replace(state, phase="remove_inflight"), now),
            )
        if len(arguments) == 5 and arguments[:4] == ("exec", state.container_id, "bash", "-c"):
            if state.terminal_calls >= state.terminal_call_limit:
                return _Decision("breach", _breached(state, "terminal call limit"))
            reservation = state.per_call_reserved_output_bytes
            if (
                state.terminal_output_bytes + state.aggregate_reserved_output_bytes + reservation
                > state.total_output_limit_bytes
            ):
                return _Decision("breach", _breached(state, "terminal output limit"))
            updated = replace(
                state,
                terminal_calls=state.terminal_calls + 1,
                aggregate_reserved_output_bytes=(
                    state.aggregate_reserved_output_bytes + reservation
                ),
                active_terminal_calls=state.active_terminal_calls + 1,
            )
            return _Decision("terminal", updated)
    return _Decision("breach", _breached(state, "protocol drift"))
