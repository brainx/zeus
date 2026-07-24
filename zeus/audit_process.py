"""Ownership-preserving subprocess-group observation and teardown."""

from __future__ import annotations

import errno
import os
import signal
import subprocess  # nosec B404
import time
from collections.abc import Callable
from enum import StrEnum
from typing import Protocol, cast


class AuditProcessError(RuntimeError):
    """Raised when a process can no longer be observed without losing ownership."""


class ProcessGroupState(StrEnum):
    absent = "absent"
    present = "present"
    unknown = "unknown"


class _WaitIdResult(Protocol):
    si_code: int
    si_status: int


_WaitId = Callable[[int, int, int], _WaitIdResult | None]


def observe_process_exit(process: subprocess.Popen[bytes]) -> int | None:
    """Return the exit code without reaping the group leader."""
    if process.returncode is not None:
        raise AuditProcessError("process group leader was already reaped")
    waitid = cast(_WaitId | None, getattr(os, "waitid", None))
    if waitid is None:
        raise AuditProcessError("non-reaping process observation is unavailable")
    try:
        result = waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except (AttributeError, ChildProcessError, OSError) as exc:
        raise AuditProcessError("process group leader identity is unavailable") from exc
    if result is None:
        return None
    if result.si_code == os.CLD_EXITED:
        return result.si_status
    if result.si_code in {os.CLD_KILLED, os.CLD_DUMPED}:
        return -result.si_status
    raise AuditProcessError("process exit state is unsupported")


def wait_process_exit(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    poll_seconds: float = 0.01,
) -> int:
    """Wait for exit while deliberately retaining the leader as an ownership pin."""
    while True:
        returncode = observe_process_exit(process)
        if returncode is not None:
            return returncode
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, 0)
        time.sleep(min(poll_seconds, remaining))


def _owned_group_state(process: subprocess.Popen[bytes]) -> ProcessGroupState:
    if process.returncode is not None:
        return ProcessGroupState.unknown
    leader_exited_without_group = False
    try:
        group_id = os.getpgid(process.pid)
        if group_id != process.pid:
            return ProcessGroupState.unknown
    except ProcessLookupError:
        try:
            returncode = observe_process_exit(process)
        except AuditProcessError:
            return ProcessGroupState.unknown
        if returncode is None:
            return ProcessGroupState.unknown
        leader_exited_without_group = True
    except OSError:
        return ProcessGroupState.unknown
    if leader_exited_without_group:
        try:
            os.killpg(process.pid, 0)
        except (PermissionError, ProcessLookupError):
            return ProcessGroupState.absent
        except OSError:
            return ProcessGroupState.unknown
        return ProcessGroupState.present
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return ProcessGroupState.absent
    except OSError:
        return ProcessGroupState.unknown
    return ProcessGroupState.present


def _signal_pinned_group(
    group_id: int,
    sent_signal: signal.Signals,
) -> ProcessGroupState:
    try:
        os.killpg(group_id, sent_signal)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return ProcessGroupState.absent
        return ProcessGroupState.unknown
    return ProcessGroupState.present


def _wait_for_reaped_group_absence(
    group_id: int,
    *,
    deadline: float,
) -> bool:
    """Observe only; never signal after the leader PID has been released."""
    while True:
        try:
            os.killpg(group_id, 0)
            state = ProcessGroupState.present
        except ProcessLookupError:
            state = ProcessGroupState.absent
        except OSError as exc:
            state = (
                ProcessGroupState.absent if exc.errno == errno.ESRCH else ProcessGroupState.unknown
            )
        if state is ProcessGroupState.absent:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _wait_for_known_group_state(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
) -> ProcessGroupState:
    while True:
        state = _owned_group_state(process)
        if state is not ProcessGroupState.unknown:
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ProcessGroupState.unknown
        time.sleep(min(0.01, remaining))


def _reap_if_exited(
    process: subprocess.Popen[bytes],
    *,
    timeout: float,
) -> bool:
    """Reap an observed terminal leader without waiting on a live process."""
    if process.returncode is not None:
        return True
    try:
        returncode = observe_process_exit(process)
    except AuditProcessError:
        return False
    if returncode is None:
        return False
    try:
        process.wait(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.returncode is not None


def _reap_and_verify_group_absence(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    wait_timeout: float,
) -> bool:
    try:
        wait_process_exit(process, deadline=deadline)
        process.wait(timeout=wait_timeout)
    except (AuditProcessError, OSError, subprocess.TimeoutExpired):
        return False
    if process.returncode is None:
        return False
    return _wait_for_reaped_group_absence(
        process.pid,
        deadline=time.monotonic() + wait_timeout,
    )


def stop_process_group(
    process: subprocess.Popen[bytes],
    *,
    term_seconds: float = 0.2,
    kill_seconds: float = 1.0,
) -> bool:
    """Stop only the group still pinned by its unreaped original leader."""
    if process.returncode is not None:
        return False
    try:
        observe_process_exit(process)
    except AuditProcessError:
        return False

    state = _wait_for_known_group_state(
        process,
        deadline=time.monotonic() + term_seconds,
    )
    if state is ProcessGroupState.unknown:
        _reap_if_exited(process, timeout=kill_seconds)
        return False
    if state is ProcessGroupState.absent:
        return _reap_if_exited(process, timeout=kill_seconds)

    # The validated, unreaped session leader pins this PGID until process.wait().
    term_state = _signal_pinned_group(process.pid, signal.SIGTERM)
    if term_state is ProcessGroupState.unknown:
        return _reap_and_verify_group_absence(
            process,
            deadline=time.monotonic() + kill_seconds,
            wait_timeout=kill_seconds,
        )
    if term_state is ProcessGroupState.absent:
        return _reap_and_verify_group_absence(
            process,
            deadline=time.monotonic() + term_seconds,
            wait_timeout=kill_seconds,
        )

    try:
        wait_process_exit(
            process,
            deadline=time.monotonic() + term_seconds,
        )
    except AuditProcessError:
        _reap_if_exited(process, timeout=kill_seconds)
        return False
    except subprocess.TimeoutExpired:
        pass

    # The unreaped leader still pins the original group identity even if it
    # exited after SIGTERM. Signal the pinned group before releasing that PID.
    kill_state = _signal_pinned_group(process.pid, signal.SIGKILL)
    if kill_state is ProcessGroupState.unknown:
        return _reap_and_verify_group_absence(
            process,
            deadline=time.monotonic() + kill_seconds,
            wait_timeout=kill_seconds,
        )
    return _reap_and_verify_group_absence(
        process,
        deadline=time.monotonic() + kill_seconds,
        wait_timeout=kill_seconds,
    )
