from __future__ import annotations

import os
import platform
import subprocess  # nosec B404

from zeus import process_identity as _process_identity
from zeus.gateway_launcher import (
    _read_bounded_file,
    _remove_marker_if_owned_locked,
)
from zeus.gateway_marker import (
    GatewayGeneration,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.gateway_runtime import (
    KillFn,
    MarkerObservation,
    OwnershipCheck,
    PopenFactory,
    PopenLike,
    RuntimeHooks,
    SignalResult,
)
from zeus.readiness import ReadinessProbe, ReadinessResult, probe_once
from zeus.supervisor_registry import _SupervisorRegistry

PidAliveFn = _process_identity.PidAliveFn
CmdlineReader = _process_identity.CmdlineReader
ProcStartFingerprintReader = _process_identity.ProcStartFingerprintReader

_CommandCheck = _process_identity.CommandCheck
_PidState = _process_identity.PidState
_looks_like_python_interpreter = _process_identity.looks_like_python_interpreter
_read_linux_cmdline = _process_identity.read_linux_cmdline
_read_linux_process_start_fingerprint = _process_identity.read_linux_process_start_fingerprint
_resolve_executable = _process_identity.resolve_executable
_resolve_launcher_exec_target = _process_identity.resolve_launcher_exec_target
_safe_command_shape = _process_identity.safe_command_shape
_trusted_hermes_paths = _process_identity.trusted_hermes_paths
_verify_gateway_command = _process_identity.verify_gateway_command

_SignalResult = SignalResult
_MarkerObservation = MarkerObservation
_GatewayGeneration = GatewayGeneration

__all__ = [
    "CmdlineReader",
    "KillFn",
    "OwnershipCheck",
    "PidAliveFn",
    "PopenFactory",
    "PopenLike",
    "ProcStartFingerprintReader",
    "Supervisor",
    "_CommandCheck",
    "_GatewayGeneration",
    "_MarkerObservation",
    "_PidState",
    "_SignalResult",
    "_looks_like_python_interpreter",
    "_read_bounded_file",
    "_read_darwin_cmdline",
    "_read_darwin_process_start_fingerprint",
    "_read_linux_cmdline",
    "_read_linux_process_start_fingerprint",
    "_read_process_cmdline",
    "_read_process_start_fingerprint",
    "_readiness_probe_from_marker",
    "_readiness_probe_marker_payload",
    "_resolve_executable",
    "_resolve_launcher_exec_target",
    "_safe_command_shape",
    "_trusted_hermes_paths",
    "_verify_gateway_command",
]


class Supervisor(_SupervisorRegistry):
    @staticmethod
    def _default_cmdline_reader(pid: int) -> list[str] | None:
        return _read_process_cmdline(pid)

    @staticmethod
    def _default_process_start_fingerprint_reader(pid: int) -> str | None:
        return _read_process_start_fingerprint(pid)

    @staticmethod
    def _probe_once(probe: ReadinessProbe) -> ReadinessResult:
        return probe_once(
            probe.url,
            timeout_seconds=min(1.0, max(0.2, probe.interval_seconds)),
            expected_status=probe.expected_status,
            expected_platform=probe.expected_platform,
        )

    def _runtime_hooks(self) -> RuntimeHooks:
        return RuntimeHooks(
            pipe=os.pipe,
            close=os.close,
            read_bounded_file=_read_bounded_file,
            remove_marker_if_owned_locked=_remove_marker_if_owned_locked,
            probe_once=probe_once,
        )

    def _pid_state(self, pid: int) -> _PidState:
        if "_runtime" in self.__dict__:
            return self._runtime.pid_state(pid)
        if self.pid_alive_fn is not None:
            return _process_identity.pid_state(pid, pid_alive_fn=self.pid_alive_fn)

        def probe_with_current_kill(probe_pid: int) -> bool:
            os.kill(probe_pid, 0)
            return True

        return _process_identity.pid_state(pid, pid_alive_fn=probe_with_current_kill)

    @staticmethod
    def _process_start_fingerprint_required() -> bool:
        return platform.system() in {"Linux", "Darwin"}


def _read_process_cmdline(pid: int) -> list[str] | None:
    return _process_identity.read_process_cmdline(
        pid,
        system=platform.system(),
        run_process=subprocess.run,
    )


def _readiness_probe_marker_payload(probe: ReadinessProbe | None) -> dict[str, object] | None:
    return readiness_probe_to_payload(probe)


def _readiness_probe_from_marker(value: object) -> ReadinessProbe | None:
    return readiness_probe_from_payload(value)


def _read_darwin_cmdline(pid: int) -> list[str] | None:
    return _process_identity.read_darwin_cmdline(pid, run_process=subprocess.run)


def _read_process_start_fingerprint(pid: int) -> str | None:
    return _process_identity.read_process_start_fingerprint(
        pid,
        system=platform.system(),
        run_process=subprocess.run,
    )


def _read_darwin_process_start_fingerprint(pid: int) -> str | None:
    return _process_identity.read_darwin_process_start_fingerprint(
        pid,
        run_process=subprocess.run,
    )
