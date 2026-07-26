from __future__ import annotations

import json
import os
import selectors
import subprocess  # nosec B404
import time
from contextlib import suppress
from typing import BinaryIO, cast

from zeus.audit_docker_broker_core import (
    _CONTROL_OUTPUT_LIMIT,
    _PROCESS_CHUNK,
    AuditDockerBrokerState,
    BrokerCommandResult,
    _DockerExecutionError,
)
from zeus.audit_process import AuditProcessError, stop_process_group, wait_process_exit


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if not stop_process_group(process):
        raise _DockerExecutionError("Docker execution process group cleanup could not be verified")


class _SubprocessDockerExecutionRunner:
    def run(
        self,
        argv: tuple[str, ...],
        *,
        deadline: float,
        output_limit: int,
        env: dict[str, str],
    ) -> BrokerCommandResult:
        try:
            process = subprocess.Popen(  # nosec B603
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            raise _DockerExecutionError("Docker execution could not be started") from exc
        if process.stdout is None or process.stderr is None:
            _stop_process(process)
            raise _DockerExecutionError("Docker execution pipes are unavailable")
        selector = selectors.DefaultSelector()
        output: dict[object, bytearray] = {
            process.stdout: bytearray(),
            process.stderr: bytearray(),
        }
        total = 0
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _stop_process(process)
                    raise _DockerExecutionError("Docker execution exceeded its deadline")
                events = selector.select(remaining)
                if not events:
                    _stop_process(process)
                    raise _DockerExecutionError("Docker execution exceeded its deadline")
                for key, _mask in events:
                    stream = cast(BinaryIO, key.fileobj)
                    try:
                        chunk = os.read(key.fd, _PROCESS_CHUNK)
                    except OSError as exc:
                        _stop_process(process)
                        raise _DockerExecutionError(
                            "Docker execution output could not be read"
                        ) from exc
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > output_limit:
                        _stop_process(process)
                        raise _DockerExecutionError(
                            "Docker execution output exceeded its byte limit"
                        )
                    output[stream].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop_process(process)
                raise _DockerExecutionError("Docker execution exceeded its deadline")
            try:
                returncode = wait_process_exit(process, deadline=deadline)
            except (AuditProcessError, subprocess.TimeoutExpired) as exc:
                _stop_process(process)
                raise _DockerExecutionError("Docker execution exceeded its deadline") from exc
            return BrokerCommandResult(
                returncode=returncode,
                stdout=bytes(output[process.stdout]),
                stderr=bytes(output[process.stderr]),
            )
        finally:
            selector.close()
            for close_stream in (process.stdout, process.stderr):
                with suppress(OSError):
                    close_stream.close()
            if process.returncode is None:
                _stop_process(process)


def _command_deadline(state: AuditDockerBrokerState, kind: str, now: float) -> float:
    seconds = (
        state.terminal_command_seconds
        if kind in {"bootstrap", "terminal"}
        else state.docker_control_seconds
    )
    deadline = min(state.deadline, now + seconds)
    if deadline <= now:
        raise _DockerExecutionError("Docker execution deadline has expired")
    return deadline


def _valid_image_entrypoint(result: BrokerCommandResult) -> bool:
    if result.returncode != 0 or result.stderr or len(result.stdout) > _CONTROL_OUTPUT_LIMIT:
        return False
    if not result.stdout.endswith(b"\n") or result.stdout.count(b"\n") != 1:
        return False
    try:
        value = json.loads(result.stdout[:-1].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        value is None
        or isinstance(value, str)
        or (isinstance(value, list) and all(isinstance(item, str) for item in value))
    )


def _valid_network(result: BrokerCommandResult) -> bool:
    return result.returncode == 0 and result.stdout == b"none\n" and not result.stderr
