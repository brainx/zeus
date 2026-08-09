from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from zeus.gateway_launcher import (
    MAX_PAYLOAD_BYTES,
    remove_marker_if_owned,
)
from zeus.gateway_marker import (
    GatewayGeneration,
)
from zeus.gateway_runtime_core import (
    _TRANSIENT_POST_EXEC_MARKER_REASONS,
    LaunchEffect,
    MarkerObservation,
    PopenLike,
    gateway_process_launch_kwargs,
)
from zeus.gateway_runtime_stop import _GatewayRuntimeStop
from zeus.hermes_profile_config import HermesProfileConfigError
from zeus.hermes_profile_environment import HermesProfileEnvironmentError
from zeus.hermes_security import UnsupportedFeishuWebhookModeError
from zeus.models import BotRecord, TemplateError
from zeus.private_io import open_private_append
from zeus.readiness import ReadinessProbe


class _GatewayRuntimeLaunch(_GatewayRuntimeStop):
    def preflight_start(
        self,
        record: BotRecord,
        *,
        timeout_seconds: float | None,
    ) -> ReadinessProbe | None:
        expected_profile = (Path(self.adapter.hermes_root) / "profiles" / record.bot_id).resolve()
        if Path(record.profile_path).resolve() != expected_profile:
            raise TemplateError("registered bot profile does not match the Hermes profile path")
        safe_profile = self.safe_profile_path(record.bot_id, record.profile_path)
        if not safe_profile.is_dir() or safe_profile.is_symlink():
            raise TemplateError("registered bot profile is not a safe directory")
        try:
            _argv, env = self.adapter.command(record.bot_id, "gateway", "run")
            readiness = self.readiness_probe(env, timeout_seconds=timeout_seconds)
            self.adapter.launcher_payload(
                record.bot_id,
                operation_id="0" * 32,
                desired_revision=max(1, record.desired_revision + 1),
                readiness_probe=readiness,
            )
        except (
            HermesProfileConfigError,
            HermesProfileEnvironmentError,
            UnsupportedFeishuWebhookModeError,
        ) as exc:
            raise TemplateError(str(exc)) from exc
        return readiness

    def launch(
        self,
        record: BotRecord,
        *,
        probe: ReadinessProbe | None,
        wait: bool,
        marker_lock: Callable[[BotRecord], contextlib.AbstractContextManager[object]] | None = None,
        marker_matcher: Callable[..., MarkerObservation] | None = None,
        ack_reader: Callable[[int], bytes] | None = None,
        pipe_writer: Callable[[int, bytes], None] | None = None,
    ) -> LaunchEffect:
        operation_id = record.pending_operation_id
        if record.pending_action not in {"start", "restart"} or operation_id is None:
            raise RuntimeError("gateway launch requires a pending start or restart intent")
        payload = self.adapter.launcher_payload(
            record.bot_id,
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            readiness_probe=probe,
        )
        marker_data = payload["marker"]
        if type(marker_data) is not dict:
            raise RuntimeError("launcher produced an invalid marker payload")
        expected_fingerprint = str(marker_data["command_fingerprint"])
        process: PopenLike | None = None
        generation: GatewayGeneration | None = None
        marker_acknowledged = False
        payload_read = payload_write = ack_read = ack_write = -1
        hooks = self._hooks()
        marker_lock = marker_lock or self.marker_publication_lock
        marker_matcher = marker_matcher or self.matching_runtime_marker
        ack_reader = ack_reader or self.read_launcher_ack
        pipe_writer = pipe_writer or self.write_pipe_payload
        try:
            encoded_payload = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            if not encoded_payload or len(encoded_payload) > MAX_PAYLOAD_BYTES:
                raise ValueError("launcher payload is too large")
            with open_private_append(self.log_path(record.profile_path)) as log_file:
                payload_read, payload_write = hooks.pipe()
                ack_read, ack_write = hooks.pipe()
                launcher_argv = self.adapter.launcher_command(payload_read, ack_write)
                process = self.popen_factory(
                    launcher_argv,
                    env=dict(os.environ),
                    stdout=log_file,
                    stderr=log_file,
                    pass_fds=(payload_read, ack_write),
                    close_fds=True,
                    **gateway_process_launch_kwargs(),
                )
            hooks.close(payload_read)
            payload_read = -1
            hooks.close(ack_write)
            ack_write = -1
            pipe_writer(payload_write, encoded_payload)
            hooks.close(payload_write)
            payload_write = -1
            acknowledgment = ack_reader(ack_read)
            hooks.close(ack_read)
            ack_read = -1
            if acknowledgment != b"1":
                raise RuntimeError("gateway launcher did not acknowledge marker publication")
            marker_acknowledged = True
            with marker_lock(record):
                registration_deadline = time.monotonic() + max(self.startup_grace_seconds, 0)
                while True:
                    marker = marker_matcher(
                        record,
                        expected_fingerprint=expected_fingerprint,
                        expected_pid=process.pid,
                        require_live_command=True,
                    )
                    generation = self.gateway_generation(marker)
                    if marker.kind == "live" and generation is not None:
                        break
                    if process.poll() is not None:
                        raise RuntimeError("gateway process exited before marker registration")
                    remaining = registration_deadline - time.monotonic()
                    if marker.reason not in _TRANSIENT_POST_EXEC_MARKER_REASONS or remaining <= 0:
                        raise RuntimeError(
                            "gateway launcher ownership marker could not be verified: "
                            + marker.reason
                        )
                    time.sleep(min(0.01, remaining))
            self._processes[record.bot_id] = process
        except BaseException as exc:
            for fd in (payload_read, payload_write, ack_read, ack_write):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        hooks.close(fd)
            if process is None:
                if not isinstance(exc, (OSError, ValueError)):
                    raise
                self._processes.pop(record.bot_id, None)
                return LaunchEffect(
                    "launch_failed",
                    reason=str(exc),
                    error_type=type(exc).__name__,
                )
            returncode = process.poll()
            cleanup_complete = self.cleanup_interrupted_launch(
                record,
                process,
                expected_fingerprint=expected_fingerprint,
            )
            if not isinstance(exc, Exception):
                raise
            if marker_acknowledged and returncode is not None and cleanup_complete:
                if generation is None:
                    generation = GatewayGeneration(
                        operation_id=operation_id,
                        desired_revision=record.desired_revision,
                        pid=process.pid,
                        command_fingerprint=expected_fingerprint,
                        proc_start_fingerprint=None,
                    )
                return LaunchEffect(
                    "startup_exited",
                    pid=process.pid,
                    generation=generation,
                    reason="gateway exited during startup grace period",
                    returncode=returncode,
                    cleanup_complete=True,
                )
            return LaunchEffect(
                "registration_failed_clean" if cleanup_complete else "registration_failed_unknown",
                pid=None if cleanup_complete else process.pid,
                reason=str(exc),
                error_type=type(exc).__name__,
                cleanup_complete=cleanup_complete,
            )
        if process is None or generation is None:
            raise RuntimeError("gateway process factory returned no process")
        returncode = self.poll_startup(process)
        if returncode is not None:
            self.remove_gateway_generation_marker(record, generation)
            self._processes.pop(record.bot_id, None)
            return LaunchEffect(
                "startup_exited",
                generation=generation,
                reason="gateway exited during startup grace period",
                returncode=returncode,
            )
        if probe is not None:
            if wait:
                readiness = self.wait_for_readiness(process, probe)
                if process.poll() is not None:
                    returncode = process.poll()
                    self.remove_gateway_generation_marker(record, generation)
                    self._processes.pop(record.bot_id, None)
                    return LaunchEffect(
                        "readiness_exited",
                        generation=generation,
                        reason="gateway process exited during readiness check",
                        returncode=returncode,
                    )
                if readiness.ready:
                    return LaunchEffect("ready", process.pid, generation)
                return LaunchEffect(
                    "readiness_timeout",
                    process.pid,
                    generation,
                    reason="readiness probe timed out",
                    readiness_message=readiness.message,
                )
            return LaunchEffect("readiness_pending", process.pid, generation)
        return LaunchEffect("running", process.pid, generation)

    def cleanup_interrupted_launch(
        self,
        record: BotRecord,
        process: PopenLike,
        *,
        expected_fingerprint: str,
    ) -> bool:
        cleanup_errors: list[str] = []
        if not self.terminate_spawned_process(process, cleanup_errors):
            return False
        self._processes.pop(record.bot_id, None)
        operation_id = record.pending_operation_id
        if operation_id is None:
            return False
        remove_marker_if_owned(
            self.safe_profile_path(record.bot_id, record.profile_path),
            operation_id=operation_id,
            desired_revision=record.desired_revision,
            pid=process.pid,
            command_fingerprint=expected_fingerprint,
        )
        return self.read_strict_runtime_marker(record.bot_id, record.profile_path).kind == "missing"

    def cleanup_registered_launch(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool:
        process = self._processes.get(record.bot_id)
        if process is None or process.pid != generation.pid:
            return False
        cleanup_errors: list[str] = []
        if not self.terminate_spawned_process(process, cleanup_errors):
            return False
        self._processes.pop(record.bot_id, None)
        self.remove_gateway_generation_marker(record, generation)
        return self.read_strict_runtime_marker(record.bot_id, record.profile_path).kind == "missing"
