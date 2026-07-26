from __future__ import annotations

import contextlib
import json
import platform
from collections.abc import Callable
from pathlib import Path

from zeus import process_identity
from zeus.gateway_launcher import (
    _confirm_marker_missing,
    _ConfirmedMissing,
    _open_logs,
    _open_profile_chain,
    _open_regular_marker,
    _reject_duplicate_keys,
    _validate_marker_bindings,
    remove_marker_if_owned,
)
from zeus.gateway_marker import (
    GatewayGeneration,
    is_owned_runtime_marker,
)
from zeus.gateway_runtime_core import (
    MarkerObservation,
    _GatewayRuntimeCore,
)
from zeus.models import BotRecord
from zeus.private_io import nofollow_absolute_path


class _GatewayRuntimeMarker(_GatewayRuntimeCore):
    def read_strict_runtime_marker(
        self,
        bot_id: str,
        registered_profile_path: str,
    ) -> MarkerObservation:
        profile_path = nofollow_absolute_path(Path(registered_profile_path))
        expected_profile = self.marker_profiles_root / bot_id
        if not profile_path.is_absolute() or profile_path != expected_profile:
            return MarkerObservation(
                "untrusted",
                reason="registered profile path does not match the trusted Hermes profile",
            )
        profile = None
        logs_fd = marker_fd = -1
        hooks = self._hooks()
        try:
            profile = _open_profile_chain(profile_path)
        except _ConfirmedMissing:
            return MarkerObservation("missing", reason="marker is missing")
        except (OSError, ValueError) as exc:
            return MarkerObservation(
                "untrusted", reason=f"registered profile cannot be opened safely: {exc}"
            )
        try:
            try:
                logs_fd = _open_logs(profile.fd, create=False)
            except ValueError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    try:
                        profile.confirm_missing("logs")
                    except (OSError, ValueError) as confirm_error:
                        return MarkerObservation(
                            "untrusted",
                            reason=f"marker directory absence is untrusted: {confirm_error}",
                        )
                    return MarkerObservation("missing", reason="marker is missing")
                return MarkerObservation(
                    "untrusted", reason=f"marker directory cannot be opened safely: {exc}"
                )
            try:
                marker_fd, marker_stat = _open_regular_marker(logs_fd)
                raw = hooks.read_bounded_file(marker_fd)
                marker_stat = _validate_marker_bindings(
                    profile,
                    logs_fd,
                    marker_fd,
                    marker_stat,
                )
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
            except FileNotFoundError:
                try:
                    _confirm_marker_missing(profile, logs_fd)
                except (OSError, ValueError) as confirm_error:
                    return MarkerObservation(
                        "untrusted", reason=f"marker absence is untrusted: {confirm_error}"
                    )
                return MarkerObservation("missing", reason="marker is missing")
            except ValueError as exc:
                if isinstance(exc.__cause__, FileNotFoundError):
                    try:
                        _confirm_marker_missing(profile, logs_fd)
                    except (OSError, ValueError) as confirm_error:
                        return MarkerObservation(
                            "untrusted", reason=f"marker absence is untrusted: {confirm_error}"
                        )
                    return MarkerObservation("missing", reason="marker is missing")
                return MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                return MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
        except FileNotFoundError as exc:
            return MarkerObservation("untrusted", reason=f"marker is invalid: {exc}")
        finally:
            for fd in (marker_fd, logs_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        hooks.close(fd)
            if profile is not None:
                profile.close()
        if type(value) is not dict:
            return MarkerObservation("untrusted", reason="marker is not an object")
        if marker_stat.st_nlink != 1:
            return MarkerObservation("untrusted", reason="marker has unexpected hard links")
        return MarkerObservation("present", payload=value)

    def matching_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_fingerprint: str,
        expected_pid: int | None = None,
        require_live_command: bool,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
    ) -> MarkerObservation:
        read_marker = read_marker or self.read_strict_runtime_marker
        observed = read_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return observed
        operation_id = record.pending_operation_id
        if operation_id is None:
            return MarkerObservation("untrusted", reason="pending operation is missing")
        return self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=expected_pid,
            expected_operation_id=operation_id,
            expected_revision=record.desired_revision,
            expected_fingerprint=expected_fingerprint,
            require_live_command=require_live_command,
        )

    def classify_schema3_runtime_marker(
        self,
        record: BotRecord,
        payload: dict[str, object],
        *,
        expected_pid: int | None = None,
        expected_operation_id: str | None = None,
        expected_revision: int | None = None,
        expected_fingerprint: str | None = None,
        require_live_command: bool,
    ) -> MarkerObservation:
        pid_value = payload.get("pid")
        if type(pid_value) is not int or pid_value <= 0:
            return MarkerObservation("untrusted", reason="marker PID is invalid")
        pid = pid_value
        if expected_pid is not None and pid != expected_pid:
            return MarkerObservation("untrusted", reason="marker PID does not match")
        operation_id = payload.get("operation_id")
        revision = payload.get("desired_revision")
        fingerprint = payload.get("command_fingerprint")
        if (
            type(operation_id) is not str
            or type(revision) is not int
            or type(fingerprint) is not str
        ):
            return MarkerObservation("untrusted", reason="marker correlation is invalid")
        if expected_operation_id is not None and operation_id != expected_operation_id:
            return MarkerObservation("untrusted", reason="marker operation does not match")
        if expected_revision is not None and revision != expected_revision:
            return MarkerObservation("untrusted", reason="marker revision does not match")
        if expected_fingerprint is not None and fingerprint != expected_fingerprint:
            return MarkerObservation("untrusted", reason="marker command does not match")
        if not is_owned_runtime_marker(
            payload,
            bot_id=record.bot_id,
            operation_id=operation_id,
            desired_revision=revision,
            pid=pid,
            expected_fingerprint=fingerprint,
        ):
            return MarkerObservation("untrusted", reason="marker schema or command does not match")
        expected_hermes = self.resolved_hermes_bin()
        if expected_hermes is None or payload.get("resolved_hermes_bin") != expected_hermes:
            return MarkerObservation("untrusted", reason="marker executable is not trusted")
        if not require_live_command:
            start_identity_error = self.process_start_identity_error(payload, pid)
            if start_identity_error is not None:
                return MarkerObservation("untrusted", reason=start_identity_error)
            return MarkerObservation("live", payload=payload)
        pid_state = self.pid_state(pid)
        if pid_state is process_identity.PidState.unknown:
            return MarkerObservation("untrusted", reason="marker PID liveness is unknown")
        if pid_state is process_identity.PidState.dead:
            if self.process_start_fingerprint_required() and not self.valid_marker_start(
                payload.get("proc_start_fingerprint")
            ):
                return MarkerObservation(
                    "untrusted", reason="process start fingerprint is unavailable"
                )
            return MarkerObservation("dead", payload=payload, reason="marker PID is dead")
        start_identity_error = self.process_start_identity_error(payload, pid)
        if start_identity_error is not None:
            return MarkerObservation("untrusted", reason=start_identity_error)
        live_argv = self.cmdline_reader(pid)
        if not live_argv:
            return MarkerObservation("untrusted", reason="live gateway command is unavailable")
        command_check = process_identity.verify_gateway_command(
            live_argv,
            record.bot_id,
            self.trusted_hermes_bins(),
            require_trusted_path=True,
        )
        if not command_check.verified:
            return MarkerObservation("untrusted", reason="live gateway command does not match")
        return MarkerObservation("live", payload=payload)

    def process_start_identity_error(self, payload: dict[str, object], pid: int) -> str | None:
        return process_identity.process_start_identity_error(
            payload.get("proc_start_fingerprint"),
            self.proc_start_fingerprint_reader(pid),
            fingerprint_required=self.process_start_fingerprint_required(),
        )

    @staticmethod
    def valid_marker_start(value: object) -> bool:
        return process_identity.valid_process_start_fingerprint(value)

    @staticmethod
    def process_start_fingerprint_required() -> bool:
        return process_identity.process_start_fingerprint_required(platform.system())

    def classify_existing_runtime_marker(
        self,
        record: BotRecord,
        *,
        expected_pid: int | None = None,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
    ) -> MarkerObservation:
        read_marker = read_marker or self.read_strict_runtime_marker
        observed = read_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return observed
        return self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=expected_pid,
            require_live_command=True,
        )

    @staticmethod
    def gateway_generation(marker: MarkerObservation) -> GatewayGeneration | None:
        payload = marker.payload
        if marker.kind not in {"live", "dead"} or payload is None:
            return None
        operation_id = payload.get("operation_id")
        revision = payload.get("desired_revision")
        pid = payload.get("pid")
        fingerprint = payload.get("command_fingerprint")
        process_start = payload.get("proc_start_fingerprint")
        if (
            type(operation_id) is not str
            or type(revision) is not int
            or type(pid) is not int
            or type(fingerprint) is not str
            or (process_start is not None and type(process_start) is not str)
        ):
            return None
        return GatewayGeneration(
            operation_id=operation_id,
            desired_revision=revision,
            pid=pid,
            command_fingerprint=fingerprint,
            proc_start_fingerprint=process_start,
        )

    def classify_exact_gateway_generation(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
    ) -> MarkerObservation:
        read_marker = read_marker or self.read_strict_runtime_marker
        observed = read_marker(record.bot_id, record.profile_path)
        if observed.kind != "present" or observed.payload is None:
            return MarkerObservation("untrusted", reason="previous gateway marker changed")
        if observed.payload.get("proc_start_fingerprint") != generation.proc_start_fingerprint:
            return MarkerObservation(
                "untrusted", reason="previous gateway process identity changed"
            )
        return self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=generation.pid,
            expected_operation_id=generation.operation_id,
            expected_revision=generation.desired_revision,
            expected_fingerprint=generation.command_fingerprint,
            require_live_command=True,
        )

    def remove_exact_schema3_marker(
        self,
        record: BotRecord,
        marker: MarkerObservation,
    ) -> bool:
        generation = self.gateway_generation(marker)
        return bool(
            marker.kind == "dead"
            and generation is not None
            and self.remove_gateway_generation_marker(record, generation)
        )

    def remove_gateway_generation_marker(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool:
        return remove_marker_if_owned(
            self.safe_profile_path(record.bot_id, record.profile_path),
            operation_id=generation.operation_id,
            desired_revision=generation.desired_revision,
            pid=generation.pid,
            command_fingerprint=generation.command_fingerprint,
            expected_proc_start_fingerprint=generation.proc_start_fingerprint,
            lock_timeout_seconds=self.lock_timeout_seconds,
        )

    def remove_gateway_generation_marker_locked(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
    ) -> bool:
        return self._hooks().remove_marker_if_owned_locked(
            self.safe_profile_path(record.bot_id, record.profile_path),
            operation_id=generation.operation_id,
            desired_revision=generation.desired_revision,
            pid=generation.pid,
            command_fingerprint=generation.command_fingerprint,
            expected_proc_start_fingerprint=generation.proc_start_fingerprint,
        )

    def remove_owned_launch_marker_locked(
        self,
        record: BotRecord,
        *,
        observed: MarkerObservation | None = None,
    ) -> bool:
        if observed is None:
            observed = self.read_strict_runtime_marker(record.bot_id, record.profile_path)
        if observed.kind == "missing":
            return True
        if observed.kind != "present" or observed.payload is None or record.pid is None:
            return False
        if record.pending_action not in {"stop", "restart"}:
            return False
        marker = self.classify_schema3_runtime_marker(
            record,
            observed.payload,
            expected_pid=record.pid,
            expected_revision=record.desired_revision - 1,
            require_live_command=True,
        )
        generation = self.gateway_generation(marker)
        return bool(
            marker.kind == "dead"
            and generation is not None
            and self.remove_gateway_generation_marker_locked(record, generation)
        )
