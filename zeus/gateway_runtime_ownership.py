from __future__ import annotations

import contextlib
import json
import os
import stat
import time
from pathlib import Path

from zeus import process_identity
from zeus.errors import BotRunningError
from zeus.fs_utils import atomic_write_json
from zeus.gateway_launcher import (
    LaunchPayloadError,
    _confirm_marker_missing,
    _ConfirmedMissing,
    _open_logs,
    _open_profile_chain,
    _open_regular_marker,
    _validate_marker_bindings,
)
from zeus.gateway_marker import (
    is_owned_runtime_marker,
    readiness_probe_from_payload,
    readiness_probe_to_payload,
)
from zeus.gateway_runtime_core import (
    OwnershipCheck,
    _caused_by_missing_path,
    _same_identity,
)
from zeus.gateway_runtime_marker import _GatewayRuntimeMarker
from zeus.models import BotRecord
from zeus.private_io import UnsafeFileError, nofollow_absolute_path
from zeus.readiness import ReadinessProbe


class _GatewayRuntimeOwnership(_GatewayRuntimeMarker):
    def assert_unregistered_profile_inactive(self, bot_id: str, profile_path: Path) -> None:
        marker_path = self.pid_marker_path(str(profile_path))
        if not marker_path.exists():
            return
        try:
            payload = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BotRunningError(
                "unregistered bot profile has an unreadable PID marker; refusing replacement"
            ) from exc
        pid = payload.get("pid") if isinstance(payload, dict) else None
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise BotRunningError(
                "unregistered bot profile has an invalid PID marker; refusing replacement"
            )
        if self.pid_state(pid) is not process_identity.PidState.dead:
            raise BotRunningError(
                f"unregistered bot profile may still own gateway PID {pid}; refusing replacement"
            )

    def write_pid_marker(
        self,
        profile_path: str,
        pid: int,
        bot_id: str,
        argv: list[str],
        *,
        readiness_probe: ReadinessProbe | None,
        include_readiness_probe: bool,
    ) -> None:
        path = self.pid_marker_path(profile_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        resolved_hermes_bin = self.resolved_hermes_bin()
        marker_argv = list(argv)
        if resolved_hermes_bin:
            marker_argv[0] = resolved_hermes_bin
        fingerprint = self.proc_start_fingerprint_reader(pid)
        payload: dict[str, object] = {
            "schema": 2,
            "pid": pid,
            "bot_id": bot_id,
            "component": "gateway",
            "action": "run",
            "argv": marker_argv,
            "resolved_hermes_bin": resolved_hermes_bin,
            "started_at": time.time(),
        }
        if include_readiness_probe:
            payload["readiness_probe"] = readiness_probe_to_payload(readiness_probe)
        if fingerprint:
            payload["proc_start_fingerprint"] = fingerprint
        atomic_write_json(path, payload, mode=0o600)

    def remove_pid_marker(self, profile_path: str) -> None:
        try:
            self.pid_marker_path(profile_path).unlink()
        except FileNotFoundError:
            return

    def read_pid_marker(self, profile_path: str) -> dict[str, object]:
        safe_profile_path = nofollow_absolute_path(Path(profile_path))
        profile = None
        logs_fd = marker_fd = -1
        hooks = self._hooks()
        try:
            try:
                profile = _open_profile_chain(safe_profile_path)
                logs_fd = _open_logs(profile.fd, create=False)
                marker_fd, marker_stat = _open_regular_marker(logs_fd)
            except _ConfirmedMissing:
                return {"exists": False}
            except (LaunchPayloadError, OSError, ValueError) as exc:
                if _caused_by_missing_path(exc):
                    try:
                        if profile is not None and logs_fd >= 0:
                            _confirm_marker_missing(profile, logs_fd)
                        elif profile is not None:
                            profile.confirm_missing("logs")
                        else:
                            raise UnsafeFileError(
                                "PID marker absence cannot be confirmed safely"
                            ) from exc
                    except (LaunchPayloadError, OSError, ValueError) as confirm_error:
                        raise UnsafeFileError(
                            "PID marker absence cannot be confirmed safely"
                        ) from confirm_error
                    return {"exists": False}
                raise UnsafeFileError("PID marker cannot be opened safely") from exc
            if marker_stat.st_uid != os.geteuid() or marker_stat.st_nlink != 1:
                raise UnsafeFileError("PID marker is not a private regular file")
            marker_mode = f"{stat.S_IMODE(marker_stat.st_mode):04o}"
            try:
                raw = hooks.read_bounded_file(marker_fd)
            except (LaunchPayloadError, OSError, TypeError, ValueError) as exc:
                try:
                    _validate_marker_bindings(profile, logs_fd, marker_fd, marker_stat)
                except (LaunchPayloadError, OSError, TypeError, ValueError) as binding_error:
                    raise UnsafeFileError(
                        "PID marker changed while it was inspected"
                    ) from binding_error
                return {"exists": True, "valid": False, "mode": marker_mode, "error": str(exc)}
            try:
                current_marker = _validate_marker_bindings(
                    profile,
                    logs_fd,
                    marker_fd,
                    marker_stat,
                )
            except (LaunchPayloadError, OSError, TypeError, ValueError) as exc:
                raise UnsafeFileError("PID marker changed while it was inspected") from exc
            if (
                not stat.S_ISREG(current_marker.st_mode)
                or current_marker.st_uid != os.geteuid()
                or current_marker.st_nlink != 1
                or not _same_identity(marker_stat, current_marker)
            ):
                raise UnsafeFileError("PID marker changed while it was inspected")
        finally:
            for descriptor in (marker_fd, logs_fd):
                if descriptor >= 0:
                    with contextlib.suppress(OSError):
                        hooks.close(descriptor)
            if profile is not None:
                profile.close()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {"exists": True, "valid": False, "mode": marker_mode, "error": str(exc)}
        if not isinstance(payload, dict):
            return {
                "exists": True,
                "valid": False,
                "mode": marker_mode,
                "error": "pid marker must be a JSON object",
            }
        deprecated = payload.get("schema") is None
        safe_payload: dict[str, object] = {
            "exists": True,
            "valid": True,
            "mode": marker_mode,
            "deprecated": deprecated,
        }
        for key in (
            "schema",
            "pid",
            "bot_id",
            "component",
            "action",
            "started_at",
            "proc_start_fingerprint",
        ):
            if key in payload:
                safe_payload[key] = payload[key]
        if "readiness_probe" in payload:
            try:
                readiness = readiness_probe_from_payload(payload["readiness_probe"])
            except ValueError:
                safe_payload["readiness_probe"] = "invalid"
            else:
                safe_payload["readiness_probe"] = readiness_probe_to_payload(readiness)
        argv_value = payload.get("argv")
        if isinstance(argv_value, list) and all(isinstance(part, str) for part in argv_value):
            safe_payload["argv_shape"] = process_identity.safe_command_shape(argv_value)
        return safe_payload

    def verify_gateway_pid_ownership(
        self,
        profile_path: str,
        pid: int,
        bot_id: str,
        *,
        expected_record: BotRecord | None,
    ) -> OwnershipCheck:
        if expected_record is not None and expected_record.profile_path != profile_path:
            return OwnershipCheck(False, "marker-mismatch")
        observed = self.read_strict_runtime_marker(bot_id, profile_path)
        if observed.kind == "missing":
            return OwnershipCheck(False, "marker-missing")
        if observed.kind != "present" or observed.payload is None:
            return OwnershipCheck(False, "marker-mismatch")
        payload = observed.payload
        if payload.get("schema") == 3:
            if expected_record is None:
                return OwnershipCheck(False, "marker-mismatch")
            marker = self.classify_schema3_runtime_marker(
                expected_record,
                payload,
                expected_pid=pid,
                require_live_command=True,
            )
            if marker.kind != "live":
                return OwnershipCheck(False, marker.reason or "marker-mismatch")
            live_argv = self.cmdline_reader(pid)
            if not live_argv:
                return OwnershipCheck(False, "live-cmdline-missing")
            live_check = process_identity.verify_gateway_command(
                live_argv,
                bot_id,
                self.trusted_hermes_bins(),
                require_trusted_path=True,
            )
            return OwnershipCheck(
                live_check.verified,
                live_check.reason,
                live_check.classification,
            )
        if payload.get("pid") != pid:
            return OwnershipCheck(False, "marker-mismatch")
        argv_value = payload.get("argv")
        if not isinstance(argv_value, list) or not all(
            isinstance(part, str) for part in argv_value
        ):
            return OwnershipCheck(False, "marker-mismatch")
        trusted_hermes = self.resolved_hermes_bin()
        if trusted_hermes is None:
            return OwnershipCheck(False, "untrusted-executable")
        marker_check = self.verify_marker_payload(payload, list(argv_value), bot_id)
        if not marker_check.verified:
            return OwnershipCheck(False, marker_check.reason, marker_check.classification)
        live_argv = self.cmdline_reader(pid)
        if not live_argv:
            return OwnershipCheck(False, "live-cmdline-missing")
        live_check = process_identity.verify_gateway_command(
            live_argv,
            bot_id,
            self.trusted_hermes_bins(),
            require_trusted_path=True,
        )
        if not live_check.verified:
            return OwnershipCheck(False, live_check.reason, live_check.classification)
        marker_schema = payload.get("schema")
        fingerprint = payload.get("proc_start_fingerprint")
        if marker_schema == 2:
            live_fingerprint = self.proc_start_fingerprint_reader(pid)
            if live_fingerprint and not (isinstance(fingerprint, str) and fingerprint):
                return OwnershipCheck(False, "pid-start-time-missing", live_check.classification)
            if isinstance(fingerprint, str) and fingerprint and live_fingerprint != fingerprint:
                return OwnershipCheck(False, "pid-start-time-mismatch", live_check.classification)
        elif isinstance(fingerprint, str) and fingerprint:
            live_fingerprint = self.proc_start_fingerprint_reader(pid)
            if live_fingerprint != fingerprint:
                return OwnershipCheck(False, "pid-start-time-mismatch", live_check.classification)
        classification = (
            "legacy-marker-valid"
            if marker_check.classification == "legacy-marker-valid"
            else live_check.classification
        )
        return OwnershipCheck(True, "ok", classification)

    def verify_marker_payload(
        self,
        payload: dict[str, object],
        argv: list[str],
        bot_id: str,
    ) -> OwnershipCheck:
        schema = payload.get("schema")
        if schema == 3:
            pid = payload.get("pid")
            operation_id = payload.get("operation_id")
            revision = payload.get("desired_revision")
            fingerprint = payload.get("command_fingerprint")
            if (
                type(pid) is not int
                or pid <= 0
                or type(operation_id) is not str
                or len(operation_id) != 32
                or any(character not in "0123456789abcdef" for character in operation_id)
                or type(revision) is not int
                or revision <= 0
                or type(fingerprint) is not str
            ):
                return OwnershipCheck(False, "marker-mismatch")
            if not is_owned_runtime_marker(
                payload,
                bot_id=bot_id,
                operation_id=operation_id,
                desired_revision=revision,
                pid=pid,
                expected_fingerprint=fingerprint,
            ):
                return OwnershipCheck(False, "marker-mismatch")
            resolved_hermes_bin = self.resolved_hermes_bin()
            marker_hermes = payload.get("resolved_hermes_bin")
            if (
                resolved_hermes_bin is None
                or type(marker_hermes) is not str
                or process_identity.resolve_executable(marker_hermes) != resolved_hermes_bin
            ):
                return OwnershipCheck(False, "untrusted-executable")
            marker_check = process_identity.verify_gateway_command(
                argv,
                bot_id,
                resolved_hermes_bin,
                require_trusted_path=True,
            )
            return OwnershipCheck(
                marker_check.verified,
                marker_check.reason,
                marker_check.classification,
            )
        if schema == 2:
            if payload.get("bot_id") != bot_id:
                return OwnershipCheck(False, "wrong-bot-id")
            if payload.get("component") != "gateway" or payload.get("action") != "run":
                return OwnershipCheck(False, "wrong-command-intent")
            resolved_hermes_bin = self.resolved_hermes_bin()
            if not isinstance(payload.get("resolved_hermes_bin"), str):
                return OwnershipCheck(False, "untrusted-executable")
            marker_hermes = process_identity.resolve_executable(str(payload["resolved_hermes_bin"]))
            if marker_hermes != resolved_hermes_bin:
                return OwnershipCheck(False, "untrusted-executable")
            marker_check = process_identity.verify_gateway_command(
                argv,
                bot_id,
                resolved_hermes_bin,
                require_trusted_path=True,
            )
            return OwnershipCheck(
                marker_check.verified,
                marker_check.reason,
                marker_check.classification,
            )
        if schema is not None:
            return OwnershipCheck(False, "marker-mismatch")
        if not self.allow_legacy_pid_markers:
            return OwnershipCheck(False, "legacy-marker-disabled")
        marker_check = process_identity.verify_gateway_command(
            argv,
            bot_id,
            None,
            require_trusted_path=False,
        )
        if not marker_check.verified:
            return OwnershipCheck(False, marker_check.reason, marker_check.classification)
        return OwnershipCheck(True, "ok", "legacy-marker-valid")
