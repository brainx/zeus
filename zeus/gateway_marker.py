from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard
from urllib.parse import urlparse

from zeus.models import ID_RE
from zeus.readiness import ReadinessProbe

__all__ = [
    "GatewayGeneration",
    "GatewayLaunchMarker",
    "GatewayRuntimeMarker",
    "MarkerValidationError",
    "command_fingerprint",
    "is_compat_runtime_marker",
    "is_owned_runtime_marker",
    "parse_launch_marker",
    "parse_runtime_marker",
    "readiness_probe_from_payload",
    "readiness_probe_to_payload",
]

_MAX_ARGV_PARTS = 64
_MAX_ARG_BYTES = 64 * 1024
_LAUNCH_MARKER_KEYS = frozenset(
    {
        "schema",
        "bot_id",
        "component",
        "action",
        "operation_id",
        "desired_revision",
        "argv",
        "resolved_hermes_bin",
        "command_fingerprint",
        "readiness_probe",
    }
)
_RUNTIME_MARKER_KEYS = _LAUNCH_MARKER_KEYS | frozenset({"pid", "started_at"})
_RUNTIME_MARKER_FINGERPRINT_KEYS = _RUNTIME_MARKER_KEYS | frozenset({"proc_start_fingerprint"})
_READINESS_PROBE_KEYS = frozenset(
    {"url", "expected_status", "expected_platform", "timeout_seconds", "interval_seconds"}
)
_OPERATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class MarkerValidationError(ValueError):
    pass


@dataclass(frozen=True)
class GatewayGeneration:
    operation_id: str
    desired_revision: int
    pid: int
    command_fingerprint: str
    proc_start_fingerprint: str | None


@dataclass(frozen=True)
class GatewayLaunchMarker:
    bot_id: str
    operation_id: str
    desired_revision: int
    argv: tuple[str, ...]
    resolved_hermes_bin: str
    command_fingerprint: str
    readiness_probe: ReadinessProbe | None

    def to_payload(self) -> dict[str, object]:
        return {
            "schema": 3,
            "bot_id": self.bot_id,
            "component": "gateway",
            "action": "run",
            "operation_id": self.operation_id,
            "desired_revision": self.desired_revision,
            "argv": list(self.argv),
            "resolved_hermes_bin": self.resolved_hermes_bin,
            "command_fingerprint": self.command_fingerprint,
            "readiness_probe": readiness_probe_to_payload(self.readiness_probe),
        }


@dataclass(frozen=True)
class GatewayRuntimeMarker(GatewayLaunchMarker):
    pid: int
    started_at: int | float
    proc_start_fingerprint: str | None = None

    def to_payload(self) -> dict[str, object]:
        payload = super().to_payload()
        payload["pid"] = self.pid
        payload["started_at"] = self.started_at
        if self.proc_start_fingerprint is not None:
            payload["proc_start_fingerprint"] = self.proc_start_fingerprint
        return payload

    def generation(self) -> GatewayGeneration:
        return GatewayGeneration(
            operation_id=self.operation_id,
            desired_revision=self.desired_revision,
            pid=self.pid,
            command_fingerprint=self.command_fingerprint,
            proc_start_fingerprint=self.proc_start_fingerprint,
        )


def command_fingerprint(argv: list[str]) -> str:
    encoded = json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_launch_marker(value: object) -> GatewayLaunchMarker:
    marker, bot_id = _parse_launch_marker_identity(value)
    operation_id, revision = _parse_launch_marker_correlation(marker)
    argv = _parse_launch_marker_argv(marker)
    return _finish_launch_marker(
        marker,
        bot_id=bot_id,
        operation_id=operation_id,
        revision=revision,
        argv=argv,
    )


def parse_runtime_marker(value: object) -> GatewayRuntimeMarker:
    if type(value) is not dict:
        raise MarkerValidationError("runtime marker must be an object")
    marker = value
    if frozenset(marker) not in {
        _RUNTIME_MARKER_KEYS,
        _RUNTIME_MARKER_FINGERPRINT_KEYS,
    } or not all(type(key) is str for key in marker):
        raise MarkerValidationError("runtime marker has invalid keys")

    bot_id = _parse_bot_id(marker)
    operation_id, revision = _parse_launch_marker_correlation(marker)
    argv = _parse_launch_marker_argv(marker)
    launch = _finish_launch_marker(
        marker,
        bot_id=bot_id,
        operation_id=operation_id,
        revision=revision,
        argv=argv,
    )
    pid = marker["pid"]
    if type(pid) is not int or pid <= 0:
        raise MarkerValidationError("marker PID is invalid")
    started_at = marker["started_at"]
    if not _is_finite_positive_number(started_at):
        raise MarkerValidationError("marker started_at is invalid")
    process_start: str | None = None
    if "proc_start_fingerprint" in marker:
        raw_process_start = marker["proc_start_fingerprint"]
        if (
            type(raw_process_start) is not str
            or not raw_process_start
            or len(raw_process_start) > 512
        ):
            raise MarkerValidationError("process start fingerprint is invalid")
        process_start = raw_process_start

    return GatewayRuntimeMarker(
        bot_id=launch.bot_id,
        operation_id=launch.operation_id,
        desired_revision=launch.desired_revision,
        argv=launch.argv,
        resolved_hermes_bin=launch.resolved_hermes_bin,
        command_fingerprint=launch.command_fingerprint,
        readiness_probe=launch.readiness_probe,
        pid=pid,
        started_at=started_at,
        proc_start_fingerprint=process_start,
    )


def is_owned_runtime_marker(
    value: object,
    *,
    bot_id: str,
    operation_id: str,
    desired_revision: int,
    pid: int,
    expected_fingerprint: str,
) -> bool:
    try:
        marker = parse_runtime_marker(value)
    except MarkerValidationError:
        return False
    return (
        marker.bot_id == bot_id
        and marker.operation_id == operation_id
        and marker.desired_revision == desired_revision
        and marker.pid == pid
        and marker.command_fingerprint == expected_fingerprint
    )


def is_compat_runtime_marker(value: object) -> bool:
    if type(value) is not dict:
        return False
    schema = value.get("schema")
    return (type(schema) is int and schema == 2) or schema is None


def readiness_probe_to_payload(probe: ReadinessProbe | None) -> dict[str, object] | None:
    if probe is None:
        return None
    return {
        "url": probe.url,
        "expected_status": probe.expected_status,
        "expected_platform": probe.expected_platform,
        "timeout_seconds": probe.timeout_seconds,
        "interval_seconds": probe.interval_seconds,
    }


def readiness_probe_from_payload(value: object) -> ReadinessProbe | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise MarkerValidationError("readiness_probe must be an object or null")
    url = value.get("url")
    expected_status = value.get("expected_status")
    expected_platform = value.get("expected_platform")
    timeout_seconds = value.get("timeout_seconds")
    interval_seconds = value.get("interval_seconds")
    if not isinstance(url, str):
        raise MarkerValidationError("url must be a string")
    try:
        parsed = urlparse(url)
        valid_url = (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid_url = False
    if not valid_url:
        raise MarkerValidationError("url must be loopback HTTP without credentials or query data")
    if not isinstance(expected_status, str) or not expected_status:
        raise MarkerValidationError("expected_status must be a non-empty string")
    if not isinstance(expected_platform, str) or not expected_platform:
        raise MarkerValidationError("expected_platform must be a non-empty string")
    if not _is_valid_probe_number(timeout_seconds) or not _is_valid_probe_number(interval_seconds):
        raise MarkerValidationError("probe timing values must be finite positive numbers")
    return ReadinessProbe(
        url=url,
        expected_status=expected_status,
        expected_platform=expected_platform,
        timeout_seconds=float(timeout_seconds),
        interval_seconds=float(interval_seconds),
    )


def _parse_launch_marker_identity(value: object) -> tuple[dict[str, object], str]:
    marker = _exact_dict(value, _LAUNCH_MARKER_KEYS, "marker")
    return marker, _parse_bot_id(marker)


def _parse_bot_id(marker: dict[str, object]) -> str:
    bot_id = _exact_string(marker["bot_id"], "bot_id", max_length=63)
    if ID_RE.fullmatch(bot_id) is None:
        raise MarkerValidationError("bot_id is invalid")
    return bot_id


def _parse_launch_marker_correlation(marker: dict[str, object]) -> tuple[str, int]:
    if marker["schema"] != 3 or type(marker["schema"]) is not int:
        raise MarkerValidationError("marker schema is invalid")
    if marker["component"] != "gateway" or marker["action"] != "run":
        raise MarkerValidationError("marker command intent is invalid")
    operation_id = _exact_string(marker["operation_id"], "operation_id", max_length=32)
    if _OPERATION_ID_RE.fullmatch(operation_id) is None:
        raise MarkerValidationError("operation_id is invalid")
    revision = marker["desired_revision"]
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise MarkerValidationError("desired_revision is invalid")
    return operation_id, revision


def _parse_launch_marker_argv(marker: dict[str, object]) -> tuple[str, ...]:
    return _parse_argv(marker["argv"])


def _finish_launch_marker(
    marker: dict[str, object],
    *,
    bot_id: str,
    operation_id: str,
    revision: int,
    argv: tuple[str, ...],
) -> GatewayLaunchMarker:
    if len(argv) != 5 or list(argv[1:]) != ["-p", bot_id, "gateway", "run"]:
        raise MarkerValidationError("argv is not a Hermes gateway command")
    resolved_hermes, canonical_hermes = _parse_absolute_path(
        marker["resolved_hermes_bin"], "resolved_hermes_bin"
    )
    if argv[0] != canonical_hermes:
        raise MarkerValidationError("exec argv does not use the resolved Hermes binary")
    fingerprint = _exact_string(marker["command_fingerprint"], "command_fingerprint", max_length=64)
    if _FINGERPRINT_RE.fullmatch(fingerprint) is None or fingerprint != command_fingerprint(
        list(argv)
    ):
        raise MarkerValidationError("command fingerprint is invalid")
    readiness = _strict_readiness_probe_from_payload(marker["readiness_probe"])
    return GatewayLaunchMarker(
        bot_id=bot_id,
        operation_id=operation_id,
        desired_revision=revision,
        argv=argv,
        resolved_hermes_bin=resolved_hermes,
        command_fingerprint=fingerprint,
        readiness_probe=readiness,
    )


def _strict_readiness_probe_from_payload(value: object) -> ReadinessProbe | None:
    if value is None:
        return None
    probe = _exact_dict(value, _READINESS_PROBE_KEYS, "readiness_probe")
    url = _exact_string(probe["url"], "readiness URL", max_length=2048)
    try:
        parsed = urlparse(url)
        valid_url = (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid_url = False
    if not valid_url:
        raise MarkerValidationError("readiness URL must be loopback HTTP")
    expected_status = _exact_string(probe["expected_status"], "expected status", max_length=128)
    expected_platform = _exact_string(
        probe["expected_platform"], "expected platform", max_length=128
    )
    timeout_seconds = probe["timeout_seconds"]
    interval_seconds = probe["interval_seconds"]
    if not _is_valid_probe_number(timeout_seconds) or not _is_valid_probe_number(interval_seconds):
        raise MarkerValidationError("readiness timing is invalid")
    return ReadinessProbe(
        url=url,
        expected_status=expected_status,
        expected_platform=expected_platform,
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
    )


def _exact_dict(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise MarkerValidationError(f"{name} must be an object")
    result = value
    if set(result) != keys or not all(type(key) is str for key in result):
        raise MarkerValidationError(f"{name} has invalid keys")
    return result


def _exact_string(value: object, name: str, *, max_length: int) -> str:
    if type(value) is not str or not value or len(value) > max_length or "\0" in value:
        raise MarkerValidationError(f"{name} must be a bounded non-empty string")
    return value


def _parse_argv(value: object) -> tuple[str, ...]:
    if type(value) is not list or not value or len(value) > _MAX_ARGV_PARTS:
        raise MarkerValidationError("argv must be a bounded non-empty list")
    argv: list[str] = []
    total = 0
    for item in value:
        part = _exact_string(item, "argv item", max_length=16 * 1024)
        total += len(part.encode("utf-8"))
        if total > _MAX_ARG_BYTES:
            raise MarkerValidationError("argv is too large")
        argv.append(part)
    return tuple(argv)


def _parse_absolute_path(value: object, name: str) -> tuple[str, str]:
    raw = _exact_string(value, name, max_length=16 * 1024)
    path = Path(raw)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise MarkerValidationError(f"{name} must be an absolute path without traversal")
    return raw, str(path)


def _is_valid_probe_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    try:
        number = float(value)
    except OverflowError:
        return False
    return math.isfinite(number) and 0 < number <= 3600


def _is_finite_positive_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    try:
        number = float(value)
    except OverflowError:
        return False
    return math.isfinite(number) and number > 0
