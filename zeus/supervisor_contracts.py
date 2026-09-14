from __future__ import annotations

from dataclasses import dataclass

from zeus.gateway_marker import GatewayGeneration
from zeus.gateway_runtime import MarkerObservation, SignalResult
from zeus.models import BotRecord
from zeus.readiness import ReadinessProbe


class _ReadinessProbeUnset:
    pass


_READINESS_PROBE_UNSET = _ReadinessProbeUnset()
_MarkerObservation = MarkerObservation
_GatewayGeneration = GatewayGeneration
_SignalResult = SignalResult


@dataclass(frozen=True)
class _LifecycleContext:
    operation_id: str
    source: str
    request_id: str | None


@dataclass(frozen=True)
class _ReconcileLaunch:
    record: BotRecord
    probe: ReadinessProbe | None
    attempt: int
    restart_max_attempts: int
