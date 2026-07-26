from __future__ import annotations

import signal
from collections.abc import Callable

from zeus import process_identity
from zeus.gateway_marker import (
    GatewayGeneration,
    is_compat_runtime_marker,
)
from zeus.gateway_runtime_core import (
    MarkerObservation,
    SignalResult,
    StopEffect,
)
from zeus.gateway_runtime_ownership import _GatewayRuntimeOwnership
from zeus.models import BotRecord


class _GatewayRuntimeStop(_GatewayRuntimeOwnership):
    def reauthorize_and_signal(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        sig: signal.Signals,
        *,
        classify_exact: Callable[[BotRecord, GatewayGeneration], MarkerObservation] | None = None,
    ) -> tuple[MarkerObservation, SignalResult | None]:
        classify_exact = classify_exact or self.classify_exact_gateway_generation
        current = classify_exact(record, generation)
        if current.kind != "live":
            return current, None
        return current, self.send_signal(generation.pid, sig)

    def stop_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        read_marker: Callable[[str, str], MarkerObservation] | None = None,
        classify_existing: Callable[..., MarkerObservation] | None = None,
        classify_exact: Callable[[BotRecord, GatewayGeneration], MarkerObservation] | None = None,
        remove_owned: Callable[..., bool] | None = None,
        remove_generation: Callable[[BotRecord, GatewayGeneration], bool] | None = None,
    ) -> StopEffect:
        read_marker = read_marker or self.read_strict_runtime_marker
        classify_existing = classify_existing or self.classify_existing_runtime_marker
        classify_exact = classify_exact or self.classify_exact_gateway_generation
        remove_owned = remove_owned or self.remove_owned_launch_marker_locked
        remove_generation = remove_generation or self.remove_gateway_generation_marker_locked
        observed = read_marker(record.bot_id, record.profile_path)
        if (
            observed.kind == "present"
            and observed.payload is not None
            and is_compat_runtime_marker(observed.payload)
        ):
            return StopEffect(
                "compat_untrusted",
                record.pid,
                reason="schema-v2 or legacy gateway stop requires manual process resolution",
            )
        if not record.pid:
            if not remove_owned(record, observed=observed):
                return StopEffect(
                    "cleanup_unverified",
                    record.pid,
                    reason="stale gateway marker ownership could not be verified",
                )
            return StopEffect("not_running", record.pid, marker_removed=True)
        marker = classify_existing(record, expected_pid=record.pid)
        generation = self.gateway_generation(marker)
        if marker.kind == "live" and generation is not None:
            return self.stop_generation_locked(
                record,
                generation,
                kill_after_timeout=kill_after_timeout,
                classify_exact=classify_exact,
                remove_generation=remove_generation,
            )
        if marker.kind == "dead":
            if not remove_owned(record, observed=observed):
                return StopEffect(
                    "cleanup_unverified",
                    record.pid,
                    reason="stale gateway marker ownership could not be verified",
                )
            return StopEffect("not_running", record.pid, marker_removed=True)
        pid_state = self.pid_state(record.pid)
        if pid_state is process_identity.PidState.unknown:
            return StopEffect("pid_unknown", record.pid, reason="gateway PID liveness is unknown")
        if pid_state is process_identity.PidState.dead:
            if not remove_owned(record, observed=observed):
                return StopEffect(
                    "cleanup_unverified",
                    record.pid,
                    reason="stale gateway marker ownership could not be verified",
                )
            return StopEffect("not_running", record.pid, marker_removed=True)
        if marker.kind != "live" or generation is None:
            return StopEffect(
                "ownership_unverified",
                record.pid,
                reason="refusing to stop process because PID ownership could not be verified",
            )
        raise AssertionError("unreachable gateway marker state")

    def stop_generation_locked(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        kill_after_timeout: bool | None,
        classify_exact: Callable[[BotRecord, GatewayGeneration], MarkerObservation] | None = None,
        remove_generation: Callable[[BotRecord, GatewayGeneration], bool] | None = None,
    ) -> StopEffect:
        classify_exact = classify_exact or self.classify_exact_gateway_generation
        remove_generation = remove_generation or self.remove_gateway_generation_marker_locked
        current = classify_exact(record, generation)
        term_result: SignalResult | None = None
        kill_result: SignalResult | None = None
        if current.kind == "dead":
            stopped = True
        elif current.kind == "live":
            current, term_result = self.reauthorize_and_signal(
                record,
                generation,
                signal.SIGTERM,
                classify_exact=classify_exact,
            )
            if current.kind != "live" or term_result is None:
                return StopEffect(
                    "term_reauthorization_failed",
                    generation.pid,
                    generation,
                    current.reason or "gateway ownership changed before SIGTERM",
                )
            if term_result is SignalResult.denied:
                return StopEffect(
                    "term_denied",
                    generation.pid,
                    generation,
                    "could not send SIGTERM to the gateway",
                    term_result=term_result,
                )
            stopped = term_result is SignalResult.missing
            if not stopped:
                stopped = self.wait_for_exit(record.bot_id, generation.pid)
        else:
            return StopEffect(
                "term_reauthorization_failed",
                generation.pid,
                generation,
                current.reason or "gateway ownership changed before SIGTERM",
            )
        should_kill = self.kill_after_timeout if kill_after_timeout is None else kill_after_timeout
        kill_attempted = False
        kill_succeeded: bool | None = None
        if not stopped and should_kill:
            kill_attempted = True
            current, kill_result = self.reauthorize_and_signal(
                record,
                generation,
                signal.SIGKILL,
                classify_exact=classify_exact,
            )
            if current.kind == "dead":
                stopped = True
                kill_succeeded = True
            elif current.kind != "live" or kill_result is None:
                return StopEffect(
                    "kill_reauthorization_failed",
                    generation.pid,
                    generation,
                    current.reason or "gateway ownership changed before SIGKILL",
                    term_result=term_result,
                    kill_attempted=True,
                )
            elif kill_result is SignalResult.denied:
                return StopEffect(
                    "kill_denied",
                    generation.pid,
                    generation,
                    "could not send SIGKILL to the gateway",
                    term_result=term_result,
                    kill_result=kill_result,
                    kill_attempted=True,
                    kill_succeeded=False,
                )
            else:
                stopped = kill_result is SignalResult.missing
                if not stopped:
                    stopped = self.wait_for_exit(record.bot_id, generation.pid)
                kill_succeeded = stopped
        if not stopped:
            return StopEffect(
                "grace_expired",
                generation.pid,
                generation,
                "gateway did not stop before grace period expired",
                term_result=term_result,
                kill_result=kill_result,
                kill_attempted=kill_attempted,
                kill_succeeded=kill_succeeded,
            )
        if not remove_generation(record, generation):
            return StopEffect(
                "cleanup_unverified",
                generation.pid,
                generation,
                "stopped gateway marker cleanup could not be verified",
                term_result=term_result,
                kill_result=kill_result,
                kill_attempted=kill_attempted,
                kill_succeeded=kill_succeeded,
            )
        self._processes.pop(record.bot_id, None)
        return StopEffect(
            "stopped",
            generation.pid,
            generation,
            term_result=term_result,
            kill_result=kill_result,
            marker_removed=True,
            kill_attempted=kill_attempted,
            kill_succeeded=kill_succeeded,
        )
