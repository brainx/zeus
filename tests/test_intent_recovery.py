from __future__ import annotations

import ast
import inspect
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from zeus.gateway_marker import GatewayGeneration
from zeus.gateway_runtime import MarkerObservation, StopEffect
from zeus.intent_recovery import PendingIntentRecovery
from zeus.models import BotRecord, BotStatus, BotStatusResponse, DesiredState
from zeus.process_identity import PidState
from zeus.readiness import ReadinessProbe, ReadinessResult


@dataclass(frozen=True)
class _Context:
    operation_id: str
    source: str = "reconcile"
    request_id: str | None = "request"


def _pending_record(
    action: str,
    *,
    pid: int | None = None,
    revision: int = 1,
) -> BotRecord:
    return BotRecord(
        "coder",
        "coding-bot",
        "Coder",
        "/profiles/coder",
        status=BotStatus.starting,
        pid=pid,
        desired_state=(DesiredState.stopped if action == "stop" else DesiredState.running),
        desired_revision=revision,
        pending_operation_id="1" * 32,
        pending_action=action,
    )


class _StrictRecoveryHost:
    def __init__(self, recovery: PendingIntentRecovery) -> None:
        self.recovery = recovery
        self.probe: ReadinessProbe | None = None
        self.fingerprint = "f" * 64
        self.strict_marker = MarkerObservation("missing")
        self.matching_marker = MarkerObservation("missing")
        self.old_marker: MarkerObservation | None = None
        self.pid_state = PidState.dead
        self.pid_owned = False
        self.start_calls = 0
        self.stop_effect_calls = 0
        self.signal_calls = 0
        self.marker_removals = 0
        self.state_updates = 0
        self.started_completions: list[tuple[str, int]] = []
        self.stopped_completions: list[str] = []
        self.audit_events: list[str] = []
        self.generation = GatewayGeneration(
            operation_id="0" * 32,
            desired_revision=1,
            pid=41,
            command_fingerprint="a" * 64,
            proc_start_fingerprint="start",
        )

    def _recovery_lifecycle_context(
        self,
        operation_id: str,
        context: _Context,
    ) -> _Context:
        return _Context(operation_id, context.source, context.request_id)

    @staticmethod
    def _pending_action_required(record: BotRecord, reason: str) -> BotStatusResponse:
        return BotStatusResponse(
            record.bot_id,
            record.status,
            record.pid,
            record.profile_path,
            f"action required: {reason}",
        )

    def _pending_launch_preflight(
        self,
        _record: BotRecord,
        _operation_id: str,
    ) -> tuple[ReadinessProbe | None, str]:
        return self.probe, self.fingerprint

    def _recover_pending_stop_intent(
        self,
        record: BotRecord,
        *,
        context: _Context,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return self.recovery.recover_pending_stop_intent_locked(
            self,
            record,
            context=context,
            allow_stop=allow_stop,
        )

    def _recover_pending_restart_predecessor(
        self,
        record: BotRecord,
        *,
        context: _Context,
        allow_stop: bool,
    ) -> BotStatusResponse | None:
        return self.recovery.recover_pending_restart_predecessor_locked(
            self,
            record,
            context=context,
            allow_stop=allow_stop,
        )

    def _recover_pending_launch(
        self,
        record: BotRecord,
        *,
        context: _Context,
        probe: ReadinessProbe | None,
        fingerprint: str,
        action: str,
        allow_launch: bool,
    ) -> BotStatusResponse | None:
        return self.recovery.recover_pending_launch_locked(
            self,
            record,
            context=context,
            probe=probe,
            fingerprint=fingerprint,
            action=action,
            allow_launch=allow_launch,
        )

    def _matching_runtime_marker(
        self,
        _record: BotRecord,
        *,
        expected_fingerprint: str,
        require_live_command: bool,
    ) -> MarkerObservation:
        if expected_fingerprint != self.fingerprint or not require_live_command:
            raise AssertionError("recovery weakened exact marker classification")
        return self.matching_marker

    @staticmethod
    def _probe_once(_probe: ReadinessProbe) -> ReadinessResult:
        return ReadinessResult(False, "not ready")

    def _complete_started_intent(
        self,
        _record: BotRecord,
        *,
        context: _Context,
        status: BotStatus,
        pid: int,
        ready_at: object,
        reset_restart: bool,
        reason: str,
    ) -> None:
        del status, ready_at, reset_restart, reason
        self.started_completions.append((context.operation_id, pid))

    def _start_record(
        self,
        record: BotRecord,
        *,
        reset_restart: bool,
        message: str,
        context: _Context,
        probe: ReadinessProbe | None,
    ) -> BotStatusResponse:
        del reset_restart, message, context, probe
        self.start_calls += 1
        return BotStatusResponse(
            record.bot_id,
            BotStatus.running,
            99,
            record.profile_path,
            "started",
        )

    def _read_strict_runtime_marker(
        self,
        _bot_id: str,
        _profile_path: str,
    ) -> MarkerObservation:
        return self.strict_marker

    def _remove_owned_launch_marker_locked(
        self,
        _record: BotRecord,
        *,
        observed: MarkerObservation,
    ) -> bool:
        del observed
        self.marker_removals += 1
        return True

    def _complete_stopped_intent(
        self,
        _record: BotRecord,
        *,
        context: _Context,
        reason: str,
    ) -> None:
        del reason
        self.stopped_completions.append(context.operation_id)

    def _pid_state(self, _pid: int) -> PidState:
        return self.pid_state

    def _pid_owned(self, _profile_path: str, _pid: int, _bot_id: str) -> bool:
        return self.pid_owned

    def _stop_record_effect_locked(
        self,
        record: BotRecord,
        *,
        kill_after_timeout: bool | None,
        context: _Context,
        complete_stop: bool,
    ) -> BotStatusResponse:
        del kill_after_timeout, context, complete_stop
        self.stop_effect_calls += 1
        return self._pending_action_required(
            record,
            "gateway marker ownership could not be verified",
        )

    @staticmethod
    def _is_compat_runtime_marker(payload: dict[str, object]) -> bool:
        return payload.get("schema") in {None, 2}

    def _pending_restart_old_marker(
        self,
        record: BotRecord,
        observed: MarkerObservation | None = None,
    ) -> MarkerObservation | None:
        if self.old_marker is not None:
            return self.old_marker
        return self.recovery.pending_restart_old_marker(self, record, observed)

    def _classify_schema3_runtime_marker(
        self,
        _record: BotRecord,
        _payload: dict[str, object],
        *,
        expected_pid: int | None,
        expected_revision: int,
        require_live_command: bool,
    ) -> MarkerObservation:
        del expected_pid, expected_revision, require_live_command
        return MarkerObservation("untrusted", reason="not configured")

    def _recover_pending_restart_old_gateway(
        self,
        record: BotRecord,
        marker: MarkerObservation,
        *,
        context: _Context,
        allow_stop: bool,
    ) -> BotStatusResponse:
        return self.recovery.recover_pending_restart_old_gateway(
            self,
            record,
            marker,
            context=context,
            allow_stop=allow_stop,
        )

    def _gateway_generation(
        self,
        _marker: MarkerObservation,
    ) -> GatewayGeneration | None:
        return self.generation

    def _remove_gateway_generation_marker_locked(
        self,
        _record: BotRecord,
        _generation: GatewayGeneration,
    ) -> bool:
        self.marker_removals += 1
        return True

    def _update_lifecycle(
        self,
        _context: _Context,
        _bot_id: str,
        _status: BotStatus,
        **_values: object,
    ) -> None:
        self.state_updates += 1

    def _stop_pending_restart_old_gateway(
        self,
        record: BotRecord,
        generation: GatewayGeneration,
        *,
        context: _Context,
    ) -> BotStatusResponse:
        return self.recovery.stop_pending_restart_old_gateway(
            self,
            record,
            generation,
            context=context,
        )

    def _stop_gateway_generation_locked(
        self,
        _record: BotRecord,
        _generation: GatewayGeneration,
    ) -> StopEffect:
        self.signal_calls += 1
        return StopEffect("stopped", pid=self.generation.pid, generation=self.generation)

    def _append_recovery_audit_event(self, action: str, **_values: object) -> None:
        self.audit_events.append(action)


class PendingIntentRecoveryTests(unittest.TestCase):
    def test_original_publication_is_adopted_once_without_duplicate_launch(self) -> None:
        recovery = PendingIntentRecovery()
        host = _StrictRecoveryHost(recovery)
        record = _pending_record("start")
        host.matching_marker = MarkerObservation("live", {"pid": 73})

        response = recovery.recover(
            host,
            record,
            context=_Context("unrelated"),
            allow_launch=True,
        )

        self.assertEqual(response.status, BotStatus.running)
        self.assertEqual(response.pid, 73)
        self.assertEqual(host.started_completions, [(record.pending_operation_id, 73)])
        self.assertEqual(host.start_calls, 0)

    def test_exact_live_restart_marker_is_adopted_without_popen_factory(self) -> None:
        recovery = PendingIntentRecovery()
        host = _StrictRecoveryHost(recovery)
        record = _pending_record("restart", revision=2)
        host.strict_marker = MarkerObservation("missing")
        host.matching_marker = MarkerObservation("live", {"pid": 81})

        response = recovery.recover(
            host,
            record,
            context=_Context("different"),
            allow_launch=True,
        )

        self.assertEqual(response.pid, 81)
        self.assertEqual(host.start_calls, 0)
        self.assertEqual(host.started_completions, [(record.pending_operation_id, 81)])

    def test_compat_restart_and_stop_have_no_signal_delete_start_or_update(self) -> None:
        recovery = PendingIntentRecovery()
        restart_host = _StrictRecoveryHost(recovery)
        restart = _pending_record("restart", pid=41, revision=2)
        restart_host.strict_marker = MarkerObservation("present", {"schema": 2, "pid": 41})

        restart_response = recovery.recover(
            restart_host,
            restart,
            context=_Context("different"),
            allow_launch=True,
        )

        stop_host = _StrictRecoveryHost(recovery)
        stop = _pending_record("stop", pid=41)
        stop_host.pid_state = PidState.alive
        stop_response = recovery.recover(
            stop_host,
            stop,
            context=_Context("different"),
            allow_launch=False,
        )

        self.assertTrue(restart_response.message.startswith("action required:"))
        self.assertTrue(stop_response.message.startswith("action required:"))
        for host in (restart_host, stop_host):
            self.assertEqual(host.signal_calls, 0)
            self.assertEqual(host.marker_removals, 0)
            self.assertEqual(host.start_calls, 0)
            self.assertEqual(host.state_updates, 0)

    def test_restart_stop_and_launch_use_separate_passes_with_one_launch(self) -> None:
        recovery = PendingIntentRecovery()
        host = _StrictRecoveryHost(recovery)
        first = _pending_record("restart", pid=41, revision=2)
        host.strict_marker = MarkerObservation("present", {"schema": 3})
        host.old_marker = MarkerObservation("live", {"pid": 41})

        first_response = recovery.recover(
            host,
            first,
            context=_Context("different"),
            allow_launch=True,
        )

        self.assertEqual(first_response.status, BotStatus.starting)
        self.assertIn("launch on next reconcile", first_response.message)
        self.assertEqual(host.signal_calls, 1)
        self.assertEqual(host.start_calls, 0)

        second = replace(first, status=BotStatus.stopped, pid=None)
        host.strict_marker = MarkerObservation("missing")
        host.old_marker = None
        host.matching_marker = MarkerObservation("missing")
        second_response = recovery.recover(
            host,
            second,
            context=_Context("new-context"),
            allow_launch=True,
        )

        self.assertEqual(second_response.status, BotStatus.running)
        self.assertEqual(host.start_calls, 1)
        self.assertEqual(host.started_completions, [])

    def test_status_with_pending_running_intent_never_launches(self) -> None:
        recovery = PendingIntentRecovery()
        host = _StrictRecoveryHost(recovery)
        record = _pending_record("start")
        host.matching_marker = MarkerObservation("missing")

        response = recovery.recover(
            host,
            record,
            context=_Context("status-context", source="cli"),
            allow_launch=False,
        )

        self.assertTrue(response.message.startswith("action required:"))
        self.assertEqual(host.start_calls, 0)
        self.assertEqual(host.signal_calls, 0)

    def test_host_methods_are_resolved_after_recovery_construction(self) -> None:
        recovery = PendingIntentRecovery()
        host = _StrictRecoveryHost(recovery)
        record = _pending_record("stop")
        observed: list[str] = []

        def patched_reader(bot_id: str, _profile_path: str) -> MarkerObservation:
            observed.append(bot_id)
            return MarkerObservation("missing")

        host._read_strict_runtime_marker = patched_reader  # type: ignore[method-assign]

        response = recovery.recover_pending_stop_intent_locked(
            host,
            record,
            context=_Context(record.pending_operation_id or ""),
            allow_stop=True,
        )

        self.assertEqual(response.status, BotStatus.stopped)
        self.assertEqual(observed, [record.bot_id])
        self.assertEqual(host.stopped_completions, [record.pending_operation_id])

    def test_module_has_structural_host_and_no_store_lock_or_id_dependency(self) -> None:
        import zeus.intent_recovery as module

        source = Path(inspect.getsourcefile(module) or "").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        from_imports = {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }

        self.assertTrue(hasattr(module, "_RecoveryHost"))
        self.assertFalse(
            any(isinstance(node, (ast.With, ast.AsyncWith)) for node in ast.walk(tree))
        )
        self.assertNotIn("sqlite3", imports | from_imports)
        self.assertNotIn("uuid", imports | from_imports)
        self.assertNotIn("zeus.state", from_imports)
        self.assertNotIn("zeus.supervisor", from_imports)
        self.assertNotIn("StateStore", source)


if __name__ == "__main__":
    unittest.main()
