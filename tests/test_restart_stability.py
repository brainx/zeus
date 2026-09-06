from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from tests.test_lifecycle_regressions import _FakePopen
from zeus.api import make_handler
from zeus.cli import _demo_services, _services
from zeus.config import Settings
from zeus.models import BotRecord, BotStatus, DesiredState, RestartPolicy
from zeus.readiness import ReadinessProbe, ReadinessResult
from zeus.reconciliation import ReconcileOutcome
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class RestartStabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.now = datetime(2026, 1, 1, tzinfo=UTC)
        self.alive = True
        self.hermes = self.root / "bin" / "hermes"
        self.hermes.parent.mkdir()
        self.hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        self.hermes.chmod(0o755)
        self.profile = self.root / "hermes" / "profiles" / "coder"
        self.profile.mkdir(parents=True)
        (self.profile / ".env").write_text("", encoding="utf-8")
        (self.profile / "config.yaml").write_text("model: test\n", encoding="utf-8")
        self.store = StateStore(self.root / "zeus.db")
        self.store.init()
        self.store.upsert_bot(
            BotRecord(
                "coder",
                "coding-bot",
                "Coder",
                str(self.profile),
                status=BotStatus.running,
                pid=4321,
                desired_state=DesiredState.running,
                desired_revision=1,
                restart_policy=RestartPolicy.on_failure,
                restart_attempts=2,
                restart_backoff_seconds=1,
                restart_max_attempts=3,
                ready_at=self.now,
            )
        )
        self.supervisor = self._supervisor()
        self._publish_marker()

    def _supervisor(self, window: float = 30) -> Supervisor:
        def spawn(*args, **kwargs):
            self.alive = True
            return _FakePopen(*args, **kwargs)

        return Supervisor(
            self.store,
            str(self.hermes),
            self.root / "hermes",
            popen_factory=spawn,
            startup_grace_seconds=0,
            pid_alive_fn=lambda _pid: self.alive,
            cmdline_reader=lambda _pid: [str(self.hermes), "-p", "coder", "gateway", "run"],
            proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            restart_stability_seconds=window,
        )

    def _record(self) -> BotRecord:
        record = self.store.get_bot("coder")
        assert record is not None
        return record

    def _publish_marker(self, probe: ReadinessProbe | None = None) -> None:
        record = self._record()
        payload = self.supervisor.adapter.launcher_payload(
            "coder",
            operation_id=record.pending_operation_id or "a" * 32,
            desired_revision=record.desired_revision,
            readiness_probe=probe,
        )
        marker = dict(payload["marker"])
        marker.update(
            pid=4321,
            started_at=self.now.timestamp(),
            proc_start_fingerprint="test-process-start:4321",
        )
        path = self.supervisor.pid_marker_path(str(self.profile))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(marker), encoding="utf-8")

    def _clock(self, now: datetime) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        for module in ("supervisor_runtime", "supervisor_start", "intent_recovery"):
            clock = stack.enter_context(patch(f"zeus.{module}.datetime", wraps=datetime))
            clock.now.return_value = now
        return stack

    def test_brief_recovery_keeps_budget_and_next_crash_uses_prior_backoff(self) -> None:
        with self._clock(self.now + timedelta(seconds=1)):
            self.assertEqual(BotStatus.running, self.supervisor.status("coder").status)
        self.assertEqual(2, self._record().restart_attempts)
        self.alive = False

        response = self.supervisor.reconcile("coder", now=self.now + timedelta(seconds=2))[0]

        self.assertEqual("restart scheduled: attempt 3/3 in 4s", response.message)
        self.assertEqual(3, self._record().restart_attempts)

    def test_repeated_brief_policy_launches_exhaust_budget(self) -> None:
        self.store.upsert_bot(replace(self._record(), restart_attempts=0))
        for attempt in range(1, 4):
            self.alive = False
            now = self.now + timedelta(seconds=attempt * 5)
            with self._clock(now):
                response = self.supervisor.reconcile("coder", force=True, now=now)[0]
            self.assertEqual(BotStatus.running, response.status)
            self.assertEqual(attempt, self._record().restart_attempts)
            self.alive = True
            with self._clock(now + timedelta(seconds=1)):
                self.supervisor.status("coder")
            self.assertEqual(attempt, self._record().restart_attempts)
            self.assertEqual(now, self._record().ready_at)
        self.alive = False
        self.assertEqual(
            "restart limit reached: 3/3", self.supervisor.reconcile("coder")[0].message
        )

    def test_stable_recovery_resets_once_across_supervisors_without_noop_events(self) -> None:
        with self._clock(self.now + timedelta(seconds=29)):
            before = self.supervisor.reconcile_one("coder")
        self.assertEqual(ReconcileOutcome.healthy, before.outcome)
        self.assertIsNone(before.event_id)
        self.assertEqual(2, self._record().restart_attempts)

        other = self._supervisor()
        with self._clock(self.now + timedelta(seconds=30)):
            changed = other.reconcile_one("coder")
        self.assertEqual(ReconcileOutcome.changed, changed.outcome)
        self.assertIsNotNone(changed.event_id)
        self.assertEqual(0, self._record().restart_attempts)
        self.assertEqual(self.now, self._record().ready_at)
        events = self.store.list_lifecycle_events("coder", limit=10, before=None)
        self.assertEqual(1, len(events))
        with self._clock(self.now + timedelta(seconds=60)):
            healthy = self.supervisor.reconcile_one("coder")
        self.assertEqual(ReconcileOutcome.healthy, healthy.outcome)
        self.assertIsNone(healthy.event_id)
        self.assertEqual(events, self.store.list_lifecycle_events("coder", limit=10, before=None))

    def test_starting_observation_starts_window_only_when_ready(self) -> None:
        self.store.upsert_bot(replace(self._record(), status=BotStatus.starting, ready_at=None))
        self._publish_marker(ReadinessProbe("http://127.0.0.1:4312/health"))
        with (
            self._clock(self.now),
            patch.object(
                self.supervisor, "_probe_once", return_value=ReadinessResult(False, "wait")
            ),
        ):
            self.assertEqual(BotStatus.starting, self.supervisor.status("coder").status)
        self.assertIsNone(self._record().ready_at)
        ready = self.now + timedelta(seconds=90)
        with (
            self._clock(ready),
            patch.object(
                self.supervisor, "_probe_once", return_value=ReadinessResult(True, "ready")
            ),
        ):
            self.assertEqual(BotStatus.running, self.supervisor.status("coder").status)
        self.assertEqual(2, self._record().restart_attempts)
        self.assertEqual(ready, self._record().ready_at)
        with self._clock(ready + timedelta(seconds=29)):
            self.supervisor.status("coder")
        self.assertEqual(2, self._record().restart_attempts)

    def test_starting_without_probe_starts_new_window(self) -> None:
        self.store.upsert_bot(replace(self._record(), status=BotStatus.starting))
        now = self.now + timedelta(seconds=90)
        with self._clock(now):
            self.supervisor.status("coder")
        self.assertEqual(now, self._record().ready_at)
        self.assertEqual(2, self._record().restart_attempts)

    def test_adopted_policy_launch_starts_new_window_without_resetting_budget(self) -> None:
        self.store.begin_lifecycle_intent(
            "coder", action="start", operation_id="b" * 32, source="reconcile"
        )
        self._publish_marker()
        now = self.now + timedelta(hours=1)
        with self._clock(now):
            response = self.supervisor.status("coder")
        self.assertEqual("recovered registered gateway", response.message)
        self.assertEqual(now, self._record().ready_at)
        self.assertEqual(2, self._record().restart_attempts)
        self.assertIsNone(self._record().pending_operation_id)
        self.assertEqual({}, self.supervisor._processes)
        self.alive = False
        self.assertEqual(
            "restart scheduled: attempt 3/3 in 4s", self.supervisor.reconcile("coder")[0].message
        )

    def test_zero_window_restores_immediate_status_and_adoption_reset(self) -> None:
        self.supervisor = self._supervisor(0)
        self.store.upsert_bot(replace(self._record(), ready_at=None))
        with self._clock(self.now):
            self.supervisor.status("coder")
        self.assertEqual(0, self._record().restart_attempts)
        self.store.upsert_bot(replace(self._record(), restart_attempts=2))
        self.store.begin_lifecycle_intent(
            "coder", action="start", operation_id="b" * 32, source="reconcile"
        )
        self._publish_marker()
        with self._clock(self.now):
            self.supervisor.status("coder")
        self.assertEqual(0, self._record().restart_attempts)

    def test_explicit_reset_and_recovered_operator_restart_keep_reset_semantics(self) -> None:
        with self._clock(self.now):
            self.supervisor.reconcile("coder", reset_restart=True)
        self.assertEqual(0, self._record().restart_attempts)
        self.store.upsert_bot(replace(self._record(), restart_attempts=2))
        self.store.begin_lifecycle_intent(
            "coder", action="restart", operation_id="b" * 32, source="cli"
        )
        self._publish_marker()
        with self._clock(self.now):
            response = self.supervisor.status("coder")
        self.assertEqual("recovered registered gateway", response.message)
        self.assertEqual(0, self._record().restart_attempts)

    def test_explicit_start_resets_budget_while_readiness_is_pending(self) -> None:
        self.alive = False
        (self.profile / ".env").write_text(
            "API_SERVER_ENABLED=1\nAPI_SERVER_PORT=4312\n", encoding="utf-8"
        )
        response = self.supervisor.start("coder")
        self.assertEqual(BotStatus.starting, response.status)
        self.assertEqual(0, self._record().restart_attempts)

    def test_clock_rollback_or_failed_ownership_never_resets_budget(self) -> None:
        with self._clock(self.now - timedelta(seconds=1)):
            self.supervisor.status("coder")
        self.assertEqual(2, self._record().restart_attempts)
        self.supervisor.proc_start_fingerprint_reader = lambda _pid: "different-process"
        with self._clock(self.now + timedelta(minutes=1)):
            response = self.supervisor.status("coder")
        self.assertEqual(BotStatus.failed, response.status)
        self.assertEqual(2, self._record().restart_attempts)


class RestartStabilitySettingsTests(unittest.TestCase):
    def test_defaults_overrides_and_invalid_bounds(self) -> None:
        self.assertEqual(30, Settings.from_env({}, include_dotenv=False).restart_stability_seconds)
        for value in ("0", "12.5", "86400"):
            with self.subTest(value=value):
                settings = Settings.from_env(
                    {"ZEUS_RESTART_STABILITY_SECONDS": value}, include_dotenv=False
                )
                self.assertEqual(float(value), settings.restart_stability_seconds)
        for value in ("-1", "86401", "nan", "inf", "invalid"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "ZEUS_RESTART_STABILITY_SECONDS"),
            ):
                Settings.from_env({"ZEUS_RESTART_STABILITY_SECONDS": value}, include_dotenv=False)

    def test_cli_demo_and_api_forward_configured_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings.from_env(
                {"ZEUS_STATE_DIR": tmp, "ZEUS_RESTART_STABILITY_SECONDS": "12.5"},
                include_dotenv=False,
            )
            with (
                patch("zeus.cli.Supervisor", wraps=Supervisor) as cli_supervisor,
                patch("zeus.cli._demo_hermes_bin", return_value="fake-hermes"),
                patch("zeus.cli._demo_cmdline_reader", return_value=lambda _pid: []),
            ):
                _services(settings)
                _demo_services(settings, "coder")
            self.assertEqual(2, cli_supervisor.call_count)
            for call in cli_supervisor.call_args_list:
                self.assertEqual(12.5, call.kwargs["restart_stability_seconds"])
            with patch("zeus.api.Supervisor", wraps=Supervisor) as api_supervisor:
                make_handler(settings)
            self.assertEqual(12.5, api_supervisor.call_args.kwargs["restart_stability_seconds"])
