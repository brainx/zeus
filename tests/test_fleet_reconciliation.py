from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeus.cli import _reconcile_exit_code
from zeus.lifecycle import LifecycleEventInput
from zeus.models import BotRecord, BotStatus, BotStatusResponse, DesiredState, RestartPolicy
from zeus.process_lock import BotProcessLock, LockTimeoutError
from zeus.reconciliation import (
    MAX_RECONCILE_TEXT_LENGTH,
    BotReconcileResult,
    FleetReconciler,
    PersistedReconcileRun,
    ReconcileLockTimeoutError,
    ReconcileOutcome,
    ReconcileRunStart,
    ReconcileRunSummary,
    ReconcileSnapshotDriftError,
    summarize_results,
)
from zeus.state import StateStore
from zeus.supervisor import Supervisor

RUN_STARTED_AT = datetime(2026, 7, 12, 11, 59, tzinfo=UTC)
RUN_FINISHED_AT = datetime(2026, 7, 12, 12, 1, tzinfo=UTC)


class _CoordinatorSupervisor:
    def __init__(self, store: StateStore, effects: dict[str, object] | None = None) -> None:
        self.store = store
        self.effects = effects or {}
        self.calls: list[str] = []
        self.lock_timeout_seconds = 0.05

    def validate_reconcile_target(
        self,
        bot_id: str,
        *,
        expected_profile_path: str | None = None,
    ) -> str:
        record = self.store.get_bot(bot_id)
        if record is None:
            raise KeyError(f"unknown bot: {bot_id}")
        if expected_profile_path is not None and record.profile_path != expected_profile_path:
            raise ReconcileSnapshotDriftError(bot_id)
        return record.profile_path

    def validate_reconcile_request(self, source: str, request_id: str | None) -> None:
        del source, request_id

    def reconcile_one(
        self,
        bot_id: str,
        *,
        now: datetime | None = None,
        force: bool = False,
        reset_restart: bool = False,
        source: str = "reconcile",
        request_id: str | None = None,
        expected_profile_path: str | None = None,
    ) -> BotReconcileResult:
        del now, force, reset_restart, source, request_id
        self.calls.append(bot_id)
        effect = self.effects.get(bot_id)
        if callable(effect):
            effect = effect()
        if isinstance(effect, BaseException):
            raise effect
        if isinstance(effect, BotReconcileResult):
            return effect
        record = self.store.get_bot(bot_id)
        if record is None:
            if expected_profile_path is not None:
                raise ReconcileSnapshotDriftError(bot_id)
            raise KeyError(f"unknown bot: {bot_id}")
        if expected_profile_path is not None and record.profile_path != expected_profile_path:
            raise ReconcileSnapshotDriftError(bot_id)
        started_at = datetime.now(UTC)
        return BotReconcileResult(
            bot_id=bot_id,
            outcome=ReconcileOutcome.healthy,
            desired_state="stopped",
            observed_status="stopped",
            pid=None,
            action="none",
            message="not running",
            error_code=None,
            event_id=None,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

    def reconcile_one_execution(self, *args, **kwargs):
        result = self.reconcile_one(*args, **kwargs)
        record = self.store.get_bot(result.bot_id)
        if record is None:
            raise ReconcileSnapshotDriftError(result.bot_id)
        status = (
            BotStatus(result.observed_status)
            if result.observed_status is not None
            else BotStatus.failed
        )
        return result, BotStatusResponse(
            bot_id=result.bot_id,
            status=status,
            pid=result.pid,
            profile_path=record.profile_path,
            message=result.message,
        )


class _AppendFailingStore:
    def __init__(self, store: StateStore) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def append_reconcile_result(self, run_id: str, result: BotReconcileResult) -> None:
        del run_id, result
        raise sqlite3.OperationalError("injected append failure")


class _FinishFailingStore:
    def __init__(self, store: StateStore) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def finish_reconcile_run(self, summary: ReconcileRunSummary) -> PersistedReconcileRun:
        del summary
        raise sqlite3.OperationalError("injected finish failure")


class _BeginFailingStore:
    def __init__(self, store: StateStore) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def begin_reconcile_run(self, run: ReconcileRunStart) -> None:
        del run
        raise sqlite3.OperationalError("injected begin failure")


class ReconciliationSummaryTests(unittest.TestCase):
    def _result(
        self,
        outcome: ReconcileOutcome,
        *,
        bot_id: str = "coder",
    ) -> BotReconcileResult:
        started_at = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
        return BotReconcileResult(
            bot_id=bot_id,
            outcome=outcome,
            desired_state="running",
            observed_status="running",
            pid=1234,
            action="none",
            message="reconciled",
            error_code=None,
            event_id=None,
            started_at=started_at,
            finished_at=started_at + timedelta(seconds=1),
        )

    def test_outcomes_have_the_exact_contract_values(self) -> None:
        self.assertEqual(
            [
                "healthy",
                "changed",
                "pending",
                "action_required",
                "error",
                "skipped",
            ],
            [outcome.value for outcome in ReconcileOutcome],
        )

    def test_each_result_increments_exactly_one_counter(self) -> None:
        results = [
            self._result(outcome, bot_id=f"bot-{index}")
            for index, outcome in enumerate(ReconcileOutcome, start=1)
        ]

        summary = summarize_results(
            "run-1",
            "fleet",
            results,
            started_at=RUN_STARTED_AT,
            finished_at=RUN_FINISHED_AT,
        )

        self.assertEqual(len(results), summary.total)
        self.assertEqual(
            {outcome.value: 1 for outcome in ReconcileOutcome},
            dict(summary.counts),
        )
        self.assertEqual(summary.total, sum(summary.counts.values()))
        self.assertEqual("completed_with_errors", summary.outcome)
        self.assertFalse(summary.ok)

    def test_pending_only_summary_is_successful(self) -> None:
        summary = summarize_results(
            "run-1",
            "fleet",
            [self._result(ReconcileOutcome.pending)],
            started_at=RUN_STARTED_AT,
            finished_at=RUN_FINISHED_AT,
        )

        self.assertEqual("succeeded", summary.outcome)
        self.assertTrue(summary.ok)

    def test_success_only_outcomes_do_not_report_errors(self) -> None:
        successful = (
            ReconcileOutcome.healthy,
            ReconcileOutcome.changed,
            ReconcileOutcome.pending,
            ReconcileOutcome.skipped,
        )
        results = [
            self._result(outcome, bot_id=f"bot-{index}")
            for index, outcome in enumerate(successful, start=1)
        ]

        summary = summarize_results(
            "run-1",
            "fleet",
            results,
            started_at=RUN_STARTED_AT,
            finished_at=RUN_FINISHED_AT,
        )

        self.assertEqual("succeeded", summary.outcome)
        self.assertTrue(summary.ok)

    def test_summary_freezes_results_and_counts_while_preserving_order(self) -> None:
        supplied = [
            self._result(ReconcileOutcome.changed, bot_id="zeta"),
            self._result(ReconcileOutcome.healthy, bot_id="alpha"),
        ]

        summary = summarize_results(
            "run-1",
            "fleet",
            iter(supplied),
            started_at=RUN_STARTED_AT,
            finished_at=RUN_FINISHED_AT,
        )
        supplied.reverse()

        self.assertIsInstance(summary.results, tuple)
        self.assertEqual(["zeta", "alpha"], [result.bot_id for result in summary.results])
        self.assertEqual(RUN_STARTED_AT, summary.started_at)
        self.assertEqual(RUN_FINISHED_AT, summary.finished_at)
        with self.assertRaises(TypeError):
            summary.counts["healthy"] = 99  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            summary.total = 99  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            summary.results[0].message = "changed"  # type: ignore[misc]

    def test_result_bounds_operator_visible_text(self) -> None:
        result = self._result(ReconcileOutcome.error)

        bounded = BotReconcileResult(
            bot_id=result.bot_id,
            outcome=result.outcome,
            desired_state=result.desired_state,
            observed_status=result.observed_status,
            pid=result.pid,
            action="a" * (MAX_RECONCILE_TEXT_LENGTH + 1),
            message="m" * (MAX_RECONCILE_TEXT_LENGTH + 1),
            error_code="e" * (MAX_RECONCILE_TEXT_LENGTH + 1),
            event_id=result.event_id,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )

        self.assertEqual(MAX_RECONCILE_TEXT_LENGTH, len(bounded.action))
        self.assertEqual(MAX_RECONCILE_TEXT_LENGTH, len(bounded.message))
        self.assertEqual(MAX_RECONCILE_TEXT_LENGTH, len(bounded.error_code or ""))

    def test_result_rejects_invalid_structural_fields(self) -> None:
        result = self._result(ReconcileOutcome.healthy)
        cases = (
            {"bot_id": ""},
            {"outcome": "not-an-outcome"},
            {"desired_state": "sideways"},
            {"observed_status": "missing"},
            {"pid": 0},
            {"event_id": 0},
            {"finished_at": result.started_at - timedelta(microseconds=1)},
        )

        for replacement in cases:
            values = {
                "bot_id": result.bot_id,
                "outcome": result.outcome,
                "desired_state": result.desired_state,
                "observed_status": result.observed_status,
                "pid": result.pid,
                "action": result.action,
                "message": result.message,
                "error_code": result.error_code,
                "event_id": result.event_id,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
            }
            values.update(replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                BotReconcileResult(**values)  # type: ignore[arg-type]

    def test_summary_rejects_invalid_identity_scope_and_duplicate_bots(self) -> None:
        result = self._result(ReconcileOutcome.healthy)

        with self.assertRaises(ValueError):
            summarize_results(
                "",
                "fleet",
                [result],
                started_at=RUN_STARTED_AT,
                finished_at=RUN_FINISHED_AT,
            )
        with self.assertRaises(ValueError):
            summarize_results(
                "run-1",
                "all",
                [result],
                started_at=RUN_STARTED_AT,
                finished_at=RUN_FINISHED_AT,
            )
        with self.assertRaises(ValueError):
            summarize_results(
                "run-1",
                "fleet",
                [result, result],
                started_at=RUN_STARTED_AT,
                finished_at=RUN_FINISHED_AT,
            )

    def test_empty_fleet_retains_explicit_run_interval(self) -> None:
        summary = summarize_results(
            "run-empty",
            "fleet",
            [],
            started_at=RUN_STARTED_AT,
            finished_at=RUN_FINISHED_AT,
        )

        self.assertEqual(0, summary.total)
        self.assertEqual({outcome.value: 0 for outcome in ReconcileOutcome}, summary.counts)
        self.assertEqual((), summary.results)
        self.assertEqual(RUN_STARTED_AT, summary.started_at)
        self.assertEqual(RUN_FINISHED_AT, summary.finished_at)
        self.assertEqual("succeeded", summary.outcome)
        self.assertTrue(summary.ok)

    def test_summary_rejects_naive_or_reversed_run_intervals(self) -> None:
        naive = datetime(2026, 7, 12, 12, 0)
        cases = (
            (naive, RUN_FINISHED_AT),
            (RUN_STARTED_AT, naive),
            (RUN_FINISHED_AT, RUN_STARTED_AT),
        )

        for started_at, finished_at in cases:
            with (
                self.subTest(started_at=started_at, finished_at=finished_at),
                self.assertRaises(ValueError),
            ):
                summarize_results(
                    "run-1",
                    "fleet",
                    [],
                    started_at=started_at,
                    finished_at=finished_at,
                )

    def test_summary_rejects_results_outside_run_interval(self) -> None:
        result = self._result(ReconcileOutcome.healthy)
        cases = (
            (
                replace(result, started_at=RUN_STARTED_AT - timedelta(seconds=1)),
                "starts before",
            ),
            (
                replace(result, finished_at=RUN_FINISHED_AT + timedelta(seconds=1)),
                "finishes after",
            ),
        )

        for outside_result, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                summarize_results(
                    "run-1",
                    "fleet",
                    [outside_result],
                    started_at=RUN_STARTED_AT,
                    finished_at=RUN_FINISHED_AT,
                )


class ReconciliationPersistenceTests(unittest.TestCase):
    def _run(
        self,
        run_id: str = "run-1",
        *,
        scope: str = "fleet",
        requested_bot_id: str | None = None,
        started_at: datetime = RUN_STARTED_AT,
    ) -> ReconcileRunStart:
        return ReconcileRunStart(
            run_id=run_id,
            scope=scope,
            requested_bot_id=requested_bot_id,
            source="cli",
            force=False,
            reset_restart=False,
            started_at=started_at,
        )

    def _result(
        self,
        bot_id: str,
        outcome: ReconcileOutcome = ReconcileOutcome.healthy,
        *,
        event_id: int | None = None,
    ) -> BotReconcileResult:
        started_at = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
        return BotReconcileResult(
            bot_id=bot_id,
            outcome=outcome,
            desired_state="running",
            observed_status="running",
            pid=1234,
            action="none" if outcome is ReconcileOutcome.healthy else "start",
            message="reconciled",
            error_code=None,
            event_id=event_id,
            started_at=started_at,
            finished_at=started_at + timedelta(seconds=1),
        )

    def _summary(
        self,
        run: ReconcileRunStart,
        results: list[BotReconcileResult],
        *,
        finished_at: datetime = RUN_FINISHED_AT,
    ) -> ReconcileRunSummary:
        return summarize_results(
            run.run_id,
            run.scope,
            results,
            started_at=run.started_at,
            finished_at=finished_at,
        )

    def _lifecycle_event(self, store: StateStore, root: Path, bot_id: str, seed: str) -> int:
        event = store.upsert_bot_with_event(
            BotRecord(
                bot_id=bot_id,
                template_id="coding-bot",
                display_name=bot_id.title(),
                profile_path=str(root / "profiles" / bot_id),
            ),
            event=LifecycleEventInput(
                bot_id=bot_id,
                operation_id=seed * 32,
                source="cli",
                action="bot.create",
                outcome="success",
            ),
        )
        return event.event_id

    def test_v6_round_trip_preserves_result_order_and_lifecycle_linkage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            event = store.upsert_bot_with_event(
                BotRecord(
                    bot_id="zeta",
                    template_id="coding-bot",
                    display_name="Zeta",
                    profile_path=str(Path(tmp) / "profiles" / "zeta"),
                ),
                event=LifecycleEventInput(
                    bot_id="zeta",
                    operation_id="a" * 32,
                    source="cli",
                    action="bot.create",
                    outcome="success",
                ),
            )
            run = self._run()
            changed = self._result(
                "zeta",
                ReconcileOutcome.changed,
                event_id=event.event_id,
            )
            healthy = self._result("alpha")

            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, changed)
            store.append_reconcile_result(run.run_id, healthy)
            finished = store.finish_reconcile_run(self._summary(run, [changed, healthy]))
            loaded = store.get_reconcile_run(run.run_id)

            self.assertIsInstance(finished, PersistedReconcileRun)
            self.assertEqual(finished, loaded)
            assert loaded is not None
            self.assertEqual("succeeded", loaded.outcome)
            self.assertEqual(2, loaded.total)
            self.assertEqual(["zeta", "alpha"], [item.bot_id for item in loaded.results])
            self.assertEqual(event.event_id, loaded.results[0].event_id)
            self.assertIsNone(loaded.results[1].event_id)
            with closing(sqlite3.connect(store.database_path)) as conn:
                ordinals = conn.execute(
                    "SELECT ordinal FROM reconcile_results WHERE run_id = ? ORDER BY ordinal",
                    (run.run_id,),
                ).fetchall()
            self.assertEqual([(0,), (1,)], ordinals)

    def test_healthy_noop_result_does_not_create_lifecycle_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            run = self._run()
            result = self._result("coder")

            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)

            with closing(sqlite3.connect(store.database_path)) as conn:
                event_count = conn.execute("SELECT COUNT(*) FROM lifecycle_events").fetchone()[0]
            self.assertEqual(0, event_count)

    def test_duplicate_and_late_results_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            run = self._run()
            result = self._result("coder")

            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)
            with self.assertRaises(sqlite3.IntegrityError):
                store.append_reconcile_result(run.run_id, result)
            store.finish_reconcile_run(self._summary(run, [result]))

            with self.assertRaisesRegex(RuntimeError, "not running"):
                store.append_reconcile_result(run.run_id, self._result("later"))

    def test_finish_rejects_result_or_counter_mismatch_without_closing_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            run = self._run()
            result = self._result("coder")
            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)

            with self.assertRaisesRegex(RuntimeError, "persisted reconciliation results"):
                store.finish_reconcile_run(self._summary(run, []))
            loaded = store.get_reconcile_run(run.run_id)
            assert loaded is not None
            self.assertEqual("running", loaded.outcome)
            self.assertEqual(1, loaded.total)

            with closing(sqlite3.connect(store.database_path)) as conn:
                conn.execute(
                    """
                    UPDATE reconcile_runs
                    SET healthy_count = 0, changed_count = 1
                    WHERE run_id = ?
                    """,
                    (run.run_id,),
                )
                conn.commit()
            with self.assertRaisesRegex(RuntimeError, "persisted reconciliation counters"):
                store.finish_reconcile_run(self._summary(run, [result]))

    def test_interrupt_marks_only_running_runs_with_exact_partial_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            partial_run = self._run("run-partial")
            empty_run = self._run("run-empty")
            completed_run = self._run("run-completed")
            pending = self._result("coder", ReconcileOutcome.pending)
            store.begin_reconcile_run(partial_run)
            store.append_reconcile_result(partial_run.run_id, pending)
            store.begin_reconcile_run(empty_run)
            store.begin_reconcile_run(completed_run)
            store.finish_reconcile_run(self._summary(completed_run, []))
            interrupted_at = RUN_FINISHED_AT + timedelta(minutes=1)

            interrupted = store.interrupt_stale_reconcile_runs(interrupted_at=interrupted_at)

            self.assertEqual(2, interrupted)
            partial = store.get_reconcile_run(partial_run.run_id)
            empty = store.get_reconcile_run(empty_run.run_id)
            completed = store.get_reconcile_run(completed_run.run_id)
            assert partial is not None and empty is not None and completed is not None
            self.assertEqual("interrupted", partial.outcome)
            self.assertEqual(interrupted_at, partial.finished_at)
            self.assertEqual(1, partial.total)
            self.assertEqual(1, partial.counts["pending"])
            self.assertEqual("interrupted", empty.outcome)
            self.assertEqual(0, empty.total)
            self.assertEqual("succeeded", completed.outcome)

    def test_run_start_validates_scope_identity_and_timestamp(self) -> None:
        bot_run = self._run("run-bot", scope="bot", requested_bot_id="coder")
        self.assertEqual("coder", bot_run.requested_bot_id)

        invalid = (
            {"scope": "fleet", "requested_bot_id": "coder"},
            {"scope": "bot", "requested_bot_id": None},
            {"scope": "all", "requested_bot_id": None},
            {"scope": "fleet", "requested_bot_id": None, "source": ""},
            {
                "scope": "fleet",
                "requested_bot_id": None,
                "started_at": datetime(2026, 7, 12, 12, 0),
            },
        )
        for replacement in invalid:
            values = {
                "run_id": "run-invalid",
                "scope": "fleet",
                "requested_bot_id": None,
                "source": "cli",
                "force": False,
                "reset_restart": False,
                "started_at": RUN_STARTED_AT,
            }
            values.update(replacement)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                ReconcileRunStart(**values)  # type: ignore[arg-type]

    def test_bot_scoped_run_rejects_other_bot_and_corrupted_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            run = self._run("run-bot", scope="bot", requested_bot_id="coder")
            store.begin_reconcile_run(run)

            with self.assertRaisesRegex(ValueError, "requested bot"):
                store.append_reconcile_result(run.run_id, self._result("other"))
            empty = store.get_reconcile_run(run.run_id)
            assert empty is not None
            self.assertEqual(0, empty.total)

            store.append_reconcile_result(run.run_id, self._result("coder"))
            with self.assertRaises(sqlite3.IntegrityError):
                store.append_reconcile_result(run.run_id, self._result("coder"))
            with closing(sqlite3.connect(store.database_path)) as conn:
                conn.execute(
                    "UPDATE reconcile_runs SET requested_bot_id = 'other' WHERE run_id = ?",
                    (run.run_id,),
                )
                conn.commit()
            with self.assertRaisesRegex(ValueError, "requested bot"):
                store.get_reconcile_run(run.run_id)

    def test_result_event_must_exist_and_belong_to_the_same_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            run = self._run()
            store.begin_reconcile_run(run)

            with self.assertRaisesRegex(ValueError, "lifecycle event"):
                store.append_reconcile_result(
                    run.run_id,
                    self._result("coder", ReconcileOutcome.changed, event_id=999),
                )
            other_event_id = self._lifecycle_event(store, root, "other", "b")
            with self.assertRaisesRegex(ValueError, "lifecycle event"):
                store.append_reconcile_result(
                    run.run_id,
                    self._result("coder", ReconcileOutcome.changed, event_id=other_event_id),
                )

            loaded = store.get_reconcile_run(run.run_id)
            assert loaded is not None
            self.assertEqual(0, loaded.total)
            self.assertEqual(1, len(store.list_lifecycle_events("other", 10, None)))

    def test_materialization_rejects_results_outside_run_interval(self) -> None:
        for corruption, expected_message in (
            ("started_at", "starts before"),
            ("finished_at", "finishes after"),
        ):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as tmp:
                store = StateStore(Path(tmp) / "zeus.db")
                store.init()
                run = self._run()
                result = self._result("coder")
                store.begin_reconcile_run(run)
                store.append_reconcile_result(run.run_id, result)
                store.finish_reconcile_run(self._summary(run, [result]))
                corrupted_timestamp = (
                    (RUN_STARTED_AT - timedelta(seconds=1)).isoformat()
                    if corruption == "started_at"
                    else (RUN_FINISHED_AT + timedelta(seconds=1)).isoformat()
                )
                with closing(sqlite3.connect(store.database_path)) as conn:
                    conn.execute(
                        f"UPDATE reconcile_results SET {corruption} = ? WHERE run_id = ?",
                        (corrupted_timestamp, run.run_id),
                    )
                    conn.commit()

                with self.assertRaisesRegex(ValueError, expected_message):
                    store.get_reconcile_run(run.run_id)

    def test_interruption_after_late_result_rolls_back_all_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            empty_run = self._run("run-empty")
            late_run = self._run("run-late")
            store.begin_reconcile_run(empty_run)
            store.begin_reconcile_run(late_run)
            store.append_reconcile_result(late_run.run_id, self._result("coder"))
            interrupted_at = datetime(2026, 7, 12, 12, 0, 0, 500_000, tzinfo=UTC)

            with self.assertRaisesRegex(ValueError, "finishes after"):
                store.interrupt_stale_reconcile_runs(interrupted_at=interrupted_at)

            empty = store.get_reconcile_run(empty_run.run_id)
            late = store.get_reconcile_run(late_run.run_id)
            assert empty is not None and late is not None
            self.assertEqual("running", empty.outcome)
            self.assertEqual("running", late.outcome)
            self.assertIsNone(empty.finished_at)
            self.assertIsNone(late.finished_at)

    def test_corrupted_sqlite_numeric_types_fail_closed_without_coercion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            run = self._run()
            result = self._result("coder")
            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)
            store.finish_reconcile_run(self._summary(run, [result]))
            corruptions = (
                ("reconcile_runs", "force", 1.5, 0),
                ("reconcile_runs", "reset_restart", 0.5, 0),
                ("reconcile_runs", "total", 1.5, 1),
                ("reconcile_runs", "healthy_count", 1.5, 1),
                ("reconcile_results", "ordinal", 0.5, 0),
                ("reconcile_results", "pid", 1234.5, 1234),
                ("reconcile_results", "event_id", 1.5, None),
            )
            with closing(sqlite3.connect(store.database_path)) as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                for table, column, corrupted, restored in corruptions:
                    with self.subTest(table=table, column=column):
                        conn.execute(
                            f"UPDATE {table} SET {column} = ? WHERE run_id = ?",
                            (corrupted, run.run_id),
                        )
                        conn.commit()
                        with self.assertRaises((TypeError, ValueError)):
                            store.get_reconcile_run(run.run_id)
                        conn.execute(
                            f"UPDATE {table} SET {column} = ? WHERE run_id = ?",
                            (restored, run.run_id),
                        )
                        conn.commit()


class FleetCoordinatorTests(unittest.TestCase):
    def _add_bot(self, store: StateStore, root: Path, bot_id: str) -> None:
        store.upsert_bot(
            BotRecord(
                bot_id=bot_id,
                template_id="coding-bot",
                display_name=bot_id.title(),
                profile_path=str(root / "profiles" / bot_id),
            )
        )

    def test_fleet_is_sorted_and_continues_after_exception_and_lock_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            for bot_id in ("zeta", "beta", "alpha"):
                self._add_bot(store, root, bot_id)
            supervisor = _CoordinatorSupervisor(
                store,
                {
                    "alpha": RuntimeError("broken"),
                    "beta": LockTimeoutError(root / "locks" / "bots" / "beta.lock", 0.01),
                },
            )

            summary = FleetReconciler(store, supervisor).run(source="cli")

            self.assertEqual(["alpha", "beta", "zeta"], supervisor.calls)
            self.assertEqual(
                [ReconcileOutcome.error, ReconcileOutcome.error, ReconcileOutcome.healthy],
                [result.outcome for result in summary.results],
            )
            self.assertEqual(summary.total, sum(summary.counts.values()))
            self.assertEqual("completed_with_errors", summary.outcome)
            loaded = store.get_reconcile_run(summary.run_id)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(summary.results, loaded.results)

    def test_bot_exceptions_use_fixed_public_messages_without_raw_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            self._add_bot(store, root, "beta")
            secret = "token-secret /private/runtime/alpha.lock"
            supervisor = _CoordinatorSupervisor(
                store,
                {
                    "alpha": RuntimeError(secret),
                    "beta": LockTimeoutError(Path("/private/runtime/beta.lock"), 0.01),
                },
            )

            summary = FleetReconciler(store, supervisor).run()

            self.assertEqual(
                ["bot reconciliation failed", "bot reconciliation lock timed out"],
                [result.message for result in summary.results],
            )
            self.assertEqual(
                ["reconcile_error", "lock_timeout"],
                [result.error_code for result in summary.results],
            )
            serialized = repr(summary.results)
            self.assertNotIn(secret, serialized)
            self.assertNotIn("/private/runtime", serialized)

    def test_generic_key_error_is_error_not_snapshot_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            supervisor = _CoordinatorSupervisor(
                store,
                {"alpha": KeyError("internal lookup token-secret")},
            )

            summary = FleetReconciler(store, supervisor).run()

            self.assertEqual(ReconcileOutcome.error, summary.results[0].outcome)
            self.assertEqual("reconcile_error", summary.results[0].error_code)
            self.assertNotIn("token-secret", summary.results[0].message)

    def test_supplied_snapshot_preserves_order_and_rejects_duplicates_before_begin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            self._add_bot(store, root, "zeta")
            supervisor = _CoordinatorSupervisor(store)
            snapshot = (
                ("zeta", str(root / "profiles" / "zeta")),
                ("alpha", str(root / "profiles" / "alpha")),
            )

            summary = FleetReconciler(store, supervisor).run(bot_snapshot=snapshot)

            self.assertEqual(["zeta", "alpha"], supervisor.calls)
            self.assertEqual(["zeta", "alpha"], [result.bot_id for result in summary.results])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            supervisor = _CoordinatorSupervisor(store)
            duplicate = (("alpha", str(root / "profiles" / "alpha")),) * 2

            with self.assertRaisesRegex(ValueError, "duplicate"):
                FleetReconciler(store, supervisor).run(bot_snapshot=duplicate)

            self.assertEqual([], supervisor.calls)
            with closing(sqlite3.connect(store.database_path)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0]
            self.assertEqual(0, count)

    def test_keyboard_interrupt_is_not_converted_and_partial_run_stays_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            supervisor = _CoordinatorSupervisor(store, {"alpha": KeyboardInterrupt()})

            with self.assertRaises(KeyboardInterrupt):
                FleetReconciler(store, supervisor).run()

            with closing(sqlite3.connect(store.database_path)) as conn:
                rows = conn.execute("SELECT outcome, total FROM reconcile_runs").fetchall()
            self.assertEqual([("running", 0)], rows)

    def test_deleted_snapshot_bot_is_skipped_and_earlier_change_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            self._add_bot(store, root, "beta")

            def change_alpha_then_delete_beta() -> None:
                store.update_status("alpha", BotStatus.running, pid=1234)
                store.delete_bot("beta")

            supervisor = _CoordinatorSupervisor(store, {"alpha": change_alpha_then_delete_beta})

            summary = FleetReconciler(store, supervisor).run()

            self.assertEqual(["alpha", "beta"], [result.bot_id for result in summary.results])
            self.assertEqual(ReconcileOutcome.skipped, summary.results[1].outcome)
            alpha = store.get_bot("alpha")
            assert alpha is not None
            self.assertEqual(BotStatus.running, alpha.status)
            self.assertEqual(1234, alpha.pid)

    def test_execution_summary_keeps_skipped_results_while_legacy_omits_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            self._add_bot(store, root, "beta")

            def delete_beta() -> None:
                store.delete_bot("beta")

            coordinator = FleetReconciler(
                store,
                _CoordinatorSupervisor(store, {"alpha": delete_beta}),
            )

            execution = coordinator.execute()

            self.assertEqual(
                [ReconcileOutcome.healthy, ReconcileOutcome.skipped],
                [result.outcome for result in execution.summary.results],
            )
            self.assertEqual(
                ["alpha"],
                [response.bot_id for response in execution.legacy_responses],
            )

    def test_replacement_during_lock_timeout_is_drift_not_replacement_failure(self) -> None:
        for explicit in (False, True):
            with self.subTest(explicit=explicit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = StateStore(root / "zeus.db")
                store.init()
                self._add_bot(store, root, "alpha")
                original_profile = str(root / "profiles" / "alpha")
                replacement_profile = str(root / "profiles" / "replacement-alpha")

                def replace_then_timeout(
                    current_store: StateStore = store,
                    current_replacement_profile: str = replacement_profile,
                    current_root: Path = root,
                ) -> LockTimeoutError:
                    record = current_store.get_bot("alpha")
                    assert record is not None
                    current_store.upsert_bot(
                        replace(record, profile_path=current_replacement_profile)
                    )
                    return LockTimeoutError(current_root / "locks" / "alpha.lock", 0.01)

                coordinator = FleetReconciler(
                    store,
                    _CoordinatorSupervisor(store, {"alpha": replace_then_timeout}),
                )

                summary = coordinator.run(bot_id="alpha" if explicit else None)

                expected_outcome = ReconcileOutcome.error if explicit else ReconcileOutcome.skipped
                self.assertEqual(expected_outcome, summary.results[0].outcome)
                self.assertEqual(
                    "snapshot_drift" if explicit else "bot_missing",
                    summary.results[0].error_code,
                )
                self.assertNotIn(replacement_profile, repr(summary.results[0]))
                if explicit:
                    self.assertEqual(1, len(coordinator.legacy_responses))
                    self.assertEqual(
                        original_profile,
                        coordinator.legacy_responses[0].profile_path,
                    )
                    self.assertEqual(BotStatus.failed, coordinator.legacy_responses[0].status)
                else:
                    self.assertEqual((), coordinator.legacy_responses)

    def test_concurrent_fleet_lock_creates_no_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = _CoordinatorSupervisor(store)
            lock_path = root / "locks" / "reconcile.lock"

            with (
                BotProcessLock(lock_path, timeout_seconds=0.1),
                self.assertRaises(ReconcileLockTimeoutError),
            ):
                FleetReconciler(store, supervisor, lock_timeout_seconds=0.01).run()

            with closing(sqlite3.connect(store.database_path)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0]
            self.assertEqual(0, count)

    def test_inner_bot_lock_timeout_is_not_reclassified_as_global_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            supervisor = _CoordinatorSupervisor(store)
            inner_error = LockTimeoutError(root / "locks" / "bots" / "alpha.lock", 0.01)

            with (
                patch.object(
                    supervisor,
                    "validate_reconcile_target",
                    side_effect=inner_error,
                ),
                self.assertRaises(LockTimeoutError) as captured,
            ):
                FleetReconciler(store, supervisor).run(bot_id="alpha")

            self.assertIs(type(captured.exception), LockTimeoutError)
            with closing(sqlite3.connect(store.database_path)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0]
            self.assertEqual(0, count)

    def test_next_run_interrupts_stale_run_and_persists_requested_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            stale = ReconcileRunStart(
                run_id="stale-run",
                scope="fleet",
                requested_bot_id=None,
                source="cli",
                force=False,
                reset_restart=False,
                started_at=datetime.now(UTC) - timedelta(minutes=1),
            )
            store.begin_reconcile_run(stale)

            summary = FleetReconciler(store, _CoordinatorSupervisor(store)).run(
                source="cli",
                force=True,
                reset_restart=True,
            )

            interrupted = store.get_reconcile_run(stale.run_id)
            current = store.get_reconcile_run(summary.run_id)
            assert interrupted is not None and current is not None
            self.assertEqual("interrupted", interrupted.outcome)
            self.assertEqual("succeeded", current.outcome)
            self.assertEqual("cli", current.source)
            self.assertTrue(current.force)
            self.assertTrue(current.reset_restart)

    def test_result_persistence_failure_propagates_and_leaves_running_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            failing_store = _AppendFailingStore(store)

            with self.assertRaisesRegex(sqlite3.OperationalError, "injected append"):
                FleetReconciler(failing_store, _CoordinatorSupervisor(store)).run()

            with closing(sqlite3.connect(store.database_path)) as conn:
                rows = conn.execute("SELECT outcome, total FROM reconcile_runs").fetchall()
            self.assertEqual([("running", 0)], rows)

    def test_begin_and_finish_failures_do_not_fabricate_completed_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            self._add_bot(store, root, "alpha")
            supervisor = _CoordinatorSupervisor(store)

            with self.assertRaisesRegex(sqlite3.OperationalError, "injected begin"):
                FleetReconciler(_BeginFailingStore(store), supervisor).run()
            self.assertEqual([], supervisor.calls)

            with self.assertRaisesRegex(sqlite3.OperationalError, "injected finish"):
                FleetReconciler(_FinishFailingStore(store), supervisor).run()

            with closing(sqlite3.connect(store.database_path)) as conn:
                rows = conn.execute("SELECT outcome, total FROM reconcile_runs").fetchall()
            self.assertEqual([("running", 1)], rows)

    def test_real_fleet_run_links_transition_event_and_keeps_healthy_noop_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="alpha",
                    template_id="coding-bot",
                    display_name="Alpha",
                    profile_path=str(root / "hermes" / "profiles" / "alpha"),
                )
            )
            store.upsert_bot(
                BotRecord(
                    bot_id="beta",
                    template_id="coding-bot",
                    display_name="Beta",
                    profile_path=str(root / "hermes" / "profiles" / "beta"),
                    status=BotStatus.failed,
                    restart_policy=RestartPolicy.on_failure,
                    restart_backoff_seconds=10,
                    desired_state=DesiredState.running,
                )
            )
            supervisor = Supervisor(store, "hermes", root / "hermes")

            summary = FleetReconciler(store, supervisor).run(
                now=datetime(2026, 1, 1, tzinfo=UTC),
                source="cli",
            )

            self.assertEqual(["alpha", "beta"], [result.bot_id for result in summary.results])
            self.assertEqual(
                [ReconcileOutcome.healthy, ReconcileOutcome.pending],
                [result.outcome for result in summary.results],
            )
            self.assertIsNone(summary.results[0].event_id)
            self.assertEqual([], store.list_lifecycle_events("alpha", limit=10, before=None))
            beta_event = store.list_lifecycle_events("beta", limit=1, before=None)[0]
            self.assertEqual(beta_event.event_id, summary.results[1].event_id)
            self.assertEqual("bot.restart.schedule", summary.results[1].action)
            loaded = store.get_reconcile_run(summary.run_id)
            assert loaded is not None
            self.assertEqual(summary.results, loaded.results)

    def test_legacy_adapter_retains_original_response_after_later_bot_deletes_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            for bot_id in ("alpha", "beta"):
                store.upsert_bot(
                    BotRecord(
                        bot_id=bot_id,
                        template_id="coding-bot",
                        display_name=bot_id.title(),
                        profile_path=str(root / "hermes" / "profiles" / bot_id),
                    )
                )
            supervisor = Supervisor(store, "hermes", root / "hermes")

            def reconcile_effect(record, *args, **kwargs):
                del args, kwargs
                if record.bot_id == "beta":
                    store.delete_bot("alpha")
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.stopped,
                    pid=None,
                    profile_path=record.profile_path,
                    message=f"original {record.bot_id}",
                )

            with patch.object(supervisor, "_reconcile_record", side_effect=reconcile_effect):
                responses = supervisor.reconcile()

            self.assertEqual(["alpha", "beta"], [response.bot_id for response in responses])
            self.assertEqual(
                ["original alpha", "original beta"],
                [response.message for response in responses],
            )

    def test_explicit_legacy_reconcile_uses_serialized_persisted_bot_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(
                BotRecord(
                    bot_id="alpha",
                    template_id="coding-bot",
                    display_name="Alpha",
                    profile_path=str(root / "hermes" / "profiles" / "alpha"),
                )
            )
            supervisor = Supervisor(
                store,
                "hermes",
                root / "hermes",
                lock_timeout_seconds=0.01,
            )
            lock_path = root / "locks" / "reconcile.lock"

            with (
                BotProcessLock(lock_path, timeout_seconds=0.1),
                self.assertRaises(LockTimeoutError) as captured,
            ):
                supervisor.reconcile("alpha")
            self.assertIs(type(captured.exception), LockTimeoutError)
            with closing(sqlite3.connect(store.database_path)) as conn:
                self.assertEqual(
                    0,
                    conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0],
                )

            response = supervisor.reconcile("alpha")

            self.assertEqual(["alpha"], [item.bot_id for item in response])
            with closing(sqlite3.connect(store.database_path)) as conn:
                row = conn.execute(
                    "SELECT scope, requested_bot_id, outcome, total FROM reconcile_runs"
                ).fetchone()
            self.assertEqual(("bot", "alpha", "succeeded", 1), row)

    def test_supervisor_summary_entrypoint_runs_once_and_serializes_ordered_results(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            for bot_id in ("zeta", "alpha"):
                store.upsert_bot(
                    BotRecord(
                        bot_id=bot_id,
                        template_id="coding-bot",
                        display_name=bot_id.title(),
                        profile_path=str(root / "hermes" / "profiles" / bot_id),
                    )
                )
            supervisor = Supervisor(store, "hermes", root / "hermes")
            calls: list[str] = []

            def reconcile_effect(record: BotRecord, *args, **kwargs) -> BotStatusResponse:
                del args, kwargs
                calls.append(record.bot_id)
                return BotStatusResponse(
                    bot_id=record.bot_id,
                    status=BotStatus.stopped,
                    pid=None,
                    profile_path=record.profile_path,
                    message="not running",
                )

            with patch.object(
                supervisor,
                "_reconcile_record",
                side_effect=reconcile_effect,
            ):
                summary = supervisor.reconcile_summary(source="cli")

            with closing(sqlite3.connect(store.database_path)) as conn:
                run_count = conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0]
            self.assertEqual(1, run_count)
            self.assertEqual(["alpha", "zeta"], calls)
            self.assertEqual(["alpha", "zeta"], [item.bot_id for item in summary.results])
            payload = summary.to_dict()
            self.assertEqual(
                [
                    "run_id",
                    "scope",
                    "started_at",
                    "finished_at",
                    "outcome",
                    "ok",
                    "counts",
                    "total",
                    "results",
                ],
                list(payload),
            )
            self.assertEqual(summary.run_id, payload["run_id"])
            self.assertEqual(summary.started_at.isoformat(), payload["started_at"])
            self.assertEqual(summary.finished_at.isoformat(), payload["finished_at"])
            self.assertEqual(dict(summary.counts), payload["counts"])
            self.assertEqual(
                [
                    "bot_id",
                    "outcome",
                    "desired_state",
                    "observed_status",
                    "pid",
                    "action",
                    "message",
                    "error_code",
                    "event_id",
                    "started_at",
                    "finished_at",
                ],
                list(payload["results"][0]),
            )

    def test_explicit_missing_legacy_reconcile_creates_no_orphan_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, "hermes", root / "hermes")

            with self.assertRaisesRegex(KeyError, "unknown bot"):
                supervisor.reconcile("missing")

            with closing(sqlite3.connect(store.database_path)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0]
            self.assertEqual(0, count)

    def test_explicit_legacy_reconcile_reports_post_validation_target_drift(self) -> None:
        for drift_kind in ("delete", "replace"):
            with self.subTest(drift_kind=drift_kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = StateStore(root / "zeus.db")
                store.init()
                original_profile = root / "hermes" / "profiles" / "alpha"
                store.upsert_bot(
                    BotRecord(
                        bot_id="alpha",
                        template_id="coding-bot",
                        display_name="Alpha",
                        profile_path=str(original_profile),
                    )
                )
                supervisor = Supervisor(store, "hermes", root / "hermes")
                validate_target = supervisor.validate_reconcile_target

                def drift_after_validation(
                    bot_id: str,
                    *,
                    expected_profile_path: str | None = None,
                    current_store: StateStore = store,
                    current_drift_kind: str = drift_kind,
                    current_root: Path = root,
                    current_validate_target=validate_target,
                ) -> str:
                    profile_path = current_validate_target(
                        bot_id,
                        expected_profile_path=expected_profile_path,
                    )
                    if current_drift_kind == "delete":
                        current_store.delete_bot(bot_id)
                    else:
                        record = current_store.get_bot(bot_id)
                        assert record is not None
                        current_store.upsert_bot(
                            replace(
                                record,
                                profile_path=str(
                                    current_root / "hermes" / "profiles" / "replacement-alpha"
                                ),
                            )
                        )
                    return profile_path

                with patch.object(
                    supervisor,
                    "validate_reconcile_target",
                    side_effect=drift_after_validation,
                ):
                    responses = supervisor.reconcile("alpha")

                self.assertEqual(1, len(responses))
                self.assertEqual(BotStatus.failed, responses[0].status)
                self.assertEqual(str(original_profile), responses[0].profile_path)
                self.assertEqual("bot changed during reconciliation", responses[0].message)
                self.assertEqual(1, _reconcile_exit_code(responses))
                with closing(sqlite3.connect(store.database_path)) as conn:
                    row = conn.execute(
                        "SELECT run_id, scope, requested_bot_id, outcome, total FROM reconcile_runs"
                    ).fetchone()
                assert row is not None
                run_id, scope, requested_bot_id, outcome, total = row
                self.assertEqual(
                    ("bot", "alpha", "completed_with_errors", 1),
                    (scope, requested_bot_id, outcome, total),
                )
                loaded = store.get_reconcile_run(run_id)
                assert loaded is not None
                self.assertEqual(ReconcileOutcome.error, loaded.results[0].outcome)
                self.assertEqual("snapshot_drift", loaded.results[0].error_code)
                self.assertEqual(
                    "bot changed during reconciliation",
                    loaded.results[0].message,
                )

    def test_explicit_missing_bot_fails_before_creating_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()

            with self.assertRaisesRegex(KeyError, "unknown bot"):
                FleetReconciler(store, _CoordinatorSupervisor(store)).run(bot_id="missing")

            with closing(sqlite3.connect(store.database_path)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM reconcile_runs").fetchone()[0]
            self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()
