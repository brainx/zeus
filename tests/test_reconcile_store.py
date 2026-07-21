from __future__ import annotations

import ast
import inspect
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, call, patch

from zeus.idempotency_store import IdempotencyStore
from zeus.reconcile_store import RECONCILE_COUNTER_COLUMNS, ReconcileStore
from zeus.reconciliation import (
    BotReconcileResult,
    PersistedReconcileRun,
    ReconcileOutcome,
    ReconcileRunStart,
    ReconcileRunSummary,
    summarize_results,
)
from zeus.schema import SchemaManager
from zeus.sqlite_db import SQLiteDatabase
from zeus.state import RECONCILE_COUNTER_COLUMNS as STATE_RECONCILE_COUNTER_COLUMNS
from zeus.state import StateStore

RUN_STARTED_AT = datetime(2026, 7, 12, 11, 59, tzinfo=UTC)
RESULT_STARTED_AT = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
RESULT_FINISHED_AT = RESULT_STARTED_AT + timedelta(seconds=1)
RUN_FINISHED_AT = datetime(2026, 7, 12, 12, 1, tzinfo=UTC)


class _TracingSQLiteDatabase(SQLiteDatabase):
    traces: ClassVar[list[tuple[int, str]]]

    def __init__(self, database_path: Path | str) -> None:
        super().__init__(database_path)
        self.traces = []

    def connect(self) -> sqlite3.Connection:
        conn = super().connect()
        connection_id = id(conn)
        conn.set_trace_callback(lambda sql: self.traces.append((connection_id, sql)))
        return conn


def _run(
    run_id: str = "run-1",
    *,
    scope: str = "fleet",
    requested_bot_id: str | None = None,
) -> ReconcileRunStart:
    return ReconcileRunStart(
        run_id=run_id,
        scope=scope,
        requested_bot_id=requested_bot_id,
        source="cli",
        force=False,
        reset_restart=False,
        started_at=RUN_STARTED_AT,
    )


def _result(
    bot_id: str = "coder",
    outcome: ReconcileOutcome = ReconcileOutcome.healthy,
    *,
    event_id: int | None = None,
) -> BotReconcileResult:
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
        started_at=RESULT_STARTED_AT,
        finished_at=RESULT_FINISHED_AT,
    )


def _summary(
    run: ReconcileRunStart,
    results: list[BotReconcileResult],
) -> ReconcileRunSummary:
    return summarize_results(
        run.run_id,
        run.scope,
        results,
        started_at=run.started_at,
        finished_at=RUN_FINISHED_AT,
    )


def _control_statements(trace: list[tuple[int, str]]) -> list[str]:
    controls = {"BEGIN", "COMMIT", "ROLLBACK"}
    return [
        sql.strip().upper()
        for _connection_id, sql in trace
        if sql.strip().upper().split(maxsplit=1)[0] in controls
    ]


def _statements(trace: list[tuple[int, str]]) -> list[str]:
    return [sql for _connection_id, sql in trace]


def _statement_index(statements: list[str], prefix: str, *, start: int = 0) -> int:
    return next(
        index
        for index, statement in enumerate(statements[start:], start=start)
        if statement.lstrip().upper().startswith(prefix)
    )


def _run_bytes(database_path: Path, run_id: str) -> tuple[object, ...] | None:
    columns = (
        "run_id",
        "scope",
        "requested_bot_id",
        "source",
        "force",
        "reset_restart",
        "started_at",
        "finished_at",
        "outcome",
        "total",
        "healthy_count",
        "changed_count",
        "pending_count",
        "action_required_count",
        "error_count",
        "skipped_count",
    )
    fields = ", ".join(f"typeof({column}), hex(CAST({column} AS BLOB))" for column in columns)
    with closing(sqlite3.connect(database_path)) as conn:
        return conn.execute(
            f"SELECT {fields} FROM reconcile_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()


class ReconcileStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "zeus.db"
        self.database = SQLiteDatabase(self.database_path)
        SchemaManager(self.database).init()
        self.store = ReconcileStore(self.database)

    def test_constructs_without_opening_database_and_owns_no_schema_or_lifecycle_store(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "zeus.db"

            ReconcileStore(SQLiteDatabase(database_path))

            self.assertFalse(database_path.exists())

        import zeus.reconcile_store as reconcile_store_module

        source = inspect.getsource(reconcile_store_module)
        tree = ast.parse(source)
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertTrue(
            imported_modules.isdisjoint(
                {
                    "zeus.bot_lifecycle_store",
                    "zeus.lifecycle",
                    "zeus.schema",
                    "zeus.state",
                }
            )
        )
        self.assertNotIn("CREATE TABLE", source.upper())
        self.assertNotIn("CREATE TRIGGER", source.upper())

    def test_direct_store_round_trip_and_interruption(self) -> None:
        run = _run()
        result = _result(outcome=ReconcileOutcome.changed)

        self.store.begin_reconcile_run(run)
        self.store.append_reconcile_result(run.run_id, result)
        finished = self.store.finish_reconcile_run(_summary(run, [result]))
        loaded = self.store.get_reconcile_run(run.run_id)

        self.assertIsInstance(finished, PersistedReconcileRun)
        self.assertEqual(finished, loaded)
        self.assertEqual("succeeded", finished.outcome)
        self.assertEqual((result,), finished.results)
        self.assertEqual(1, finished.counts[ReconcileOutcome.changed.value])

        stale = _run("run-stale")
        self.store.begin_reconcile_run(stale)
        interrupted_at = RUN_FINISHED_AT + timedelta(minutes=1)
        self.assertEqual(
            1,
            self.store.interrupt_stale_reconcile_runs(interrupted_at=interrupted_at),
        )
        interrupted = self.store.get_reconcile_run(stale.run_id)
        self.assertIsNotNone(interrupted)
        self.assertEqual("interrupted", interrupted.outcome if interrupted else None)
        self.assertEqual(interrupted_at, interrupted.finished_at if interrupted else None)

    def test_all_five_operations_keep_exact_transaction_boundaries(self) -> None:
        database = _TracingSQLiteDatabase(self.database_path.with_name("trace.db"))
        SchemaManager(database).init()
        database.traces.clear()
        store = ReconcileStore(database)
        run = _run()
        result = _result()

        store.begin_reconcile_run(run)
        begin_trace = list(database.traces)
        database.traces.clear()

        store.append_reconcile_result(run.run_id, result)
        append_trace = list(database.traces)
        database.traces.clear()

        store.finish_reconcile_run(_summary(run, [result]))
        finish_trace = list(database.traces)
        database.traces.clear()

        loaded = store.get_reconcile_run(run.run_id)
        get_trace = list(database.traces)

        store.begin_reconcile_run(_run("run-stale-a"))
        store.begin_reconcile_run(_run("run-stale-b"))
        database.traces.clear()
        interrupted = store.interrupt_stale_reconcile_runs(interrupted_at=RUN_FINISHED_AT)
        interrupt_trace = list(database.traces)

        self.assertIsNotNone(loaded)
        self.assertEqual(2, interrupted)
        for trace in (begin_trace, append_trace, finish_trace, get_trace, interrupt_trace):
            self.assertEqual(1, len({connection_id for connection_id, _sql in trace}))

        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(begin_trace))
        begin_sql = _statements(begin_trace)
        self.assertLess(
            _statement_index(begin_sql, "BEGIN IMMEDIATE"),
            _statement_index(begin_sql, "INSERT INTO RECONCILE_RUNS"),
        )
        self.assertLess(
            _statement_index(begin_sql, "INSERT INTO RECONCILE_RUNS"),
            _statement_index(begin_sql, "COMMIT"),
        )

        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(append_trace))
        append_sql = _statements(append_trace)
        result_insert = _statement_index(append_sql, "INSERT INTO RECONCILE_RESULTS")
        counter_update = _statement_index(append_sql, "UPDATE RECONCILE_RUNS")
        self.assertLess(result_insert, counter_update)
        self.assertLess(counter_update, _statement_index(append_sql, "COMMIT"))

        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(finish_trace))
        finish_sql = _statements(finish_trace)
        finish_update = _statement_index(finish_sql, "UPDATE RECONCILE_RUNS")
        run_selects = [
            index
            for index, sql in enumerate(finish_sql)
            if sql.lstrip().upper().startswith("SELECT * FROM RECONCILE_RUNS")
        ]
        result_selects = [
            index
            for index, sql in enumerate(finish_sql)
            if sql.lstrip().upper().startswith("SELECT * FROM RECONCILE_RESULTS")
        ]
        self.assertEqual(2, len(run_selects))
        self.assertEqual(2, len(result_selects))
        self.assertLess(run_selects[0], result_selects[0])
        self.assertLess(result_selects[0], finish_update)
        self.assertLess(finish_update, run_selects[1])
        self.assertLess(run_selects[1], result_selects[1])
        self.assertLess(result_selects[1], _statement_index(finish_sql, "COMMIT"))

        self.assertEqual(["BEGIN", "COMMIT"], _control_statements(get_trace))
        get_sql = _statements(get_trace)
        self.assertEqual("BEGIN", get_sql[0].strip().upper())
        self.assertTrue(
            all(sql.lstrip().upper().startswith(("BEGIN", "SELECT", "COMMIT")) for sql in get_sql)
        )

        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(interrupt_trace))
        interrupt_sql = _statements(interrupt_trace)
        interrupt_updates = [
            index
            for index, sql in enumerate(interrupt_sql)
            if sql.lstrip().upper().startswith("UPDATE RECONCILE_RUNS")
        ]
        self.assertEqual(2, len(interrupt_updates))
        self.assertLess(interrupt_updates[-1], _statement_index(interrupt_sql, "COMMIT"))

    def test_result_insert_and_counter_update_roll_back_together(self) -> None:
        database = _TracingSQLiteDatabase(self.database_path.with_name("append-rollback.db"))
        SchemaManager(database).init()
        store = ReconcileStore(database)
        run = _run()
        store.begin_reconcile_run(run)
        with closing(database.connect()) as conn:
            conn.execute(
                """
                CREATE TRIGGER reject_reconcile_counter_update
                BEFORE UPDATE ON reconcile_runs
                WHEN NEW.total = OLD.total + 1
                BEGIN
                    SELECT RAISE(ABORT, 'injected counter failure');
                END
                """
            )
            conn.commit()
        database.traces.clear()

        with self.assertRaisesRegex(sqlite3.DatabaseError, "injected counter failure"):
            store.append_reconcile_result(run.run_id, _result())
        append_trace = list(database.traces)

        self.assertEqual(["BEGIN IMMEDIATE", "ROLLBACK"], _control_statements(append_trace))
        append_sql = _statements(append_trace)
        self.assertLess(
            _statement_index(append_sql, "INSERT INTO RECONCILE_RESULTS"),
            _statement_index(append_sql, "UPDATE RECONCILE_RUNS"),
        )
        with closing(sqlite3.connect(database.database_path)) as conn:
            result_count = conn.execute(
                "SELECT COUNT(*) FROM reconcile_results WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
            run_row = conn.execute(
                """
                SELECT outcome, total, healthy_count, changed_count, pending_count,
                       action_required_count, error_count, skipped_count
                FROM reconcile_runs
                WHERE run_id = ?
                """,
                (run.run_id,),
            ).fetchone()
        self.assertEqual(0, result_count)
        self.assertEqual(("running", 0, 0, 0, 0, 0, 0, 0), run_row)

    def test_finish_validation_rolls_back_and_leaves_run_open_byte_for_byte(self) -> None:
        database = _TracingSQLiteDatabase(self.database_path.with_name("finish-rollback.db"))
        SchemaManager(database).init()
        store = ReconcileStore(database)
        run = _run()
        result = _result()
        store.begin_reconcile_run(run)
        store.append_reconcile_result(run.run_id, result)
        before = _run_bytes(database.database_path, run.run_id)
        database.traces.clear()

        with self.assertRaisesRegex(RuntimeError, "persisted reconciliation results"):
            store.finish_reconcile_run(_summary(run, []))
        finish_trace = list(database.traces)

        self.assertEqual(["BEGIN IMMEDIATE", "ROLLBACK"], _control_statements(finish_trace))
        self.assertEqual(before, _run_bytes(database.database_path, run.run_id))
        with closing(sqlite3.connect(database.database_path)) as conn:
            outcome, finished_at = conn.execute(
                "SELECT outcome, finished_at FROM reconcile_runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            result_count = conn.execute(
                "SELECT COUNT(*) FROM reconcile_results WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
        self.assertEqual(("running", None), (outcome, finished_at))
        self.assertEqual(1, result_count)

    def test_interrupt_rolls_back_every_running_run_when_one_has_a_late_result(self) -> None:
        database = _TracingSQLiteDatabase(self.database_path.with_name("interrupt-rollback.db"))
        SchemaManager(database).init()
        store = ReconcileStore(database)
        first = _run("run-a-empty")
        late = _run("run-z-late")
        store.begin_reconcile_run(first)
        store.begin_reconcile_run(late)
        store.append_reconcile_result(late.run_id, _result())
        first_before = _run_bytes(database.database_path, first.run_id)
        late_before = _run_bytes(database.database_path, late.run_id)
        interrupted_at = RESULT_STARTED_AT + timedelta(microseconds=500_000)
        database.traces.clear()

        with self.assertRaisesRegex(ValueError, "finishes after"):
            store.interrupt_stale_reconcile_runs(interrupted_at=interrupted_at)
        interrupt_trace = list(database.traces)

        self.assertEqual(["BEGIN IMMEDIATE", "ROLLBACK"], _control_statements(interrupt_trace))
        interrupt_sql = _statements(interrupt_trace)
        self.assertEqual(
            1,
            sum(sql.lstrip().upper().startswith("UPDATE RECONCILE_RUNS") for sql in interrupt_sql),
        )
        self.assertEqual(first_before, _run_bytes(database.database_path, first.run_id))
        self.assertEqual(late_before, _run_bytes(database.database_path, late.run_id))

    def test_event_link_rejects_missing_and_wrong_bot_without_partial_results(self) -> None:
        run = _run()
        self.store.begin_reconcile_run(run)

        with self.assertRaisesRegex(ValueError, "lifecycle event"):
            self.store.append_reconcile_result(
                run.run_id,
                _result(outcome=ReconcileOutcome.changed, event_id=999),
            )

        with closing(sqlite3.connect(self.database_path)) as conn:
            cursor = conn.execute(
                """
                INSERT INTO lifecycle_events (
                    bot_id, operation_id, occurred_at, source, action, outcome
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "other",
                    "a" * 32,
                    RUN_STARTED_AT.isoformat(),
                    "cli",
                    "bot.create",
                    "success",
                ),
            )
            wrong_bot_event_id = int(cursor.lastrowid)
            conn.commit()

        with self.assertRaisesRegex(ValueError, "lifecycle event"):
            self.store.append_reconcile_result(
                run.run_id,
                _result(
                    outcome=ReconcileOutcome.changed,
                    event_id=wrong_bot_event_id,
                ),
            )

        with closing(sqlite3.connect(self.database_path)) as conn:
            result_count = conn.execute(
                "SELECT COUNT(*) FROM reconcile_results WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
            total = conn.execute(
                "SELECT total FROM reconcile_runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
        self.assertEqual(0, result_count)
        self.assertEqual(0, total)

    def test_state_facade_uses_shared_database_and_delegates_verbatim_signatures(self) -> None:
        database_path = Path("state") / "zeus.db"
        database = MagicMock(spec=SQLiteDatabase)
        database.database_path = database_path
        schema = MagicMock(spec=SchemaManager)
        idempotency = MagicMock(spec=IdempotencyStore)
        delegate = MagicMock(spec=ReconcileStore)
        run = _run()
        result = _result()
        summary = _summary(run, [result])
        finished = MagicMock(spec=PersistedReconcileRun)
        loaded = MagicMock(spec=PersistedReconcileRun)
        delegate.finish_reconcile_run.return_value = finished
        delegate.interrupt_stale_reconcile_runs.return_value = 3
        delegate.get_reconcile_run.return_value = loaded

        with (
            patch("zeus.state.SQLiteDatabase", return_value=database) as database_type,
            patch("zeus.state.SchemaManager", return_value=schema) as schema_type,
            patch("zeus.state.IdempotencyStore", return_value=idempotency) as idempotency_type,
            patch("zeus.state.ReconcileStore", return_value=delegate) as reconcile_type,
        ):
            facade = StateStore(database_path)
            facade.begin_reconcile_run(run)
            facade.append_reconcile_result(run.run_id, result)
            actual_finished = facade.finish_reconcile_run(summary)
            actual_interrupted = facade.interrupt_stale_reconcile_runs(
                interrupted_at=RUN_FINISHED_AT
            )
            actual_loaded = facade.get_reconcile_run(run.run_id)

        self.assertEqual([call(database_path)], database_type.call_args_list)
        self.assertEqual([call(database)], schema_type.call_args_list)
        self.assertEqual([call(database)], idempotency_type.call_args_list)
        self.assertEqual([call(database)], reconcile_type.call_args_list)
        database.connect.assert_not_called()
        delegate.begin_reconcile_run.assert_called_once_with(run)
        delegate.append_reconcile_result.assert_called_once_with(run.run_id, result)
        delegate.finish_reconcile_run.assert_called_once_with(summary)
        delegate.interrupt_stale_reconcile_runs.assert_called_once_with(
            interrupted_at=RUN_FINISHED_AT
        )
        delegate.get_reconcile_run.assert_called_once_with(run.run_id)
        self.assertIs(finished, actual_finished)
        self.assertEqual(3, actual_interrupted)
        self.assertIs(loaded, actual_loaded)
        for method_name in (
            "begin_reconcile_run",
            "append_reconcile_result",
            "finish_reconcile_run",
            "interrupt_stale_reconcile_runs",
            "get_reconcile_run",
        ):
            self.assertEqual(
                inspect.signature(getattr(ReconcileStore, method_name)),
                inspect.signature(getattr(StateStore, method_name)),
            )

    def test_reconcile_counter_columns_remain_a_state_compatibility_alias(self) -> None:
        self.assertIs(RECONCILE_COUNTER_COLUMNS, STATE_RECONCILE_COUNTER_COLUMNS)
        self.assertEqual(
            {
                ReconcileOutcome.healthy: "healthy_count",
                ReconcileOutcome.changed: "changed_count",
                ReconcileOutcome.pending: "pending_count",
                ReconcileOutcome.action_required: "action_required_count",
                ReconcileOutcome.error: "error_count",
                ReconcileOutcome.skipped: "skipped_count",
            },
            RECONCILE_COUNTER_COLUMNS,
        )


if __name__ == "__main__":
    unittest.main()
