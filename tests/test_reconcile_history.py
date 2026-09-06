from __future__ import annotations

import base64
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.reconcile_history import ReconcileHistoryReader
from zeus.reconcile_store import ReconcileStore
from zeus.reconciliation import (
    BotReconcileResult,
    ReconcileOutcome,
    ReconcileRunStart,
    summarize_results,
)
from zeus.schema import SCHEMA_VERSION, SchemaManager
from zeus.sqlite_db import SQLiteDatabase, StateReadinessError

START = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
INDEXES = (
    "reconcile_runs_started_id_idx",
    "reconcile_runs_outcome_started_id_idx",
    "reconcile_results_bot_finished_run_idx",
)


def _cursor(payload: object) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class ReconcileHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "zeus.db"
        self.database = SQLiteDatabase(self.path)
        SchemaManager(self.database).init()
        self.store = ReconcileStore(self.database)
        self.reader = ReconcileHistoryReader(self.path)

    def _run(
        self,
        run_id: str = "run-a",
        *,
        started_at: datetime = START,
        bots: tuple[str, ...] = ("coder",),
        outcome: str = "succeeded",
        requested_bot_id: str | None = None,
    ) -> None:
        run = ReconcileRunStart(
            run_id=run_id,
            scope="fleet" if requested_bot_id is None else "bot",
            requested_bot_id=requested_bot_id,
            source="cli",
            force=False,
            reset_restart=False,
            started_at=started_at,
        )
        self.store.begin_reconcile_run(run)
        results = []
        for bot_id in bots:
            result = BotReconcileResult(
                bot_id=bot_id,
                outcome=(
                    ReconcileOutcome.error
                    if outcome == "completed_with_errors"
                    else ReconcileOutcome.healthy
                ),
                desired_state="running",
                observed_status="running",
                pid=1234,
                action="reconcile",
                message="healthy",
                error_code=None,
                event_id=None,
                started_at=started_at + timedelta(seconds=1),
                finished_at=started_at + timedelta(seconds=2),
            )
            self.store.append_reconcile_result(run_id, result)
            results.append(result)
        if outcome in {"succeeded", "completed_with_errors"}:
            self.store.finish_reconcile_run(
                summarize_results(
                    run_id,
                    run.scope,
                    results,
                    started_at=started_at,
                    finished_at=started_at + timedelta(seconds=3),
                )
            )
        elif outcome == "interrupted":
            with closing(sqlite3.connect(self.path)) as conn:
                conn.execute(
                    "UPDATE reconcile_runs SET outcome = 'interrupted', finished_at = ? "
                    "WHERE run_id = ?",
                    ((started_at + timedelta(seconds=3)).isoformat(), run_id),
                )
                conn.commit()

    def _write(self, sql: str, parameters: tuple[object, ...] = ()) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA ignore_check_constraints=ON")
            conn.execute(sql, parameters)
            conn.commit()

    def test_reads_preserve_database_bytes_schema_and_logical_state(self) -> None:
        self._run(bots=("first", "second", "third"))
        before = self.path.read_bytes()
        version = SCHEMA_VERSION
        with patch.object(SQLiteDatabase, "connect", side_effect=AssertionError("writer opened")):
            page = self.reader.list_runs()
            detail = self.reader.get_run("run-a", limit=2)
            self.assertIsNone(self.reader.get_run("missing"))
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual("run-a", page["runs"][0]["run_id"])
        self.assertEqual([0, 1], [result["ordinal"] for result in detail["results"]])
        self.assertEqual(1, detail["next_after"])
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(
                version, conn.execute("SELECT version FROM schema_version").fetchone()[0]
            )
            self.assertEqual(
                3, conn.execute("SELECT COUNT(*) FROM reconcile_results").fetchone()[0]
            )

    def test_missing_database_does_not_create_state_and_wrong_schemas_are_not_migrated(
        self,
    ) -> None:
        missing = self.root / "missing" / "state.db"
        reader = ReconcileHistoryReader(missing)
        self.assertFalse(missing.parent.exists())
        for operation in (reader.list_runs, lambda: reader.get_run("missing")):
            with self.assertRaisesRegex(
                StateReadinessError, "^reconciliation history is unavailable$"
            ):
                operation()
            self.assertFalse(missing.parent.exists())
        for version in (SCHEMA_VERSION - 1, SCHEMA_VERSION + 1):
            self._write("UPDATE schema_version SET version = ?", (version,))
            before = self.path.read_bytes()
            with self.subTest(version=version), self.assertRaises(StateReadinessError):
                self.reader.list_runs()
            self.assertEqual(before, self.path.read_bytes())

    def test_wal_commits_are_visible_without_checkpoint(self) -> None:
        with closing(sqlite3.connect(self.path)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute(
                "INSERT INTO reconcile_runs "
                "(run_id,scope,source,force,reset_restart,started_at,outcome) "
                "VALUES ('live-wal','fleet','cli',0,0,?,'running')",
                (START.isoformat(),),
            )
            writer.commit()
            self.assertGreater(self.path.with_name("zeus.db-wal").stat().st_size, 0)
            self.assertEqual("live-wal", self.reader.list_runs()["runs"][0]["run_id"])

    def test_newest_first_tied_timestamps_and_deleted_anchor_pagination(self) -> None:
        for run_id in ("run-a", "run-c", "run-b"):
            self._run(run_id)
        self._run("newer", started_at=START + timedelta(minutes=1))
        page = self.reader.list_runs(limit=2)
        self.assertEqual(["newer", "run-c"], [run["run_id"] for run in page["runs"]])
        before = page["next_before"]
        self.assertLessEqual(len(before), 2048)
        self._write("DELETE FROM reconcile_runs WHERE run_id = 'run-c'")
        self._run("newest", started_at=START + timedelta(minutes=2))
        page = self.reader.list_runs(limit=2, before=before)
        self.assertEqual(["run-b", "run-a"], [run["run_id"] for run in page["runs"]])
        self.assertIsNone(page["next_before"])

    def test_long_unicode_run_ids_have_valid_self_contained_cursors(self) -> None:
        run_id = "\U0001f310" * 128
        self._run("older")
        self._run(run_id)
        first = self.reader.list_runs(limit=1)
        self.assertEqual(run_id, first["runs"][0]["run_id"])
        second = self.reader.list_runs(limit=1, before=first["next_before"])
        self.assertEqual("older", second["runs"][0]["run_id"])

    def test_filters_include_bot_scope_without_results_and_fleet_membership(self) -> None:
        self._run("empty-bot", bots=(), outcome="running", requested_bot_id="coder")
        self._run("failed-fleet", bots=("coder", "worker"), outcome="completed_with_errors")
        self._run("stopped-run", outcome="interrupted")
        self._run("success", bots=("worker",))
        self.assertEqual(
            {"empty-bot", "failed-fleet", "stopped-run"},
            {run["run_id"] for run in self.reader.list_runs(bot_id="coder")["runs"]},
        )
        for outcome, expected in (
            ("running", "empty-bot"),
            ("completed_with_errors", "failed-fleet"),
            ("interrupted", "stopped-run"),
            ("succeeded", "success"),
        ):
            with self.subTest(outcome=outcome):
                page = self.reader.list_runs(outcome=outcome)
                self.assertEqual([expected], [run["run_id"] for run in page["runs"]])
        self.assertEqual([], self.reader.list_runs(bot_id="coder", outcome="succeeded")["runs"])

    def test_detail_paginates_ordinals_and_handles_empty_unknown_and_past_end(self) -> None:
        self._run(bots=("zero", "one", "two", "three", "four"))
        first = self.reader.get_run("run-a", limit=2)
        self.assertEqual(["zero", "one"], [result["bot_id"] for result in first["results"]])
        second = self.reader.get_run("run-a", limit=2, after=first["next_after"])
        third = self.reader.get_run("run-a", limit=2, after=second["next_after"])
        self.assertEqual([2, 3], [result["ordinal"] for result in second["results"]])
        self.assertEqual([4], [result["ordinal"] for result in third["results"]])
        self.assertIsNone(third["next_after"])
        self.assertEqual(first["run"], third["run"])
        self.assertEqual([], self.reader.get_run("run-a", after=2**63 - 1)["results"])
        self._run("empty", bots=())
        self.assertEqual([], self.reader.get_run("empty")["results"])
        self.assertIsNone(self.reader.get_run("unknown"))

    def test_invalid_parameters_fail_before_opening_database(self) -> None:
        bad_cursors = (
            "",
            "!",
            "a" * 2049,
            "W10=",
            _cursor([]),
            _cursor({}),
            _cursor([START.isoformat(), "bad\nrun"]),
            _cursor(["not-a-date", "run-a"]),
            _cursor(["2026-09-06T12:00:00", "run-a"]),
            _cursor(["0001-01-01T00:00:00+01:00", "run-a"]),
            _cursor([START.isoformat(), "\ud800"]),
        )
        operations = [
            lambda value=value: self.reader.list_runs(before=value) for value in bad_cursors
        ]
        for value in (0, 101, True, "2", None):
            operations.extend(
                (
                    lambda value=value: self.reader.list_runs(limit=value),
                    lambda value=value: self.reader.get_run("run-a", limit=value),
                )
            )
        operations.extend(
            (
                lambda: self.reader.list_runs(outcome="unknown"),
                lambda: self.reader.list_runs(outcome=[]),
                lambda: self.reader.list_runs(bot_id=True),
                lambda: self.reader.get_run("bad\nrun"),
                lambda: self.reader.get_run(None),
                lambda: self.reader.get_run("run-a", after=-1),
                lambda: self.reader.get_run("run-a", after=True),
                lambda: self.reader.get_run("run-a", after=2**63),
            )
        )
        with patch("zeus.reconcile_history.sqlite3.connect", side_effect=AssertionError("opened")):
            for operation in operations:
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    operation()

    def test_corrupt_headers_fail_with_safe_error_and_unchanged_bytes(self) -> None:
        self._run()
        for assignment, value in (
            ("source", ""),
            ("scope", "invalid"),
            ("force", 2),
            ("started_at", "invalid"),
            ("started_at", "0001-01-01T00:00:00+01:00"),
            ("finished_at", None),
            ("total", 8),
            ("outcome", "completed_with_errors"),
            ("healthy_count", 1.5),
        ):
            with closing(sqlite3.connect(self.path)) as conn:
                original = conn.execute(f"SELECT {assignment} FROM reconcile_runs").fetchone()[0]
            self._write(f"UPDATE reconcile_runs SET {assignment} = ?", (value,))
            before = self.path.read_bytes()
            for operation in (self.reader.list_runs, lambda: self.reader.get_run("run-a")):
                with (
                    self.subTest(assignment=assignment),
                    self.assertRaisesRegex(
                        StateReadinessError, "^reconciliation history is unavailable$"
                    ),
                ):
                    operation()
            self.assertEqual(before, self.path.read_bytes())
            self._write(f"UPDATE reconcile_runs SET {assignment} = ?", (original,))

    def test_selected_result_corruption_and_missing_event_are_rejected(self) -> None:
        self._run()
        for assignment, value in (
            ("ordinal", 4),
            ("pid", 1.5),
            ("event_id", 999),
            ("started_at", (START - timedelta(seconds=1)).isoformat()),
            ("finished_at", (START + timedelta(minutes=1)).isoformat()),
            ("outcome", "unknown"),
            ("message", "x" * 2049),
        ):
            with closing(sqlite3.connect(self.path)) as conn:
                original = conn.execute(f"SELECT {assignment} FROM reconcile_results").fetchone()[0]
            self._write(f"UPDATE reconcile_results SET {assignment} = ?", (value,))
            with self.subTest(assignment=assignment), self.assertRaises(StateReadinessError):
                self.reader.get_run("run-a")
            self._write(f"UPDATE reconcile_results SET {assignment} = ?", (original,))

    def test_paged_reader_does_not_claim_validation_of_unselected_history(self) -> None:
        self._run(bots=("zero", "one", "two"))
        self._write("UPDATE reconcile_results SET pid = 1.5 WHERE ordinal = 2")
        page = self.reader.get_run("run-a", limit=1)
        self.assertEqual("zero", page["results"][0]["bot_id"])
        with self.assertRaises(StateReadinessError):
            self.reader.get_run("run-a", after=1)
        with self.assertRaises(ValueError):
            self.store.get_reconcile_run("run-a")

    def test_selected_event_link_must_belong_to_result_bot(self) -> None:
        self._run()
        with closing(sqlite3.connect(self.path)) as conn:
            event_ids = []
            for bot_id in ("coder", "other"):
                cursor = conn.execute(
                    "INSERT INTO lifecycle_events "
                    "(bot_id, operation_id, occurred_at, source, action, outcome) "
                    "VALUES (?, 'operation', ?, 'cli', 'reconcile', 'succeeded')",
                    (bot_id, START.isoformat()),
                )
                event_ids.append(cursor.lastrowid)
            conn.commit()
        self._write("UPDATE reconcile_results SET event_id = ?", (event_ids[0],))
        self.assertEqual(event_ids[0], self.reader.get_run("run-a")["results"][0]["event_id"])
        self._write("UPDATE reconcile_results SET event_id = ?", (event_ids[1],))
        with self.assertRaises(StateReadinessError):
            self.reader.get_run("run-a")

    def test_queries_are_bounded_and_use_ordered_indexes(self) -> None:
        self._run(bots=tuple(f"bot-{index}" for index in range(40)))
        traces = []
        connect = sqlite3.connect

        def traced_connect(*args, **kwargs):
            conn = connect(*args, **kwargs)
            conn.set_trace_callback(traces.append)
            return conn

        with patch("zeus.reconcile_history.sqlite3.connect", side_effect=traced_connect):
            self.reader.list_runs(limit=2)
            self.reader.get_run("run-a", limit=2)
        normalized = [" ".join(sql.upper().split()) for sql in traces]
        self.assertTrue(
            all(
                sql.startswith(("PRAGMA QUERY_ONLY", "BEGIN", "SELECT", "ROLLBACK"))
                for sql in normalized
            )
        )
        result_queries = [sql for sql in normalized if "FROM RECONCILE_RESULTS AS RESULTS" in sql]
        self.assertEqual(1, len(result_queries))
        self.assertTrue(result_queries[0].endswith("LIMIT 3"))
        self.assertFalse(any("SELECT BOT_ID FROM LIFECYCLE_EVENTS" in sql for sql in normalized))
        with closing(sqlite3.connect(self.path)) as conn:
            for predicate, index in (("1", INDEXES[0]), ("outcome = 'running'", INDEXES[1])):
                plan = conn.execute(
                    "EXPLAIN QUERY PLAN SELECT * FROM reconcile_runs WHERE "
                    + predicate
                    + " ORDER BY started_at DESC, run_id DESC LIMIT 3"
                ).fetchall()
                self.assertTrue(any(index in row[3] for row in plan), plan)
                self.assertFalse(any("TEMP B-TREE" in row[3] for row in plan), plan)
            plan = conn.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM reconcile_runs "
                "WHERE (started_at, run_id) < (?, ?) "
                "ORDER BY started_at DESC, run_id DESC LIMIT 3",
                (START.isoformat(), "run-a"),
            ).fetchall()
            self.assertTrue(any("SEARCH" in row[3] and INDEXES[0] in row[3] for row in plan), plan)
            self.assertFalse(any("TEMP B-TREE" in row[3] for row in plan), plan)

    def test_schema_v6_migration_adds_indexes_without_changing_history(self) -> None:
        self._run()
        with closing(sqlite3.connect(self.path)) as conn:
            before = conn.execute("SELECT * FROM reconcile_runs").fetchall()
            results = conn.execute("SELECT * FROM reconcile_results").fetchall()
            for index in INDEXES:
                conn.execute(f"DROP INDEX {index}")
            conn.execute("DROP TABLE message_receipts")
            conn.execute("UPDATE schema_version SET version = 6")
            conn.commit()
        with self.assertRaises(StateReadinessError):
            self.reader.list_runs()
        SchemaManager(self.database).init()
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(before, conn.execute("SELECT * FROM reconcile_runs").fetchall())
            self.assertEqual(results, conn.execute("SELECT * FROM reconcile_results").fetchall())
            self.assertEqual(8, conn.execute("SELECT version FROM schema_version").fetchone()[0])
            indexes = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
            }
            self.assertTrue(set(INDEXES).issubset(indexes))
        self.assertEqual("run-a", self.reader.list_runs()["runs"][0]["run_id"])

    def test_failed_index_migration_rolls_back_schema_version_and_partial_index(self) -> None:
        self._run()
        with closing(sqlite3.connect(self.path)) as conn:
            before = conn.execute("SELECT * FROM reconcile_runs").fetchall()
            for index in INDEXES:
                conn.execute(f"DROP INDEX {index}")
            conn.execute("DROP TABLE message_receipts")
            conn.execute("UPDATE schema_version SET version = 6")
            conn.execute(f"CREATE TABLE {INDEXES[1]} (marker TEXT)")
            conn.commit()
        with self.assertRaises(sqlite3.OperationalError):
            SchemaManager(self.database).init()
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(before, conn.execute("SELECT * FROM reconcile_runs").fetchall())
            self.assertEqual(6, conn.execute("SELECT version FROM schema_version").fetchone()[0])
            indexes = {
                row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
            }
            self.assertTrue(set(INDEXES).isdisjoint(indexes))


if __name__ == "__main__":
    unittest.main()
