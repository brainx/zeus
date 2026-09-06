from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.fleet_overview import _OVERVIEW_SQL, FleetOverviewReader
from zeus.models import BotRecord, BotStatus, DesiredState, RestartPolicy
from zeus.reconciliation import BotReconcileResult, ReconcileOutcome, ReconcileRunStart
from zeus.sqlite_db import StateReadinessError
from zeus.state import StateStore


class FleetOverviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = StateStore(self.root / "zeus.db")
        self.store.init()
        self.reader = FleetOverviewReader(self.store.database_path)
        self.now = datetime(2026, 9, 6, 12, tzinfo=UTC)
        self.run_count = 0

    def _bot(self, bot_id: str = "coder", **changes) -> BotRecord:
        record = replace(
            BotRecord(
                bot_id=bot_id,
                template_id="coding-bot",
                display_name=bot_id,
                profile_path=str(self.root / "profiles" / bot_id),
                desired_state=DesiredState.running,
                status=BotStatus.running,
                pid=4321,
                restart_policy=RestartPolicy.on_failure,
                restart_attempts=2,
                restart_max_attempts=5,
                created_at=self.now - timedelta(hours=1),
                updated_at=self.now - timedelta(minutes=1),
            ),
            **changes,
        )
        self.store.upsert_bot(record)
        return record

    def _observation(
        self,
        bot_id: str = "coder",
        *,
        age: float = 5,
        started_at: datetime | None = None,
        outcome: ReconcileOutcome = ReconcileOutcome.healthy,
        reason: str = "running",
    ) -> str:
        self.run_count += 1
        run_id = f"run-{self.run_count:04}"
        finished_at = self.now - timedelta(seconds=age)
        started_at = started_at or finished_at - timedelta(seconds=1)
        self.store.begin_reconcile_run(
            ReconcileRunStart(run_id, "bot", bot_id, "reconcile", False, False, started_at)
        )
        self.store.append_reconcile_result(
            run_id,
            BotReconcileResult(
                bot_id=bot_id,
                outcome=outcome,
                desired_state="running",
                observed_status="running",
                pid=4321,
                action="none",
                message=reason,
                error_code=None,
                event_id=None,
                started_at=started_at,
                finished_at=finished_at,
            ),
        )
        return run_id

    def _overview(self, **kwargs):
        return self.reader.overview(now=self.now, **kwargs)

    def test_fresh_observation_is_explicitly_cached_and_keeps_stored_retry_fields(self) -> None:
        self._bot()
        run_id = self._observation()
        payload = self._overview()

        self.assertFalse(payload["live_probe"])
        self.assertEqual("persisted_reconciliation", payload["freshness_source"])
        item = payload["items"][0]
        self.assertEqual("running", item["stored_status"])
        self.assertEqual("running", item["desired_state"])
        self.assertEqual(2, item["restart_attempts"])
        self.assertEqual(5, item["restart_max_attempts"])
        self.assertEqual(3, item["restart_budget_remaining"])
        self.assertEqual("fresh", item["freshness"])
        self.assertFalse(item["needs_attention"])
        self.assertEqual([], item["attention_reasons"])
        self.assertEqual(run_id, item["observation"]["run_id"])
        self.assertEqual(5.0, item["observation"]["age_seconds"])
        self.assertEqual(
            (self.now - timedelta(seconds=5)).isoformat(), item["observation"]["observed_at"]
        )
        self.assertNotIn("profile_path", item)
        self.assertNotIn("live", item)

    def test_missing_stale_and_clock_rollback_are_attention_states(self) -> None:
        for bot_id in ("missing", "stale", "future", "boundary"):
            self._bot(bot_id)
        self._observation("stale", age=121)
        self._observation("future", age=-1)
        self._observation("boundary", age=120)
        items = {item["bot_id"]: item for item in self._overview()["items"]}

        self.assertEqual("unknown", items["missing"]["freshness"])
        self.assertIsNone(items["missing"]["observation"])
        self.assertEqual(["no_reconciliation_observation"], items["missing"]["attention_reasons"])
        self.assertEqual("stale", items["stale"]["freshness"])
        self.assertEqual(["stale_observation"], items["stale"]["attention_reasons"])
        self.assertEqual("clock_skew", items["future"]["freshness"])
        self.assertEqual(0.0, items["future"]["observation"]["age_seconds"])
        self.assertEqual(["observation_clock_skew"], items["future"]["attention_reasons"])
        self.assertFalse(items["boundary"]["needs_attention"])

    def test_pending_failed_mismatched_and_exhausted_states_identify_reasons(self) -> None:
        self._bot(
            status=BotStatus.failed,
            pid=None,
            restart_attempts=5,
            pending_operation_id="a" * 32,
            pending_action="start",
            pending_since=self.now,
        )
        self._observation(outcome=ReconcileOutcome.action_required, reason="manual action needed")
        item = self._overview()["items"][0]

        self.assertEqual(
            [
                "reconcile_action_required",
                "pending_intent",
                "desired_state_mismatch",
                "stored_failed",
                "restart_budget_exhausted",
            ],
            item["attention_reasons"],
        )
        self.assertEqual(0, item["restart_budget_remaining"])

    def test_final_scheduled_attempt_is_not_counted_as_completed(self) -> None:
        deadline = self.now + timedelta(seconds=10)
        self._bot(status=BotStatus.failed, pid=None, restart_attempts=5, next_restart_at=deadline)
        self._observation(outcome=ReconcileOutcome.pending)
        item = self._overview()["items"][0]

        self.assertEqual(1, item["restart_budget_remaining"])
        self.assertEqual(deadline.isoformat(), item["next_restart_at"])
        self.assertNotIn("restart_budget_exhausted", item["attention_reasons"])

    def test_latest_observation_uses_finished_time_and_deterministic_tie_breaker(self) -> None:
        self._bot()
        self._observation(age=10, outcome=ReconcileOutcome.error)
        self._observation(age=1)
        newest = self._observation(age=1, reason="last tied observation")
        self._observation(age=20)
        item = self._overview()["items"][0]

        self.assertEqual(newest, item["observation"]["run_id"])
        self.assertEqual("last tied observation", item["observation"]["reason"])
        self.assertFalse(item["needs_attention"])

    def test_recreated_bot_excludes_previous_incarnation_and_spanning_observations(self) -> None:
        self._bot()
        self._observation(age=20)
        self._observation(age=1, started_at=self.now - timedelta(seconds=20))
        self.store.delete_bot("coder")
        self._bot(created_at=self.now - timedelta(seconds=10))
        item = self._overview()["items"][0]
        self.assertIsNone(item["observation"])
        self.assertEqual("unknown", item["freshness"])

        current = self._observation(age=2)
        self.assertEqual(current, self._overview()["items"][0]["observation"]["run_id"])

    def test_attention_filter_applies_before_keyset_page_limit(self) -> None:
        for bot_id in ("aa", "bb", "cc", "dd", "ee", "ff"):
            self._bot(bot_id)
            if bot_id not in {"bb", "dd", "ff"}:
                self._observation(bot_id)
        first = self._overview(limit=2, attention_only=True)
        self.assertEqual(["bb", "dd"], [item["bot_id"] for item in first["items"]])
        self.assertEqual("dd", first["next_after"])
        second = self._overview(limit=2, after=first["next_after"], attention_only=True)
        self.assertEqual(["ff"], [item["bot_id"] for item in second["items"]])
        self.assertIsNone(second["next_after"])
        self.store.delete_bot("dd")
        self.assertEqual(second, self._overview(limit=2, after="dd", attention_only=True))

    def test_unfiltered_keyset_is_bounded_and_empty_pages_have_no_cursor(self) -> None:
        for index in range(102):
            self._bot(f"bot-{index:03}")
        first = self._overview(limit=100)
        self.assertEqual(100, len(first["items"]))
        self.assertEqual("bot-099", first["next_after"])
        second = self._overview(limit=100, after=first["next_after"])
        self.assertEqual(2, len(second["items"]))
        self.assertIsNone(second["next_after"])
        self.assertEqual([], self._overview(after="zz")["items"])

    def test_public_text_is_bounded_redacted_and_omits_private_bot_data(self) -> None:
        self._bot(display_name="API_KEY=example-value\n" + "x" * 1000)
        run_id = self._observation()
        with closing(sqlite3.connect(self.store.database_path)) as conn:
            conn.execute(
                "UPDATE reconcile_results SET message = ? WHERE run_id = ?",
                ("password=example-password\n" + "x" * 1900, run_id),
            )
            conn.commit()
        payload = self._overview()
        rendered = json.dumps(payload)

        self.assertNotIn("example-value", rendered)
        self.assertNotIn("example-password", rendered)
        self.assertNotIn(str(self.root), rendered)
        self.assertLessEqual(len(payload["items"][0]["display_name"]), 256)
        self.assertLessEqual(len(payload["items"][0]["observation"]["reason"]), 2048)

    def test_read_only_snapshot_does_not_change_database_or_use_per_bot_queries(self) -> None:
        for bot_id in ("aa", "bb", "cc"):
            self._bot(bot_id)
            self._observation(bot_id)
        with closing(sqlite3.connect(self.store.database_path)) as conn:
            before = list(conn.iterdump())
        before_hash = hashlib.sha256(self.store.database_path.read_bytes()).digest()
        original_connect = sqlite3.connect
        statements: list[str] = []

        def connect(database, **kwargs):
            self.assertTrue(database.endswith("?mode=ro"))
            self.assertTrue(kwargs["uri"])
            conn = original_connect(database, **kwargs)
            conn.set_trace_callback(statements.append)
            return conn

        with patch("zeus.fleet_overview.sqlite3.connect", side_effect=connect) as connector:
            self._overview()
        self.assertEqual(1, connector.call_count)
        self.assertEqual(
            1, sum(statement.lstrip().startswith("WITH overview") for statement in statements)
        )
        self.assertFalse(
            any(
                statement.lstrip()
                .upper()
                .startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER"))
                for statement in statements
            )
        )
        with closing(original_connect(self.store.database_path)) as conn:
            self.assertEqual(before, list(conn.iterdump()))
        self.assertEqual(
            before_hash, hashlib.sha256(self.store.database_path.read_bytes()).digest()
        )

    def test_indexed_latest_observation_lookup_has_no_history_sort(self) -> None:
        with closing(sqlite3.connect(self.store.database_path)) as conn:
            plan = conn.execute(
                "EXPLAIN QUERY PLAN " + _OVERVIEW_SQL,
                {
                    "after": "",
                    "now": self.now.isoformat(),
                    "cutoff": (self.now - timedelta(seconds=120)).isoformat(),
                    "attention_only": 0,
                    "row_limit": 51,
                },
            ).fetchall()
        details = "\n".join(str(row[3]) for row in plan)
        self.assertIn("reconcile_results_bot_finished_run_idx", details)
        self.assertNotIn("SCAN candidate", details)
        self.assertNotIn("USE TEMP B-TREE", details)

    def test_read_only_reader_sees_committed_wal_state_without_checkpointing(self) -> None:
        self._bot()
        self._observation()
        before_hash = hashlib.sha256(self.store.database_path.read_bytes()).digest()
        with closing(sqlite3.connect(self.store.database_path)) as writer:
            writer.execute("UPDATE bots SET status = 'unknown' WHERE bot_id = 'coder'")
            writer.commit()
            self.assertTrue(Path(f"{self.store.database_path}-wal").exists())
            item = self._overview()["items"][0]
            self.assertEqual("unknown", item["stored_status"])
            self.assertIn("stored_unknown", item["attention_reasons"])
            self.assertEqual(
                before_hash, hashlib.sha256(self.store.database_path.read_bytes()).digest()
            )

    def test_corrupt_timestamp_overflow_has_a_safe_error(self) -> None:
        self._bot()
        self._observation()
        with closing(sqlite3.connect(self.store.database_path)) as conn:
            conn.execute(
                "UPDATE bots SET next_restart_at = ? WHERE bot_id = 'coder'",
                ("0001-01-01T00:00:00+01:00",),
            )
            conn.commit()
        with self.assertRaisesRegex(StateReadinessError, "^fleet overview is unavailable$"):
            self._overview()

    def test_invalid_arguments_are_rejected_before_opening_database(self) -> None:
        invalid = [
            {"limit": 0},
            {"limit": 101},
            {"limit": True},
            {"limit": 1.5},
            {"after": "../invalid"},
            {"after": ""},
            {"attention_only": 1},
            {"stale_after_seconds": -1},
            {"stale_after_seconds": 86401},
            {"stale_after_seconds": float("nan")},
            {"stale_after_seconds": float("inf")},
            {"stale_after_seconds": True},
            {"now": datetime(2026, 1, 1)},
        ]
        for values in invalid:
            with (
                self.subTest(values=values),
                patch("zeus.fleet_overview.sqlite3.connect") as connector,
            ):
                with self.assertRaises(ValueError):
                    self.reader.overview(**values)
                connector.assert_not_called()

    def test_missing_old_and_corrupt_databases_have_safe_errors_without_initialization(
        self,
    ) -> None:
        missing = self.root / "missing" / "zeus.db"
        with self.assertRaisesRegex(StateReadinessError, "^fleet overview is unavailable$"):
            FleetOverviewReader(missing).overview()
        self.assertFalse(missing.parent.exists())
        for name in ("old", "corrupt"):
            path = self.root / f"{name}.db"
            if name == "old":
                with closing(sqlite3.connect(path)) as conn:
                    conn.execute("CREATE TABLE schema_version (version INTEGER)")
                    conn.execute("INSERT INTO schema_version VALUES (1)")
                    conn.commit()
            else:
                path.write_bytes(b"invalid database")
            before = path.read_bytes()
            with self.assertRaisesRegex(StateReadinessError, "^fleet overview is unavailable$"):
                FleetOverviewReader(path).overview()
            self.assertEqual(before, path.read_bytes())
