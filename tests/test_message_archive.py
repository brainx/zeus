from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, redirect_stdout
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from tests import test_bot_messaging as fixtures
from zeus.bot_messaging import MessagingError
from zeus.cli import main
from zeus.message_store import MessageStore, MessageStoreError
from zeus.schema import SchemaManager, _assert_schema_current
from zeus.sqlite_db import SQLiteDatabase
from zeus.state import StateStore


class MessageArchiveTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "zeus.db"
        StateStore(self.path).init()
        self.store = MessageStore(self.path)
        self.old = datetime(2026, 1, 1, tzinfo=UTC)
        self.now = self.old + timedelta(days=31)
        self.sequence = 0

    def args(self, **changes):
        args = dict(
            bot_id="coder",
            incarnation=self.old - timedelta(days=1),
            target_fingerprint="a" * 64,
            endpoint="http://127.0.0.1:8765/health",
            credential_fingerprint="b" * 64,
            input_fingerprint="c" * 64,
            request_key_fingerprint=None,
            now=self.old,
            retry_before=self.old + timedelta(minutes=10),
        )
        args.update(changes)
        return args

    def receipt(self, state="rejected", status=None, released=False, error=None):
        self.sequence += 1
        receipt, _ = self.store.prepare(**self.args(bot_id=f"bot-{self.sequence}"))
        if state != "prepared":
            receipt = self.store.finish_attempt(
                receipt.message_id,
                expected_version=1,
                dispatch_state=state,
                run_id=f"run-{self.sequence}" if state == "accepted" else None,
                run_status=status,
                error_code=error,
                now=self.old,
            )
        if released:
            receipt = self.store.release(
                receipt.message_id, expected_version=receipt.version, now=self.old
            )
        return receipt

    def dump(self):
        with closing(sqlite3.connect(self.path)) as conn:
            return list(conn.iterdump())

    def test_eligibility_matrix_and_preview_identity(self):
        eligible = [self.receipt(error="invalid_request")]
        eligible += [
            self.receipt("accepted", status)
            for status in ("completed", "failed", "cancelled", "interrupted")
        ]
        for state in ("prepared", "unknown"):
            self.receipt(state)
        for status in ("queued", "running", "waiting_for_approval", "stopping"):
            self.receipt("accepted", status)
            self.receipt("accepted", status, released=True)
        released = self.receipt("accepted", "running", released=True)
        eligible.append(
            self.store.update_run(
                released.message_id,
                expected_version=released.version,
                run_status="completed",
                now=self.old,
            )
        )
        before = self.dump()
        preview = self.store.archive(now=self.now)
        self.assertEqual(before, self.dump())
        self.assertFalse(preview["applied"])
        self.assertEqual(sorted(r.message_id for r in eligible), preview["message_ids"])
        applied = self.store.archive(now=self.now, apply=True)
        self.assertEqual(preview["message_ids"], applied["message_ids"])
        self.assertEqual(len(eligible), self.store.capacity()["archived"])
        for original in eligible:
            current = self.store.get(original.message_id)
            self.assertEqual(self.now, current.archived_at)
            self.assertEqual(original.version + 1, current.version)
            self.assertEqual(original.updated_at, current.updated_at)
            self.assertEqual(original.upstream_key, current.upstream_key)
            self.assertEqual(original.released_at, current.released_at)
        self.assertEqual(0, self.store.archive(now=self.now, apply=True)["count"])

    def test_cutoff_timezone_limits_and_preview_not_reservation(self):
        receipt = self.receipt("accepted", "completed")
        self.assertEqual(0, self.store.archive(before=self.old, now=self.now)["count"])
        cutoff = (self.old + timedelta(microseconds=1)).astimezone(timezone(timedelta(hours=2)))
        self.assertEqual(1, self.store.archive(before=cutoff, now=self.now)["count"])
        for limit in (0, 501, True, 1.0):
            with self.assertRaises(ValueError):
                self.store.archive(limit=limit, now=self.now)
        for cutoff in (self.now + timedelta(seconds=1), self.now.replace(tzinfo=None)):
            with self.assertRaises(ValueError):
                self.store.archive(before=cutoff, now=self.now)
        self.store.update_run(
            receipt.message_id,
            expected_version=receipt.version,
            run_status="completed",
            now=self.now,
        )
        self.assertEqual(0, self.store.archive(now=self.now, apply=True)["count"])
        self.assertIsNone(self.store.get(receipt.message_id).archived_at)

    def test_archive_invalidates_writers_and_terminal_observation_keeps_identity(self):
        receipt = self.receipt("accepted", "completed")
        self.store.archive(apply=True, now=self.now)
        for method, kwargs in (
            (self.store.update_run, {"run_status": "completed"}),
            (self.store.record_cancel_intent, {}),
            (self.store.release, {}),
        ):
            with self.assertRaisesRegex(MessageStoreError, "receipt_changed"):
                method(receipt.message_id, expected_version=receipt.version, now=self.now, **kwargs)
        current = self.store.get(receipt.message_id)
        with self.assertRaisesRegex(MessageStoreError, "clock_rollback"):
            self.store.update_run(
                current.message_id,
                expected_version=current.version,
                run_status="completed",
                now=self.now - timedelta(seconds=1),
            )
        later = self.store.update_run(
            current.message_id,
            expected_version=current.version,
            run_status="completed",
            now=self.now + timedelta(days=1),
        )
        self.assertEqual(current.archived_at, later.archived_at)
        self.assertEqual(current.run_id, later.run_id)
        with self.assertRaisesRegex(MessageStoreError, "invalid_transition"):
            self.store.update_run(
                later.message_id,
                expected_version=later.version,
                run_status="running",
                now=self.now + timedelta(days=2),
            )

    def test_replay_precedes_capacity_and_target_blocker_and_rejects_changes(self):
        original, _ = self.store.prepare(**self.args(request_key_fingerprint="d" * 64))
        self.store.finish_attempt(
            original.message_id, expected_version=1, dispatch_state="rejected", now=self.old
        )
        self.store.archive(apply=True, now=self.now)
        current = self.store.get(original.message_id)
        with patch("zeus.message_store.MAX_MESSAGE_RECEIPTS", 1):
            self.store.prepare(
                **self.args(now=self.now, retry_before=self.now + timedelta(minutes=10))
            )
            replay, created = self.store.prepare(
                **self.args(
                    request_key_fingerprint="d" * 64,
                    now=self.now,
                    retry_before=self.now + timedelta(minutes=10),
                )
            )
            self.assertFalse(created)
            self.assertEqual(current, replay)
            for changes in ({"input_fingerprint": "e" * 64}, {"bot_id": "different"}):
                with self.assertRaisesRegex(MessageStoreError, "request_conflict"):
                    self.store.prepare(**self.args(request_key_fingerprint="d" * 64, **changes))
            with self.assertRaisesRegex(MessageStoreError, "capacity_exceeded"):
                self.store.prepare(**self.args(bot_id="another"))
        with self.assertRaisesRegex(MessageStoreError, "clock_rollback"):
            self.store.prepare(**self.args(request_key_fingerprint="d" * 64))

    def test_overlapping_archivers_select_disjoint_batches(self):
        expected = {self.receipt().message_id for _ in range(8)}
        barrier = threading.Barrier(2)

        def archive(_):
            barrier.wait(timeout=3)
            return MessageStore(self.path).archive(limit=4, apply=True, now=self.now)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(archive, range(2)))
        self.assertEqual(expected, set(results[0]["message_ids"]) | set(results[1]["message_ids"]))
        self.assertFalse(set(results[0]["message_ids"]) & set(results[1]["message_ids"]))

    def test_corrupt_selected_row_and_failed_transaction_roll_back_whole_batch(self):
        self.receipt()
        corrupt = self.receipt()
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute(
                "UPDATE message_receipts SET target_bot_id = '!!' WHERE message_id = ?",
                (corrupt.message_id,),
            )
            conn.commit()
        before = self.dump()
        with self.assertRaisesRegex(MessageStoreError, "invalid_receipt"):
            self.store.archive(now=self.now, apply=True)
        self.assertEqual(before, self.dump())
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("UPDATE message_receipts SET target_bot_id = 'fixed'")
            conn.execute(
                "CREATE TRIGGER archive_full BEFORE UPDATE OF archived_at ON message_receipts "
                "WHEN NEW.message_id = (SELECT max(message_id) FROM message_receipts) "
                "BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END"
            )
            conn.commit()
        before = self.dump()
        with self.assertRaisesRegex(MessageStoreError, "state_unavailable"):
            self.store.archive(now=self.now, apply=True)
        self.assertEqual(before, self.dump())

    def test_full_durability_and_interrupted_transaction(self):
        self.receipt()
        original = self.dump()
        with self.assertRaises(KeyboardInterrupt), self.store._write() as conn:
            self.assertEqual(2, conn.execute("PRAGMA synchronous").fetchone()[0])
            conn.execute(
                "UPDATE message_receipts SET archived_at = ?, version = version + 1",
                (self.now.isoformat(),),
            )
            raise KeyboardInterrupt()
        self.assertEqual(original, self.dump())
        with self.store._read() as conn:
            self.assertIn(
                "message_receipts_unarchived_idx",
                str(
                    conn.execute(
                        "EXPLAIN QUERY PLAN SELECT count(*) FROM message_receipts "
                        "WHERE archived_at IS NULL"
                    ).fetchall()[0][3]
                ),
            )

    def test_cli_has_no_workflow_and_missing_or_old_state_is_not_initialized(self):
        self.receipt()

        def cli(*args):
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"ZEUS_STATE_DIR": str(self.root)}, clear=True),
                redirect_stdout(output),
            ):
                result = main(["message", "archive", "--json", *args])
            return result, json.loads(output.getvalue())

        before = self.dump()
        forbidden = AssertionError("archive crossed local storage boundary")
        with (
            patch("zeus.messaging_cli.BotMessaging", side_effect=forbidden),
            patch("zeus.messaging_cli.Supervisor", side_effect=forbidden),
            patch("zeus.messaging_cli.StateStore", side_effect=forbidden),
            patch("subprocess.Popen", side_effect=forbidden),
            patch("subprocess.run", side_effect=forbidden),
            patch("os.kill", side_effect=forbidden),
            patch("os.killpg", side_effect=forbidden),
            patch("zeus.hermes_runs_client.request_json", side_effect=forbidden),
            patch("zeus.gateway_http.request_json", side_effect=forbidden),
            patch("zeus.gateway_http.socket.socket", side_effect=forbidden),
        ):
            code, result = cli("--before", self.now.isoformat())
            self.assertEqual(0, code)
            self.assertEqual(1, result["count"])
            self.assertEqual(before, self.dump())
            code, result = cli("--before", self.now.isoformat(), "--apply")
            self.assertEqual(0, code)
            self.assertTrue(result["applied"])
        for cutoff in ("not-a-date", "2026-01-01", "9999-01-01T00:00:00+00:00"):
            self.assertEqual(1, cli("--before", cutoff)[0])
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("UPDATE schema_version SET version = 9")
            conn.commit()
        before = self.dump()
        self.assertEqual(1, cli("--apply")[0])
        self.assertEqual(before, self.dump())
        self.path.unlink()
        self.assertEqual(1, cli()[0])
        self.assertFalse(self.path.exists())

    def test_storage_drill_25001_retained_and_11001_actual_admissions(self):
        # Test-only persistent connection avoids 22000 fsyncs. Other tests verify FULL.
        # All 11001 admissions call prepare and finish_attempt; 14000 older rows are seeded.
        with closing(sqlite3.connect(self.path)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA synchronous=OFF")

            @contextmanager
            def fast_write():
                with conn:
                    conn.execute("BEGIN IMMEDIATE")
                    _assert_schema_current(conn)
                    yield conn

            with patch.object(self.store, "_write", fast_write):
                first = self.receipt()
                self.store.archive(now=self.now, apply=True)
                columns = [r[1] for r in conn.execute("PRAGMA table_info(message_receipts)")]
                row = dict(conn.execute("SELECT * FROM message_receipts").fetchone())
                values = []
                for index in range(14000):
                    seeded = dict(
                        row, message_id=f"{index:032x}", upstream_key=f"{index + 14000:032x}"
                    )
                    values.append(tuple(seeded[c] for c in columns))
                conn.executemany(
                    "INSERT INTO message_receipts VALUES (" + ",".join("?" for _ in columns) + ")",
                    values,
                )
                conn.commit()
                admitted = 1
                for index in range(11000):
                    receipt, created = self.store.prepare(**self.args())
                    self.assertTrue(created)
                    self.store.finish_attempt(
                        receipt.message_id,
                        expected_version=1,
                        dispatch_state="rejected",
                        now=self.old,
                    )
                    admitted += 1
                    if index % 500 == 499:
                        self.assertEqual(
                            500, self.store.archive(limit=500, now=self.now, apply=True)["count"]
                        )
                self.assertEqual(11001, admitted)
                capacity = self.store.capacity()
                self.assertEqual(25001, capacity["total"])
                self.assertEqual(25001, capacity["archived"])
                self.assertEqual(0, capacity["used"])
                self.assertEqual(first.message_id, self.store.get(first.message_id).message_id)
                self.assertEqual(100, len(self.store.list(limit=100)["items"]))


class ArchiveWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.BotMessagingTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_fake_submit_counter_archived_retry_and_replay_do_not_resubmit(self):
        fixture = self.fixture
        workflow = fixture.messaging
        receipt = workflow.send("coder", "operator message", request_key="original")
        fixture.remote_status.return_value = {"run_id": fixture.run_id, "status": "completed"}
        workflow.status(receipt["message_id"])
        fixture.now += timedelta(days=31)
        workflow.store.archive(now=fixture.now, apply=True)
        self.assertEqual(1, fixture.submit.call_count)
        replay = workflow.send("coder", "operator message", request_key="original")
        self.assertIsNotNone(replay["archived_at"])
        self.assertEqual(replay, workflow.retry(receipt["message_id"], "operator message"))
        self.assertEqual(1, fixture.submit.call_count)

    def test_archived_workflow_clock_rollback_precedes_target_and_http_work(self):
        fixture = self.fixture
        workflow = fixture.messaging
        receipt = workflow.send("coder", "operator message")
        fixture.remote_status.return_value = {"run_id": fixture.run_id, "status": "completed"}
        workflow.status(receipt["message_id"])
        fixture.now += timedelta(days=31)
        archived_at = fixture.now
        workflow.store.archive(now=archived_at, apply=True)
        stored = workflow.store.get(receipt["message_id"])
        fixture.now -= timedelta(seconds=1)
        self.assertGreater(fixture.now, stored.updated_at)
        for mock in (fixture.submit, fixture.remote_status, fixture.stop, fixture.health):
            mock.reset_mock()
        with patch.object(workflow, "_receipt_target", side_effect=AssertionError("target read")):
            for action in (
                lambda: workflow.retry(receipt["message_id"], "operator message"),
                lambda: workflow.status(receipt["message_id"]),
                lambda: workflow.cancel(receipt["message_id"]),
            ):
                with self.assertRaisesRegex(MessagingError, "clock_rollback"):
                    action()
            for now in (archived_at, archived_at + timedelta(seconds=1)):
                fixture.now = now
                replay = workflow.retry(receipt["message_id"], "operator message")
                self.assertEqual(receipt["message_id"], replay["message_id"])
                self.assertEqual(archived_at.isoformat(), replay["archived_at"])
                self.assertEqual("completed", replay["run_status"])
        for mock in (fixture.submit, fixture.remote_status, fixture.stop, fixture.health):
            mock.assert_not_called()

    def test_status_and_cancel_racing_archive_fail_cas(self):
        fixture = self.fixture
        workflow = fixture.messaging
        receipt = workflow.send("coder", "operator message")
        fixture.remote_status.return_value = {"run_id": fixture.run_id, "status": "completed"}
        workflow.status(receipt["message_id"])
        fixture.now += timedelta(days=31)

        def response(*args, **kwargs):
            workflow.store.archive(now=fixture.now, apply=True)
            return {"run_id": fixture.run_id, "status": "completed"}

        fixture.remote_status.side_effect = response
        with self.assertRaisesRegex(MessageStoreError, "receipt_changed"):
            workflow.status(receipt["message_id"])
        self.assertIsNotNone(workflow.store.get(receipt["message_id"]).archived_at)
        # A cancel that captured the old version before archival cannot dispatch.
        fixture.remote_status.side_effect = None
        second = workflow.send("coder", "next message")
        workflow.status(second["message_id"])
        fixture.now += timedelta(days=31)
        get_receipt = workflow._receipt

        def capture_then_archive(message_id):
            captured = get_receipt(message_id)
            workflow.store.archive(now=fixture.now, apply=True)
            return captured

        with (
            patch.object(workflow, "_receipt", side_effect=capture_then_archive),
            self.assertRaisesRegex(MessageStoreError, "receipt_changed"),
        ):
            workflow.cancel(second["message_id"])
        fixture.stop.assert_not_called()

    def test_archive_during_submit_skips_uncertain_receipt_and_failed_prepare_never_dispatches(
        self,
    ):
        fixture = self.fixture
        workflow = fixture.messaging

        def submit(*args, **kwargs):
            self.assertEqual(
                0, workflow.store.archive(before=fixture.now, now=fixture.now, apply=True)["count"]
            )
            return {"run_id": fixture.run_id, "status": "running"}

        fixture.submit.side_effect = submit
        receipt = workflow.send("coder", "operator message")
        self.assertIsNone(receipt["archived_at"])
        fixture.submit.reset_mock()
        fixture.remote_status.return_value = {"run_id": fixture.run_id, "status": "completed"}
        workflow.status(receipt["message_id"])
        with closing(sqlite3.connect(workflow.store.database_path)) as conn:
            conn.execute(
                "CREATE TRIGGER disk_full BEFORE INSERT ON message_receipts "
                "BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END"
            )
            conn.commit()
        with self.assertRaisesRegex(MessageStoreError, "state_unavailable"):
            workflow.send("coder", "next message")
        fixture.submit.assert_not_called()


class MessageArchiveSchemaTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "zeus.db"
        self.database = SQLiteDatabase(self.path)
        with patch("zeus.schema.SCHEMA_VERSION", 9):
            SchemaManager(self.database).init()
        self.old = "2026-01-01T00:00:00+00:00"
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute(
                "INSERT INTO message_receipts (message_id, request_key_hash, target_bot_id, "
                "target_created_at, target_fingerprint, endpoint, credential_fingerprint, "
                "request_hash, upstream_key, dispatch_state, created_at, updated_at, "
                "retry_before, version) VALUES (?, ?, 'coder', ?, ?, ?, ?, ?, ?, "
                "'rejected', ?, ?, ?, 1)",
                (
                    "a" * 32,
                    "b" * 64,
                    self.old,
                    "c" * 64,
                    "http://127.0.0.1:8765/health",
                    "d" * 64,
                    "e" * 64,
                    "f" * 32,
                    self.old,
                    self.old,
                    "2026-01-01T00:10:00+00:00",
                ),
            )
            conn.commit()

    def snapshot(self):
        with closing(sqlite3.connect(self.path)) as conn:
            return list(conn.iterdump())

    def test_additive_upgrade_preserves_identity_indexes_and_old_readers_reject(self):
        with closing(sqlite3.connect(self.path)) as conn:
            before = conn.execute("SELECT rowid, * FROM message_receipts").fetchall()
            indexes = dict(conn.execute("SELECT name, sql FROM sqlite_master WHERE type='index'"))
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            after = conn.execute("SELECT rowid, * FROM message_receipts").fetchall()
            self.assertEqual(before, [row[:-1] for row in after])
            self.assertIsNone(after[0][-1])
            current = dict(conn.execute("SELECT name, sql FROM sqlite_master WHERE type='index'"))
            self.assertTrue(all(current[name] == sql for name, sql in indexes.items()))
            self.assertEqual(10, conn.execute("SELECT version FROM schema_version").fetchone()[0])
        migrated = self.snapshot()
        SchemaManager(self.database).migrate()
        self.assertEqual(migrated, self.snapshot())
        with patch("zeus.schema.SCHEMA_VERSION", 9):
            with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                StateStore(self.path).connect()
            with self.assertRaisesRegex(MessageStoreError, "state_unavailable"):
                MessageStore(self.path).archive(apply=True)
        self.assertEqual(migrated, self.snapshot())

    def test_failed_migration_preserves_schema_nine_and_data(self):
        class FailingSchema(SchemaManager):
            def _migrate_v9_to_v10(self, conn):
                super()._migrate_v9_to_v10(conn)
                raise sqlite3.OperationalError("injected interruption")

        original = self.snapshot()
        with self.assertRaisesRegex(sqlite3.OperationalError, "injected interruption"):
            FailingSchema(self.database).migrate()
        self.assertEqual(original, self.snapshot())

    def test_invalid_archival_is_rejected_by_sql_and_reader(self):
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            for timestamp in (
                "not-time",
                "2026-01-01T00:00:00Z",
                "2025-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00.000000+00:00",
            ):
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("UPDATE message_receipts SET archived_at = ?", (timestamp,))
            conn.execute("UPDATE message_receipts SET dispatch_state = 'unknown'")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE message_receipts SET archived_at = ?", (self.old,))
            conn.execute("PRAGMA ignore_check_constraints=ON")
            conn.execute("UPDATE message_receipts SET archived_at = ?", (self.old,))
            conn.commit()
        with self.assertRaisesRegex(MessageStoreError, "invalid_receipt"):
            MessageStore(self.path).get("a" * 32)
