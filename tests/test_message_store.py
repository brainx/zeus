from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.message_store import MessageStore, MessageStoreError
from zeus.models import BotRecord
from zeus.schema import SchemaManager
from zeus.sqlite_db import SQLiteDatabase
from zeus.state import StateStore


class MessageStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / "zeus.db"
        self.state = StateStore(self.path)
        self.state.init()
        self.store = MessageStore(self.path)
        self.now = datetime(2026, 1, 1, tzinfo=UTC)
        self.incarnation = self.now - timedelta(days=1)

    def _args(self, **changes):
        args = dict(
            bot_id="coder",
            incarnation=self.incarnation,
            target_fingerprint="a" * 64,
            endpoint="http://127.0.0.1:8765/health",
            credential_fingerprint="b" * 64,
            input_fingerprint="c" * 64,
            request_key_fingerprint="d" * 64,
            now=self.now,
            retry_before=self.now + timedelta(minutes=10),
        )
        args.update(changes)
        return args

    def _prepare(self, **changes):
        return self.store.prepare(**self._args(**changes))[0]

    def _error(self, code, action):
        with self.assertRaises(MessageStoreError) as raised:
            action()
        self.assertEqual(code, raised.exception.code)

    def test_reservation_is_committed_and_interrupted_prepared_is_ambiguous(self) -> None:
        receipt, created = self.store.prepare(**self._args())
        self.assertTrue(created)
        self.assertEqual("prepared", receipt.dispatch_state)
        self.assertEqual(1, receipt.version)
        observed = MessageStore(self.path).get(receipt.message_id)
        self.assertEqual("unknown", observed.dispatch_state)
        self.assertEqual(receipt.upstream_key, observed.upstream_key)
        replay, created = self.store.prepare(**self._args())
        self.assertFalse(created)
        self.assertEqual(observed, replay)
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(
                "prepared",
                conn.execute("SELECT dispatch_state FROM message_receipts").fetchone()[0],
            )

    def test_concurrent_same_key_has_one_dispatch_owner(self) -> None:
        barrier = threading.Barrier(4)

        def reserve():
            barrier.wait(timeout=3)
            return MessageStore(self.path).prepare(**self._args())

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _index: reserve(), range(4)))
        self.assertEqual(1, sum(created for _receipt, created in results))
        self.assertEqual(1, len({receipt.message_id for receipt, _created in results}))
        self.assertEqual(1, len({receipt.upstream_key for receipt, _created in results}))

    def test_request_key_conflicts_on_input_target_and_credentials(self) -> None:
        self._prepare()
        for changes in (
            {"input_fingerprint": "e" * 64},
            {"target_fingerprint": "e" * 64},
            {"credential_fingerprint": "e" * 64},
            {"bot_id": "other-bot"},
            {"incarnation": self.incarnation + timedelta(hours=1)},
            {"endpoint": "http://127.0.0.1:9988/health"},
        ):
            with self.subTest(fields=list(changes)):
                self._error("request_conflict", lambda changes=changes: self._prepare(**changes))

    def test_concurrent_different_keys_block_same_incarnation(self) -> None:
        barrier = threading.Barrier(2)

        def reserve(key):
            barrier.wait(timeout=3)
            try:
                return MessageStore(self.path).prepare(**self._args(request_key_fingerprint=key))[1]
            except MessageStoreError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, ("d" * 64, "e" * 64)))
        self.assertCountEqual([True, "bot_busy"], results)

    def test_accepted_nonterminal_blocks_until_terminal_and_cancel_is_sticky(self) -> None:
        receipt = self._prepare()
        receipt = self.store.finish_attempt(
            receipt.message_id,
            expected_version=1,
            dispatch_state="accepted",
            run_id="run-123",
            run_status="running",
            now=self.now,
        )
        for status in ("queued", "waiting_for_approval", "stopping"):
            receipt = self.store.update_run(
                receipt.message_id,
                expected_version=receipt.version,
                run_status=status,
                now=self.now,
                cancel_requested=status == "stopping",
            )
            self._error("bot_busy", lambda: self._prepare(request_key_fingerprint="e" * 64))
        receipt = self.store.update_run(
            receipt.message_id,
            expected_version=receipt.version,
            run_status="cancelled",
            now=self.now + timedelta(seconds=2),
        )
        self.assertEqual(self.now, receipt.cancel_requested_at)
        self.assertEqual(self.now + timedelta(seconds=2), receipt.last_checked_at)
        self._error(
            "invalid_transition",
            lambda: self.store.update_run(
                receipt.message_id,
                expected_version=receipt.version,
                run_status="running",
                now=self.now + timedelta(seconds=3),
            ),
        )
        self.assertEqual("prepared", self._prepare(request_key_fingerprint="e" * 64).dispatch_state)

    def test_unknown_blocks_even_after_retry_expiry_and_rejected_releases_target(self) -> None:
        receipt = self._prepare()
        receipt = self.store.finish_attempt(
            receipt.message_id,
            expected_version=1,
            dispatch_state="unknown",
            error_code="timeout",
            now=self.now,
        )
        self._error(
            "bot_busy",
            lambda: self._prepare(
                request_key_fingerprint="e" * 64,
                now=self.now + timedelta(hours=1),
                retry_before=self.now + timedelta(hours=2),
            ),
        )
        retry = self.store.claim_retry(
            receipt.message_id, expected_version=receipt.version, now=self.now
        )
        receipt = self.store.finish_attempt(
            receipt.message_id,
            expected_version=retry.version,
            dispatch_state="rejected",
            error_code="authentication_failed",
            now=self.now,
        )
        self.assertEqual("rejected", receipt.dispatch_state)
        self._prepare(request_key_fingerprint="e" * 64)

    def test_cancel_intent_preserves_last_observation_and_terminal_status(self) -> None:
        receipt = self._prepare()
        receipt = self.store.finish_attempt(
            receipt.message_id,
            expected_version=receipt.version,
            dispatch_state="accepted",
            run_id="run-123",
            run_status="running",
            now=self.now,
        )
        requested_at = self.now + timedelta(seconds=1)
        receipt = self.store.record_cancel_intent(
            receipt.message_id, expected_version=receipt.version, now=requested_at
        )
        self.assertEqual("running", receipt.run_status)
        self.assertIsNone(receipt.last_checked_at)
        self.assertEqual(requested_at, receipt.cancel_requested_at)
        self.assertEqual(requested_at, receipt.updated_at)
        checked_at = self.now + timedelta(seconds=2)
        receipt = self.store.update_run(
            receipt.message_id,
            expected_version=receipt.version,
            run_status="completed",
            now=checked_at,
        )
        receipt = self.store.record_cancel_intent(
            receipt.message_id,
            expected_version=receipt.version,
            now=self.now + timedelta(seconds=3),
        )
        self.assertEqual("completed", receipt.run_status)
        self.assertEqual(checked_at, receipt.last_checked_at)
        self.assertEqual(requested_at, receipt.cancel_requested_at)

    def test_cancel_intent_requires_acknowledgement_current_version_and_clock(self) -> None:
        receipt = self._prepare()
        self._error(
            "invalid_transition",
            lambda: self.store.record_cancel_intent(
                receipt.message_id, expected_version=receipt.version, now=self.now
            ),
        )
        receipt = self.store.finish_attempt(
            receipt.message_id,
            expected_version=receipt.version,
            dispatch_state="accepted",
            run_id="run-123",
            run_status="running",
            now=self.now,
        )
        self._error(
            "clock_rollback",
            lambda: self.store.record_cancel_intent(
                receipt.message_id,
                expected_version=receipt.version,
                now=self.now - timedelta(seconds=1),
            ),
        )
        requested = self.store.record_cancel_intent(
            receipt.message_id, expected_version=receipt.version, now=self.now
        )
        self.assertEqual(receipt.version + 1, requested.version)
        self._error(
            "receipt_changed",
            lambda: self.store.record_cancel_intent(
                receipt.message_id, expected_version=receipt.version, now=self.now
            ),
        )
        self.assertEqual(requested, self.store.get(receipt.message_id))

    def test_retry_lease_expiry_clock_rollback_and_cas(self) -> None:
        receipt = self._prepare()
        self._error(
            "clock_rollback",
            lambda: self.store.claim_retry(
                receipt.message_id, expected_version=1, now=self.now - timedelta(seconds=1)
            ),
        )
        self._error(
            "attempt_in_progress",
            lambda: self.store.claim_retry(
                receipt.message_id, expected_version=1, now=self.now + timedelta(seconds=29)
            ),
        )
        retry = self.store.claim_retry(
            receipt.message_id, expected_version=1, now=self.now + timedelta(seconds=30)
        )
        self.assertEqual(receipt.upstream_key, retry.upstream_key)
        self._error(
            "receipt_changed",
            lambda: self.store.finish_attempt(
                receipt.message_id,
                expected_version=1,
                dispatch_state="accepted",
                run_id="late",
                run_status="running",
                now=self.now + timedelta(seconds=31),
            ),
        )
        accepted = self.store.finish_attempt(
            receipt.message_id,
            expected_version=retry.version,
            dispatch_state="accepted",
            run_id="new",
            run_status="running",
            now=self.now + timedelta(seconds=31),
        )
        self._error(
            "receipt_changed",
            lambda: self.store.finish_attempt(
                receipt.message_id,
                expected_version=retry.version,
                dispatch_state="unknown",
                error_code="timeout",
                now=self.now + timedelta(seconds=32),
            ),
        )
        self.assertEqual(accepted, self.store.get(receipt.message_id))

    def test_concurrent_retry_claims_cannot_share_dispatch_authority(self) -> None:
        receipt = self._prepare()
        barrier = threading.Barrier(2)

        def retry():
            barrier.wait(timeout=3)
            try:
                return (
                    MessageStore(self.path)
                    .claim_retry(
                        receipt.message_id, expected_version=1, now=self.now + timedelta(seconds=30)
                    )
                    .dispatch_state
                )
            except MessageStoreError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: retry(), range(2)))
        self.assertCountEqual(["prepared", "receipt_changed"], results)

    def test_expired_retry_cannot_submit_and_clock_rollback_cannot_replay(self) -> None:
        receipt = self._prepare()
        self._error(
            "retry_expired",
            lambda: self.store.claim_retry(
                receipt.message_id, expected_version=1, now=receipt.retry_before
            ),
        )
        self._error("clock_rollback", lambda: self._prepare(now=self.now - timedelta(seconds=1)))
        observed = self.store.get(receipt.message_id)
        self.assertEqual(1, observed.version)
        self.assertEqual("unknown", observed.dispatch_state)

    def test_tombstones_survive_bot_deletion_and_recreation_is_distinct(self) -> None:
        self.state.upsert_bot(
            BotRecord(
                "coder", "coding-bot", "Coder", "hermes/profiles/coder", created_at=self.incarnation
            )
        )
        receipt = self._prepare()
        self.state.delete_bot("coder")
        self.assertIsNotNone(self.store.get(receipt.message_id))
        self.state.upsert_bot(
            BotRecord("coder", "coding-bot", "Coder", "hermes/profiles/coder", created_at=self.now)
        )
        recreated = self._prepare(incarnation=self.now, request_key_fingerprint="e" * 64)
        self.assertNotEqual(receipt.message_id, recreated.message_id)
        self._error("request_conflict", lambda: self._prepare(incarnation=self.now))

    def test_capacity_is_global_and_never_prunes_receipts(self) -> None:
        receipt = self._prepare()
        self.store.finish_attempt(
            receipt.message_id, expected_version=1, dispatch_state="rejected", now=self.now
        )
        with closing(sqlite3.connect(self.path)) as conn:
            conn.executemany(
                "INSERT INTO message_receipts SELECT ?, NULL, target_bot_id, target_created_at, "
                "target_fingerprint, endpoint, credential_fingerprint, request_hash, ?, "
                "dispatch_state, run_id, run_status, created_at, updated_at, retry_before, "
                "last_checked_at, cancel_requested_at, lease_until, error_code, version, "
                "released_at "
                "FROM message_receipts WHERE message_id = ?",
                [
                    (f"{index:032x}", f"{index + 10000:032x}", receipt.message_id)
                    for index in range(9999)
                ],
            )
            conn.commit()
        self._error(
            "capacity_exceeded",
            lambda: self._prepare(bot_id="other-bot", request_key_fingerprint="e" * 64),
        )
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(
                10000, conn.execute("SELECT count(*) FROM message_receipts").fetchone()[0]
            )
        replay, created = self.store.prepare(**self._args())
        self.assertFalse(created)
        self.assertEqual(receipt.message_id, replay.message_id)

    def test_pagination_is_bounded_stable_and_can_filter_bot(self) -> None:
        # UUID order deliberately disagrees with chronology, including a timestamp tie.
        receipts = []
        for bot, seconds, letter in (
            ("coder", 0, "f"),
            ("other-bot", 20, "e"),
            ("coder", 10, "d"),
            ("coder", 20, "c"),
            ("other-bot", 30, "b"),
        ):
            stamp = self.now + timedelta(seconds=seconds)
            with patch(
                "zeus.message_store.uuid.uuid4",
                side_effect=[uuid.UUID(hex=letter * 32), uuid.UUID(hex="1" + letter * 31)],
            ):
                receipt = self._prepare(bot_id=bot, request_key_fingerprint=None, now=stamp)
            receipts.append(receipt)
            self.store.finish_attempt(
                receipt.message_id, expected_version=1, dispatch_state="rejected", now=stamp
            )
        first = self.store.list(limit=2)
        newer = self._prepare(
            bot_id="other-bot", request_key_fingerprint=None, now=self.now + timedelta(seconds=40)
        )
        second = self.store.list(limit=2, before=first["next_before"])
        third = self.store.list(limit=2, before=second["next_before"])
        observed = [item.message_id for page in (first, second, third) for item in page["items"]]
        self.assertEqual([letter * 32 for letter in ("b", "e", "c", "d", "f")], observed)
        self.assertNotIn(newer.message_id, observed)
        self.assertIsNone(third["next_before"])
        filtered_first = self.store.list(bot_id="coder", limit=1)
        filtered_rest = self.store.list(bot_id="coder", before=filtered_first["next_before"])
        self.assertEqual(
            [letter * 32 for letter in ("c", "d", "f")],
            [item.message_id for item in filtered_first["items"] + filtered_rest["items"]],
        )
        self.assertIsNone(filtered_rest["next_before"])
        self._error("invalid_cursor", lambda: self.store.list(before="0" * 32))
        self._error(
            "invalid_cursor", lambda: self.store.list(bot_id="coder", before=receipts[1].message_id)
        )
        for limit in (0, 101, True, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.store.list(limit=limit)
        self.assertIsNone(self.store.get("0" * 32))

    def test_receipt_updates_do_not_move_chronological_cursor(self) -> None:
        older = self._prepare()
        newer = self._prepare(
            bot_id="other-bot", request_key_fingerprint=None, now=self.now + timedelta(seconds=1)
        )
        self.store.finish_attempt(
            older.message_id,
            expected_version=1,
            dispatch_state="unknown",
            now=self.now + timedelta(seconds=2),
        )
        self.assertEqual(
            [newer.message_id, older.message_id],
            [item.message_id for item in self.store.list()["items"]],
        )
        self.assertEqual(
            [older.message_id],
            [item.message_id for item in self.store.list(before=newer.message_id)["items"]],
        )

    def test_reads_never_initialize_missing_state_or_change_journal_mode(self) -> None:
        missing = self.root / "missing" / "zeus.db"
        for action in (
            lambda: MessageStore(missing).get("f" * 32),
            lambda: MessageStore(missing).list(),
        ):
            self._error("state_unavailable", action)
        self.assertFalse(missing.parent.exists())
        receipt = self._prepare()
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
            before = list(conn.iterdump())
        self.store.get(receipt.message_id)
        self.store.list()
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(before, list(conn.iterdump()))
            self.assertEqual("delete", conn.execute("PRAGMA journal_mode").fetchone()[0])

    def test_receipt_writes_use_full_durability_without_network_transaction(self) -> None:
        original = sqlite3.connect
        observed = []

        def connect(*args, **kwargs):
            self.assertTrue(args[0].endswith("?mode=rw"))
            conn = original(*args, **kwargs)
            # Start below FULL, so this checks the write path overrides the default.
            conn.execute("PRAGMA synchronous=OFF")

            def trace(sql):
                if sql == "BEGIN IMMEDIATE":
                    observed.append(conn.execute("PRAGMA synchronous").fetchone()[0])

            conn.set_trace_callback(trace)
            return conn

        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
        with patch("zeus.message_store.sqlite3.connect", side_effect=connect):
            receipt = self._prepare()
            self.store.finish_attempt(
                receipt.message_id, expected_version=1, dispatch_state="unknown", now=self.now
            )
        self.assertEqual([2, 2], observed)
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual("delete", conn.execute("PRAGMA journal_mode").fetchone()[0])
            self.assertEqual(
                "unknown", conn.execute("SELECT dispatch_state FROM message_receipts").fetchone()[0]
            )

    def test_writes_never_initialize_missing_state_including_after_a_read(self) -> None:
        missing = self.root / "missing" / "zeus.db"
        self._error("state_unavailable", lambda: MessageStore(missing).prepare(**self._args()))
        self.assertFalse(missing.parent.exists())
        missing = self.root / "missing.db"
        self._error("state_unavailable", lambda: MessageStore(missing).prepare(**self._args()))
        self.assertFalse(missing.exists())
        receipt = self._prepare()
        self.assertIsNotNone(self.store.get(receipt.message_id))
        self.path.rename(self.root / "moved.db")
        self._error(
            "state_unavailable",
            lambda: self.store.finish_attempt(
                receipt.message_id, expected_version=1, dispatch_state="unknown", now=self.now
            ),
        )
        self.assertFalse(self.path.exists())
        with closing(sqlite3.connect(self.root / "moved.db")) as conn:
            self.assertEqual(
                "prepared",
                conn.execute("SELECT dispatch_state FROM message_receipts").fetchone()[0],
            )

    def test_invalid_inputs_and_persisted_values_fail_without_secret_echo(self) -> None:
        private = "private-fixture-value"
        for changes in (
            {"target_fingerprint": private},
            {"request_key_fingerprint": private},
            {"endpoint": f"http://{private}@127.0.0.1:8765"},
            {"endpoint": f"http://127.0.0.1:8765/?token={private}"},
            {"now": self.now.replace(tzinfo=None)},
            {"retry_before": self.now},
            {"retry_before": self.now + timedelta(days=2)},
        ):
            with self.subTest(fields=list(changes)), self.assertRaises(ValueError) as raised:
                self._prepare(**changes)
            self.assertTrue(private not in str(raised.exception))
        receipt = self._prepare()
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("UPDATE message_receipts SET error_code = ?", (private,))
            conn.commit()
        self._error("invalid_receipt", lambda: self.store.get(receipt.message_id))
        self._error("invalid_receipt", lambda: self.store.list())
        self._error("invalid_receipt", lambda: self._prepare())


class MessageSchemaMigrationTests(unittest.TestCase):
    def _v7(self, path):
        class PriorSchemaManager(SchemaManager):
            def _migrate_v7_to_v8(self, conn):
                pass

            def _migrate_v8_to_v9(self, conn):
                pass

        PriorSchemaManager(SQLiteDatabase(path)).init()
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("UPDATE schema_version SET version = 7")
            conn.commit()

    def test_v7_migration_preserves_existing_data_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zeus.db"
            self._v7(path)
            state = StateStore(path)
            state.upsert_bot(BotRecord("coder", "coding-bot", "Coder", "hermes/profiles/coder"))
            with closing(sqlite3.connect(path)) as conn:
                before_bot = conn.execute("SELECT * FROM bots").fetchall()
                before_schema = conn.execute(
                    "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
                ).fetchall()
            state.migrate()
            state.migrate()
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(before_bot, conn.execute("SELECT * FROM bots").fetchall())
                after_schema = dict(
                    conn.execute("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL")
                )
                self.assertTrue(all(after_schema[name] == sql for name, sql in before_schema))
                self.assertEqual(
                    9, conn.execute("SELECT version FROM schema_version").fetchone()[0]
                )
                self.assertEqual(
                    [], conn.execute("PRAGMA foreign_key_list(message_receipts)").fetchall()
                )
                columns = {row[1] for row in conn.execute("PRAGMA table_info(message_receipts)")}
                self.assertTrue({"body", "api_key", "transcript", "prompt"}.isdisjoint(columns))
                for index, expected in (
                    ("message_receipts_created_id_idx", ["created_at", "message_id"]),
                    (
                        "message_receipts_target_created_id_idx",
                        ["target_bot_id", "created_at", "message_id"],
                    ),
                ):
                    self.assertEqual(
                        expected,
                        [
                            row[2]
                            for row in conn.execute("SELECT * FROM pragma_index_info(?)", (index,))
                        ],
                    )

    def test_migration_rollback_and_older_reader_guard_preserve_database(self) -> None:
        class FailingSchemaManager(SchemaManager):
            def _migrate_v7_to_v8(self, conn):
                super()._migrate_v7_to_v8(conn)
                raise sqlite3.OperationalError("fixture interruption")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zeus.db"
            self._v7(path)
            with closing(sqlite3.connect(path)) as conn:
                before = list(conn.iterdump())
            with self.assertRaises(sqlite3.OperationalError):
                FailingSchemaManager(SQLiteDatabase(path)).migrate()
            with closing(sqlite3.connect(path)) as conn:
                self.assertEqual(before, list(conn.iterdump()))
            StateStore(path).migrate()
            with (
                patch("zeus.schema.SCHEMA_VERSION", 7),
                self.assertRaisesRegex(RuntimeError, "newer than supported"),
            ):
                StateStore(path).connect()
