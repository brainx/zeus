from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from zeus.schema import SCHEMA_VERSION, SchemaManager
from zeus.sqlite_db import SQLiteDatabase

_CREATED = "2026-01-01T00:00:00+00:00"
_UPDATED = "2026-01-01T00:01:00+00:00"
_ACTIVE_INDEX = "message_receipts_active_target_idx"


class _VersionEightSchema(SchemaManager):
    def _migrate_v8_to_v9(self, conn: sqlite3.Connection) -> None:
        pass


class MessageReleaseSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = root / "zeus.db"
        self.database = SQLiteDatabase(self.path)
        _VersionEightSchema(self.database).init()
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("UPDATE schema_version SET version = 8")
            conn.commit()

    def _insert(
        self,
        conn: sqlite3.Connection,
        number: int,
        *,
        bot_id: str | None = None,
        dispatch_state: str = "accepted",
        run_status: str = "running",
    ) -> str:
        message_id = f"{number:032x}"
        accepted = dispatch_state == "accepted"
        conn.execute(
            """
            INSERT INTO message_receipts (
                message_id, request_key_hash, target_bot_id, target_created_at,
                target_fingerprint, endpoint, credential_fingerprint, request_hash,
                upstream_key, dispatch_state, run_id, run_status,
                created_at, updated_at, retry_before, lease_until, version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                f"{number:064x}",
                bot_id or f"bot-{number}",
                _CREATED,
                "a" * 64,
                "http://127.0.0.1:8765/health",
                "b" * 64,
                "c" * 64,
                f"{number + 100:032x}",
                dispatch_state,
                f"run_{number:032x}" if accepted else None,
                run_status if accepted else None,
                _CREATED,
                _UPDATED,
                "2026-01-01T00:10:00+00:00",
                "2026-01-01T00:01:30+00:00" if dispatch_state == "prepared" else None,
                1,
            ),
        )
        return message_id

    def test_upgrade_preserves_v8_data_rowids_and_other_indexes(self) -> None:
        with closing(sqlite3.connect(self.path)) as conn:
            for number, state in enumerate(("accepted", "unknown", "prepared", "rejected"), 1):
                self._insert(conn, number, dispatch_state=state)
            self._insert(conn, 5, run_status="completed")
            conn.commit()
            old_columns = [row[1] for row in conn.execute("PRAGMA table_info(message_receipts)")]
            old_rows = conn.execute(
                "SELECT rowid, * FROM message_receipts ORDER BY rowid"
            ).fetchall()
            old_objects = conn.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT IN ('message_receipts', ?) ORDER BY type, name",
                (_ACTIVE_INDEX,),
            ).fetchall()

        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(9, SCHEMA_VERSION)
            self.assertEqual(9, conn.execute("SELECT version FROM schema_version").fetchone()[0])
            columns = [row[1] for row in conn.execute("PRAGMA table_info(message_receipts)")]
            self.assertEqual([*old_columns, "released_at"], columns)
            rows = conn.execute("SELECT rowid, * FROM message_receipts ORDER BY rowid").fetchall()
            self.assertEqual(old_rows, [row[:-1] for row in rows])
            self.assertEqual([None] * len(rows), [row[-1] for row in rows])
            self.assertEqual(
                old_objects,
                conn.execute(
                    "SELECT type, name, sql FROM sqlite_master "
                    "WHERE name NOT IN ('message_receipts', ?) ORDER BY type, name",
                    (_ACTIVE_INDEX,),
                ).fetchall(),
            )
            indexes = {row[1]: row for row in conn.execute("PRAGMA index_list(message_receipts)")}
            self.assertEqual(1, indexes[_ACTIVE_INDEX][2])
            self.assertEqual(1, indexes[_ACTIVE_INDEX][4])
            self.assertEqual(
                ["target_bot_id", "target_created_at"],
                [row[2] for row in conn.execute(f"PRAGMA index_info({_ACTIVE_INDEX})")],
            )
            migrated_dump = list(conn.iterdump())

        SchemaManager(self.database).init()
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(migrated_dump, list(conn.iterdump()))

    def test_release_frees_only_accepted_active_receipt_slot(self) -> None:
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            for number, status in enumerate(
                ("queued", "running", "waiting_for_approval", "stopping"), 1
            ):
                with self.subTest(status=status):
                    bot_id = f"bot-{number}"
                    message_id = self._insert(conn, number, run_status=status)
                    before = conn.execute(
                        "SELECT * FROM message_receipts WHERE message_id = ?", (message_id,)
                    ).fetchone()
                    with self.assertRaises(sqlite3.IntegrityError):
                        self._insert(conn, number + 10, bot_id=bot_id, dispatch_state="unknown")
                    conn.execute(
                        "UPDATE message_receipts SET released_at = ? WHERE message_id = ?",
                        (_UPDATED, message_id),
                    )
                    after = conn.execute(
                        "SELECT * FROM message_receipts WHERE message_id = ?", (message_id,)
                    ).fetchone()
                    self.assertEqual(before[:-1], after[:-1])
                    self.assertEqual(_UPDATED, after[-1])
                    self._insert(conn, number + 10, bot_id=bot_id, dispatch_state="unknown")
                    with self.assertRaises(sqlite3.IntegrityError):
                        self._insert(conn, number + 20, bot_id=bot_id, dispatch_state="prepared")
                    # A released row still owns its request key and upstream key.
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(
                            "UPDATE message_receipts SET request_key_hash = ? WHERE message_id = ?",
                            (f"{number:064x}", f"{number + 10:032x}"),
                        )
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(
                            "UPDATE message_receipts SET upstream_key = ? WHERE message_id = ?",
                            (f"{number + 100:032x}", f"{number + 10:032x}"),
                        )

    def test_terminal_receipts_remain_outside_active_index(self) -> None:
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            for number, status in enumerate(("completed", "failed", "cancelled", "interrupted"), 1):
                with self.subTest(status=status):
                    self._insert(conn, number, run_status=status)
                    self._insert(
                        conn, number + 10, bot_id=f"bot-{number}", dispatch_state="unknown"
                    )

    def test_release_timestamp_requires_canonical_utc_and_record_time_bounds(self) -> None:
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            self._insert(conn, 1)
            for timestamp in (
                _CREATED,
                "2026-01-01T00:00:00.000001+00:00",
                "2026-01-01T00:00:00.999999+00:00",
                _UPDATED,
                None,
            ):
                with self.subTest(valid=timestamp):
                    conn.execute("UPDATE message_receipts SET released_at = ?", (timestamp,))
            for timestamp in (
                "2025-12-31T23:59:59+00:00",
                "2026-01-01T00:01:01+00:00",
                "2026-01-01T00:00:01Z",
                "2026-01-01T00:00:01+01:00",
                "2026-01-01 00:00:01+00:00",
                "2026-01-01T00:00:61+00:00",
                "2026-01-01T00:00:01.1+00:00",
                "2026-01-01T00:00:01.000000+00:00",
                "2026-01-01T00:00:01.00000a+00:00",
                "not-a-timestamp",
                b"2026-01-01T00:00:01+00:00",
            ):
                with self.subTest(invalid=timestamp), self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("UPDATE message_receipts SET released_at = ?", (timestamp,))

    def test_only_accepted_receipts_can_have_a_release_timestamp(self) -> None:
        SchemaManager(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            for number, state in enumerate(("prepared", "unknown", "rejected"), 1):
                with self.subTest(state=state):
                    message_id = self._insert(conn, number, dispatch_state=state)
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(
                            "UPDATE message_receipts SET released_at = ? WHERE message_id = ?",
                            (_UPDATED, message_id),
                        )

    def test_failed_upgrade_rolls_back_column_index_and_version(self) -> None:
        class FailingMigration(SchemaManager):
            def _migrate_v8_to_v9(self, conn: sqlite3.Connection) -> None:
                super()._migrate_v8_to_v9(conn)
                raise sqlite3.OperationalError("injected migration failure")

        with closing(sqlite3.connect(self.path)) as conn:
            self._insert(conn, 1)
            conn.commit()
            original_dump = list(conn.iterdump())
        with self.assertRaisesRegex(sqlite3.OperationalError, "injected migration failure"):
            FailingMigration(self.database).migrate()
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(original_dump, list(conn.iterdump()))
            self.assertEqual(8, conn.execute("SELECT version FROM schema_version").fetchone()[0])
            self.assertNotIn(
                "released_at",
                [row[1] for row in conn.execute("PRAGMA table_info(message_receipts)")],
            )
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert(conn, 2, bot_id="bot-1", dispatch_state="unknown")


if __name__ == "__main__":
    unittest.main()
