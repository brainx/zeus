from __future__ import annotations

import inspect
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, call, patch

from zeus import api as api_module
from zeus.config import SQLiteSynchronous
from zeus.idempotency import IdempotencyClaim
from zeus.idempotency_store import (
    IDEMPOTENCY_HASH_RE,
    IDEMPOTENCY_OWNER_RE,
    MAX_IDEMPOTENCY_RESPONSE_BYTES,
    IdempotencyStore,
)
from zeus.schema import SchemaManager
from zeus.sqlite_db import SQLiteDatabase
from zeus.state import (
    IDEMPOTENCY_HASH_RE as STATE_IDEMPOTENCY_HASH_RE,
)
from zeus.state import (
    IDEMPOTENCY_OWNER_RE as STATE_IDEMPOTENCY_OWNER_RE,
)
from zeus.state import (
    MAX_IDEMPOTENCY_RESPONSE_BYTES as STATE_MAX_IDEMPOTENCY_RESPONSE_BYTES,
)
from zeus.state import StateStore


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


class _UnavailableSQLiteDatabase(SQLiteDatabase):
    def connect(self) -> sqlite3.Connection:
        raise sqlite3.OperationalError("database unavailable")


def _row_bytes(database_path: Path, key_hash: str) -> tuple[object, ...] | None:
    columns = (
        "key_hash",
        "request_hash",
        "state",
        "owner_instance_id",
        "response_status",
        "response_json",
        "created_at",
        "updated_at",
        "expires_at",
    )
    fields = ", ".join(f"typeof({column}), hex(CAST({column} AS BLOB))" for column in columns)
    with closing(sqlite3.connect(database_path)) as conn:
        return conn.execute(
            f"SELECT {fields} FROM idempotency_records WHERE key_hash = ?",
            (key_hash,),
        ).fetchone()


def _control_statements(trace: list[tuple[int, str]]) -> list[str]:
    controls = {"BEGIN", "COMMIT", "ROLLBACK"}
    return [
        sql.strip().upper()
        for _identity, sql in trace
        if sql.strip().upper().split(maxsplit=1)[0] in controls
    ]


def _statement_index(statements: list[str], prefix: str) -> int:
    return next(
        index
        for index, statement in enumerate(statements)
        if statement.lstrip().upper().startswith(prefix)
    )


class IdempotencyStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "zeus.db"
        self.database = SQLiteDatabase(self.database_path)
        SchemaManager(self.database).init()
        self.store = IdempotencyStore(self.database)
        self.key_hash = "a" * 64
        self.request_hash = "b" * 64
        self.future = datetime.now(UTC) + timedelta(hours=1)

    def claim(
        self,
        *,
        key_hash: str | None = None,
        request_hash: str | None = None,
        owner_instance_id: str = "owner-a",
        max_records: int = 10_000,
    ) -> IdempotencyClaim:
        return self.store.claim_idempotency(
            key_hash=key_hash or self.key_hash,
            request_hash=request_hash or self.request_hash,
            owner_instance_id=owner_instance_id,
            expires_at=self.future,
            max_records=max_records,
        )

    def complete(self, *, key_hash: str | None = None) -> None:
        self.store.complete_idempotency(
            key_hash=key_hash or self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            response_status=202,
            response_json='{"ok":true}',
            completed_at=datetime.now(UTC),
            expires_at=self.future,
        )

    def test_constructs_without_opening_the_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "zeus.db"

            IdempotencyStore(SQLiteDatabase(database_path))

            self.assertFalse(database_path.exists())

    def test_direct_store_preserves_every_claim_outcome(self) -> None:
        self.assertEqual("claimed", self.claim().kind)
        self.assertEqual("in_progress", self.claim().kind)
        self.assertEqual("conflict", self.claim(request_hash="c" * 64).kind)
        self.assertEqual(
            "indeterminate",
            self.claim(owner_instance_id="owner-b").kind,
        )

        self.complete()
        replay = self.claim()
        self.assertEqual("replay", replay.kind)
        self.assertEqual(202, replay.response_status)
        self.assertEqual('{"ok":true}', replay.response_json)

        unavailable = IdempotencyStore(
            _UnavailableSQLiteDatabase(self.database_path.with_name("unavailable.db"))
        )
        unavailable_claim = unavailable.claim_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            expires_at=self.future,
        )
        unavailable_lookup = unavailable.lookup_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
        )
        self.assertEqual("unavailable", unavailable_claim.kind)
        self.assertIsNotNone(unavailable_lookup)
        self.assertEqual("unavailable", unavailable_lookup.kind if unavailable_lookup else None)

    def test_validation_precedes_connection_and_completion_connection_errors_propagate(
        self,
    ) -> None:
        database = MagicMock(spec=SQLiteDatabase)
        store = IdempotencyStore(database)

        with self.assertRaisesRegex(ValueError, "key hash is invalid"):
            store.claim_idempotency(
                key_hash="invalid",
                request_hash=self.request_hash,
                owner_instance_id="owner-a",
                expires_at=self.future,
            )
        database.connect.assert_not_called()

        unavailable = IdempotencyStore(
            _UnavailableSQLiteDatabase(self.database_path.with_name("unavailable.db"))
        )
        with self.assertRaisesRegex(sqlite3.OperationalError, "database unavailable"):
            unavailable.complete_idempotency(
                key_hash=self.key_hash,
                request_hash=self.request_hash,
                owner_instance_id="owner-a",
                response_status=200,
                response_json="{}",
                completed_at=datetime.now(UTC),
                expires_at=self.future,
            )

    def test_claim_complete_and_lookup_keep_exact_transaction_boundaries(self) -> None:
        tracing_database = _TracingSQLiteDatabase(
            self.database_path.with_name("transaction-trace.db")
        )
        SchemaManager(tracing_database).init()
        tracing_database.traces.clear()
        store = IdempotencyStore(tracing_database)

        claimed = store.claim_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            expires_at=self.future,
        )
        claim_trace = list(tracing_database.traces)
        tracing_database.traces.clear()

        store.complete_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            response_status=200,
            response_json="{}",
            completed_at=datetime.now(UTC),
            expires_at=self.future,
        )
        complete_trace = list(tracing_database.traces)
        tracing_database.traces.clear()

        replay = store.lookup_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
        )
        lookup_trace = list(tracing_database.traces)

        claim_sql = [sql for _identity, sql in claim_trace]
        complete_sql = [sql for _identity, sql in complete_trace]
        lookup_sql = [sql for _identity, sql in lookup_trace]
        self.assertEqual("claimed", claimed.kind)
        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(claim_trace))
        self.assertEqual(1, len({identity for identity, _sql in claim_trace}))
        self.assertLess(
            _statement_index(claim_sql, "SELECT *"),
            _statement_index(claim_sql, "DELETE FROM"),
        )
        self.assertLess(
            _statement_index(claim_sql, "DELETE FROM"),
            _statement_index(claim_sql, "SELECT COUNT"),
        )
        self.assertLess(
            _statement_index(claim_sql, "SELECT COUNT"),
            _statement_index(claim_sql, "INSERT INTO"),
        )

        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(complete_trace))
        self.assertEqual(1, len({identity for identity, _sql in complete_trace}))
        self.assertLess(
            _statement_index(complete_sql, "SELECT *"),
            _statement_index(complete_sql, "UPDATE"),
        )

        self.assertIsNotNone(replay)
        self.assertEqual("replay", replay.kind if replay else None)
        self.assertEqual([], _control_statements(lookup_trace))
        self.assertEqual(1, len({identity for identity, _sql in lookup_trace}))
        self.assertTrue(lookup_sql)
        self.assertTrue(all(sql.lstrip().upper().startswith("SELECT") for sql in lookup_sql))

    def test_capacity_exhaustion_is_an_explicit_normal_commit(self) -> None:
        tracing_database = _TracingSQLiteDatabase(self.database_path.with_name("capacity.db"))
        SchemaManager(tracing_database).init()
        store = IdempotencyStore(tracing_database)
        store.claim_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            expires_at=self.future,
            max_records=1,
        )
        tracing_database.traces.clear()

        result = store.claim_idempotency(
            key_hash="c" * 64,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            expires_at=self.future,
            max_records=1,
        )
        trace = list(tracing_database.traces)

        self.assertEqual("unavailable", result.kind)
        self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(trace))
        self.assertFalse(any(sql.lstrip().upper().startswith("INSERT") for _identity, sql in trace))

    def test_corrupt_claim_rolls_back_without_changing_any_stored_bytes(self) -> None:
        self.assertEqual("claimed", self.claim().kind)
        with closing(sqlite3.connect(self.database_path)) as conn:
            conn.execute(
                "UPDATE idempotency_records SET request_hash = 'corrupt' WHERE key_hash = ?",
                (self.key_hash,),
            )
            conn.commit()
        before = _row_bytes(self.database_path, self.key_hash)

        result = self.claim(owner_instance_id="owner-b")

        self.assertEqual("unavailable", result.kind)
        self.assertEqual(before, _row_bytes(self.database_path, self.key_hash))
        with closing(sqlite3.connect(self.database_path)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
        self.assertEqual(1, count)

    def test_failed_completion_rolls_back_without_changing_any_stored_bytes(self) -> None:
        self.assertEqual("claimed", self.claim().kind)
        with closing(sqlite3.connect(self.database_path)) as conn:
            conn.execute(
                """
                CREATE TRIGGER reject_test_completion
                BEFORE UPDATE ON idempotency_records
                WHEN NEW.state = 'completed'
                BEGIN
                    SELECT RAISE(ABORT, 'injected completion failure');
                END
                """
            )
            conn.commit()
        before = _row_bytes(self.database_path, self.key_hash)

        with self.assertRaisesRegex(sqlite3.DatabaseError, "injected completion failure"):
            self.complete()

        self.assertEqual(before, _row_bytes(self.database_path, self.key_hash))

    def test_lookup_leaves_an_expired_record_byte_for_byte_unchanged(self) -> None:
        self.assertEqual("claimed", self.claim().kind)
        completed_at = datetime.now(UTC)
        self.store.complete_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            response_status=200,
            response_json="{}",
            completed_at=completed_at,
            expires_at=completed_at,
        )
        before = _row_bytes(self.database_path, self.key_hash)

        result = self.store.lookup_idempotency(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
        )

        self.assertIsNone(result)
        self.assertEqual(before, _row_bytes(self.database_path, self.key_hash))

    def test_state_facade_delegates_exact_keywords_and_propagates_results_and_errors(self) -> None:
        database_path = Path("state") / "zeus.db"
        database = MagicMock(spec=SQLiteDatabase)
        database.database_path = database_path
        schema = MagicMock(spec=SchemaManager)
        delegate = MagicMock(spec=IdempotencyStore)
        claim_result = IdempotencyClaim("claimed")
        delegate.claim_idempotency.return_value = claim_result
        delegate.lookup_idempotency.return_value = None
        completion_error = RuntimeError("completion sentinel")
        delegate.complete_idempotency.side_effect = completion_error
        completed_at = datetime(2026, 7, 22, 12, tzinfo=UTC)
        expires_at = completed_at + timedelta(hours=1)

        with (
            patch("zeus.state.SQLiteDatabase", return_value=database) as database_type,
            patch("zeus.state.SchemaManager", return_value=schema) as schema_type,
            patch("zeus.state.IdempotencyStore", return_value=delegate) as store_type,
        ):
            facade = StateStore(database_path)
            actual_claim = facade.claim_idempotency(
                key_hash=self.key_hash,
                request_hash=self.request_hash,
                owner_instance_id="owner-a",
                expires_at=expires_at,
                max_records=321,
            )
            actual_lookup = facade.lookup_idempotency(
                key_hash=self.key_hash,
                request_hash=self.request_hash,
                owner_instance_id="owner-a",
            )
            with self.assertRaises(RuntimeError) as caught:
                facade.complete_idempotency(
                    key_hash=self.key_hash,
                    request_hash=self.request_hash,
                    owner_instance_id="owner-a",
                    response_status=201,
                    response_json='{"created":true}',
                    completed_at=completed_at,
                    expires_at=expires_at,
                )

        self.assertEqual(
            [
                call(
                    database_path,
                    synchronous=SQLiteSynchronous.NORMAL,
                )
            ],
            database_type.call_args_list,
        )
        self.assertEqual([call(database)], schema_type.call_args_list)
        self.assertEqual([call(database)], store_type.call_args_list)
        database.connect.assert_not_called()
        self.assertIs(claim_result, actual_claim)
        self.assertIsNone(actual_lookup)
        self.assertIs(completion_error, caught.exception)
        delegate.claim_idempotency.assert_called_once_with(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            expires_at=expires_at,
            max_records=321,
        )
        delegate.lookup_idempotency.assert_called_once_with(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
        )
        delegate.complete_idempotency.assert_called_once_with(
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            response_status=201,
            response_json='{"created":true}',
            completed_at=completed_at,
            expires_at=expires_at,
        )
        self.assertEqual(
            inspect.signature(IdempotencyStore.claim_idempotency),
            inspect.signature(StateStore.claim_idempotency),
        )
        self.assertEqual(
            inspect.signature(IdempotencyStore.lookup_idempotency),
            inspect.signature(StateStore.lookup_idempotency),
        )
        self.assertEqual(
            inspect.signature(IdempotencyStore.complete_idempotency),
            inspect.signature(StateStore.complete_idempotency),
        )

    def test_state_compatibility_aliases_and_class_monkeypatch_remain_supported(self) -> None:
        self.assertIs(IDEMPOTENCY_HASH_RE, STATE_IDEMPOTENCY_HASH_RE)
        self.assertIs(IDEMPOTENCY_OWNER_RE, STATE_IDEMPOTENCY_OWNER_RE)
        self.assertIs(
            MAX_IDEMPOTENCY_RESPONSE_BYTES,
            STATE_MAX_IDEMPOTENCY_RESPONSE_BYTES,
        )
        self.assertIs(
            STATE_MAX_IDEMPOTENCY_RESPONSE_BYTES,
            api_module.MAX_IDEMPOTENCY_RESPONSE_BYTES,
        )
        facade = StateStore(self.database_path.with_name("monkeypatch.db"))
        patched_result = IdempotencyClaim("unavailable")

        with patch.object(
            StateStore,
            "claim_idempotency",
            autospec=True,
            return_value=patched_result,
        ) as patched_claim:
            result = facade.claim_idempotency(
                key_hash=self.key_hash,
                request_hash=self.request_hash,
                owner_instance_id="owner-a",
                expires_at=self.future,
                max_records=55,
            )

        self.assertIs(patched_result, result)
        patched_claim.assert_called_once_with(
            facade,
            key_hash=self.key_hash,
            request_hash=self.request_hash,
            owner_instance_id="owner-a",
            expires_at=self.future,
            max_records=55,
        )


if __name__ == "__main__":
    unittest.main()
