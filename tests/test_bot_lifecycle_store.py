from __future__ import annotations

import ast
import inspect
import json
import sqlite3
import tempfile
import unittest
from collections.abc import Callable
from contextlib import closing
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from operator import methodcaller
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from zeus.bot_lifecycle_store import (
    LIFECYCLE_ERROR_CODE_RE,
    LIFECYCLE_ID_RE,
    LIFECYCLE_INTENT_ACTIONS,
    LIFECYCLE_SOURCES,
    BotLifecycleStore,
)
from zeus.config import SQLiteSynchronous
from zeus.idempotency_store import IdempotencyStore
from zeus.lifecycle import LifecycleEvent, LifecycleEventInput
from zeus.models import BotRecord, BotStatus
from zeus.reconcile_store import ReconcileStore
from zeus.sanitization import MAX_SANITIZED_JSON_BYTES
from zeus.schema import SchemaManager
from zeus.sqlite_db import SQLiteDatabase
from zeus.state import LIFECYCLE_ERROR_CODE_RE as STATE_LIFECYCLE_ERROR_CODE_RE
from zeus.state import LIFECYCLE_ID_RE as STATE_LIFECYCLE_ID_RE
from zeus.state import LIFECYCLE_INTENT_ACTIONS as STATE_LIFECYCLE_INTENT_ACTIONS
from zeus.state import LIFECYCLE_SOURCES as STATE_LIFECYCLE_SOURCES
from zeus.state import StateStore

FIXED_NOW = datetime(2026, 7, 21, 12, 34, 56, tzinfo=UTC)
NEXT_RESTART = FIXED_NOW + timedelta(minutes=5)

PUBLIC_METHODS = (
    "begin_lifecycle_intent",
    "complete_lifecycle_intent",
    "clear_stale_intent",
    "audit_log_path",
    "append_audit_event",
    "upsert_bot",
    "upsert_bot_with_event",
    "get_bot",
    "list_bots",
    "update_status",
    "update_lifecycle_state",
    "update_lifecycle_with_event",
    "update_restart_state",
    "update_restart_with_event",
    "delete_bot",
    "delete_bot_with_event",
    "list_lifecycle_events",
    "history_payload",
)


class _TracingSQLiteDatabase(SQLiteDatabase):
    def __init__(self, database_path: Path | str) -> None:
        super().__init__(database_path)
        self.traces: list[tuple[int, str]] = []
        self.connection_count = 0

    def connect(self) -> sqlite3.Connection:
        self.connection_count += 1
        conn = super().connect()
        connection_serial = self.connection_count
        conn.set_trace_callback(lambda sql: self.traces.append((connection_serial, sql)))
        return conn


class _CountingSQLiteDatabase(SQLiteDatabase):
    def __init__(self, database_path: Path | str) -> None:
        super().__init__(database_path)
        self.connection_count = 0

    def connect(self) -> sqlite3.Connection:
        self.connection_count += 1
        return super().connect()


def _record(root: Path, *, bot_id: str = "coder") -> BotRecord:
    return BotRecord(
        bot_id=bot_id,
        template_id="coding-bot",
        display_name=bot_id.title(),
        profile_path=str(root / "profiles" / bot_id),
    )


def _event(
    action: str,
    *,
    bot_id: str = "coder",
    operation_character: str = "a",
) -> LifecycleEventInput:
    return LifecycleEventInput(
        bot_id=bot_id,
        operation_id=operation_character * 32,
        source="cli",
        action=action,
        outcome="success",
        reason="test transition",
        details={"kind": action},
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
    normalized_prefix = " ".join(prefix.split()).upper()
    return next(
        index
        for index, statement in enumerate(statements[start:], start=start)
        if " ".join(statement.split()).upper().startswith(normalized_prefix)
    )


def _table_bytes(database_path: Path, table: str, order_by: str) -> tuple[tuple[object, ...], ...]:
    with closing(sqlite3.connect(database_path)) as conn:
        columns = tuple(row[1] for row in conn.execute(f"PRAGMA table_info({table})"))
        fields = ", ".join(f"typeof({column}), hex(CAST({column} AS BLOB))" for column in columns)
        rows = conn.execute(f"SELECT {fields} FROM {table} ORDER BY {order_by}").fetchall()
    return tuple(rows)


def _database_snapshot(
    database_path: Path,
) -> tuple[tuple[tuple[object, ...], ...], tuple[tuple[object, ...], ...]]:
    return (
        _table_bytes(database_path, "bots", "bot_id"),
        _table_bytes(database_path, "lifecycle_events", "event_id"),
    )


def _install_event_rejection(database_path: Path) -> None:
    with closing(sqlite3.connect(database_path)) as conn:
        conn.execute(
            """
            CREATE TRIGGER reject_test_lifecycle_event
            BEFORE INSERT ON lifecycle_events
            BEGIN
                SELECT RAISE(ABORT, 'injected lifecycle event failure');
            END
            """
        )
        conn.commit()


class BotLifecycleStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.database_path = self.root / "zeus.db"
        self.database = SQLiteDatabase(self.database_path)
        SchemaManager(self.database).init()
        self.store = BotLifecycleStore(self.database)

    def _new_tracing_store(
        self,
        name: str,
    ) -> tuple[_TracingSQLiteDatabase, BotLifecycleStore, Path]:
        root = self.root / name
        database = _TracingSQLiteDatabase(root / "zeus.db")
        SchemaManager(database).init()
        database.traces.clear()
        return database, BotLifecycleStore(database), root

    def _prepare_atomic(
        self,
        store: BotLifecycleStore,
        root: Path,
        operation: str,
    ) -> None:
        if operation != "create":
            store.upsert_bot(_record(root))
        if operation in {"complete_intent", "clear_intent"}:
            store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="b" * 32,
                source="cli",
            )

    def _invoke_atomic(
        self,
        store: BotLifecycleStore,
        root: Path,
        operation: str,
    ) -> object:
        if operation == "create":
            return store.upsert_bot_with_event(
                _record(root),
                event=_event("bot.create"),
            )
        if operation == "lifecycle":
            return store.update_lifecycle_with_event(
                "coder",
                BotStatus.running,
                4321,
                event=_event("bot.start"),
                started_at=FIXED_NOW,
                ready_at=FIXED_NOW,
            )
        if operation == "restart":
            return store.update_restart_with_event(
                "coder",
                status=BotStatus.failed,
                pid=None,
                restart_attempts=1,
                next_restart_at=NEXT_RESTART,
                event=_event("bot.restart.schedule"),
            )
        if operation == "delete":
            return store.delete_bot_with_event(
                "coder",
                event=_event("bot.delete"),
            )
        if operation == "begin_intent":
            return store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
            )
        if operation == "complete_intent":
            return store.complete_lifecycle_intent(
                "coder",
                action="start",
                operation_id="b" * 32,
                desired_revision=1,
                status=BotStatus.running,
                pid=4321,
                source="cli",
            )
        if operation == "clear_intent":
            return store.clear_stale_intent(
                "coder",
                action="start",
                operation_id="b" * 32,
                desired_revision=1,
                source="recovery",
                reason="stale intent",
            )
        raise AssertionError(f"unknown atomic operation: {operation}")

    def test_ownership_construction_and_compatibility_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "zeus.db"

            BotLifecycleStore(SQLiteDatabase(database_path))

            self.assertFalse(database_path.exists())

        import zeus.bot_lifecycle_store as bot_lifecycle_store_module

        source = inspect.getsource(bot_lifecycle_store_module)
        tree = ast.parse(source)
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        self.assertTrue(
            imported_modules.isdisjoint(
                {
                    "zeus.reconcile_store",
                    "zeus.reconciliation",
                    "zeus.schema",
                    "zeus.state",
                }
            )
        )
        self.assertNotIn("CREATE TABLE", source.upper())
        self.assertNotIn("CREATE TRIGGER", source.upper())
        self.assertIs(LIFECYCLE_ID_RE, STATE_LIFECYCLE_ID_RE)
        self.assertIs(LIFECYCLE_ERROR_CODE_RE, STATE_LIFECYCLE_ERROR_CODE_RE)
        self.assertIs(LIFECYCLE_SOURCES, STATE_LIFECYCLE_SOURCES)
        self.assertIs(LIFECYCLE_INTENT_ACTIONS, STATE_LIFECYCLE_INTENT_ACTIONS)

    def test_direct_store_round_trip_covers_every_public_family(self) -> None:
        coder = _record(self.root)
        self.store.upsert_bot(coder)
        self.assertEqual(coder, self.store.get_bot("coder"))
        self.assertEqual([coder], self.store.list_bots())

        self.store.update_status("coder", BotStatus.starting, 1111, reset_restart=True)
        self.store.update_lifecycle_state(
            "coder",
            BotStatus.running,
            2222,
            started_at=FIXED_NOW,
            ready_at=FIXED_NOW,
            last_transition_reason="ready",
        )
        self.store.update_restart_state(
            "coder",
            status=BotStatus.failed,
            pid=None,
            restart_attempts=2,
            next_restart_at=NEXT_RESTART,
        )
        loaded = self.store.get_bot("coder")
        assert loaded is not None
        self.assertEqual(BotStatus.failed, loaded.status)
        self.assertEqual(2, loaded.restart_attempts)
        self.assertEqual(NEXT_RESTART, loaded.next_restart_at)

        begun = self.store.begin_lifecycle_intent(
            "coder",
            action="start",
            operation_id="a" * 32,
            source="cli",
        )
        self.assertEqual(1, begun.desired_revision)
        completed = self.store.complete_lifecycle_intent(
            "coder",
            action="start",
            operation_id="a" * 32,
            desired_revision=1,
            status=BotStatus.running,
            pid=3333,
            source="cli",
        )
        self.assertTrue(completed.converged)
        restarted = self.store.begin_lifecycle_intent(
            "coder",
            action="restart",
            operation_id="b" * 32,
            source="cli",
        )
        cleared = self.store.clear_stale_intent(
            "coder",
            action="restart",
            operation_id="b" * 32,
            desired_revision=restarted.desired_revision,
            source="recovery",
            reason="stale intent",
        )
        self.assertIsNone(cleared.pending_operation_id)

        evented = _record(self.root, bot_id="evented")
        created = self.store.upsert_bot_with_event(
            evented,
            event=_event("bot.create", bot_id="evented", operation_character="c"),
        )
        transitioned = self.store.update_lifecycle_with_event(
            "evented",
            BotStatus.running,
            4444,
            event=_event("bot.start", bot_id="evented", operation_character="d"),
        )
        scheduled = self.store.update_restart_with_event(
            "evented",
            status=BotStatus.failed,
            pid=None,
            restart_attempts=1,
            next_restart_at=NEXT_RESTART,
            event=_event(
                "bot.restart.schedule",
                bot_id="evented",
                operation_character="e",
            ),
        )
        deleted = self.store.delete_bot_with_event(
            "evented",
            event=_event("bot.delete", bot_id="evented", operation_character="f"),
        )
        self.assertEqual(
            ["bot.delete", "bot.restart.schedule", "bot.start", "bot.create"],
            [event.action for event in self.store.list_lifecycle_events("evented", 10, None)],
        )
        self.assertIsInstance(created, LifecycleEvent)
        self.assertIsInstance(transitioned, LifecycleEvent)
        self.assertIsInstance(scheduled, LifecycleEvent)
        self.assertIs(deleted, True)
        self.assertEqual("evented", self.store.history_payload("evented", 2, None)["bot_id"])
        self.assertEqual(self.root / "logs" / "audit.jsonl", self.store.audit_log_path())

        self.store.update_status("missing", BotStatus.running, 9999)
        with self.assertRaises(KeyError):
            self.store.update_lifecycle_state("missing", BotStatus.failed)
        with self.assertRaises(KeyError):
            self.store.update_restart_state(
                "missing",
                status=BotStatus.failed,
                pid=None,
                restart_attempts=1,
                next_restart_at=None,
            )
        self.assertIs(self.store.delete_bot("missing"), False)
        with self.assertRaises(KeyError):
            self.store.delete_bot_with_event(
                "missing",
                event=_event("bot.delete", bot_id="missing"),
            )
        self.assertIs(self.store.delete_bot("coder"), True)

    def test_invalid_inputs_are_rejected_before_connecting(self) -> None:
        database = _CountingSQLiteDatabase(self.root / "validation.db")
        store = BotLifecycleStore(database)
        record = _record(self.root)

        invalid_calls = (
            lambda: store.begin_lifecycle_intent(
                "coder",
                action="delete",
                operation_id="a" * 32,
                source="cli",
            ),
            lambda: store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="api",
            ),
            lambda: store.complete_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                desired_revision=0,
                status=BotStatus.running,
                pid=1,
                source="cli",
            ),
            lambda: store.complete_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                desired_revision=1,
                status=BotStatus.stopped,
                pid=None,
                source="cli",
            ),
            lambda: store.upsert_bot_with_event(
                record,
                event=_event("bot.create", bot_id="other"),
            ),
            lambda: store.list_lifecycle_events("coder", 0, None),
            lambda: store.history_payload("coder", 10, 0),
        )
        for invalid_call in invalid_calls:
            with self.subTest(call=invalid_call), self.assertRaises((TypeError, ValueError)):
                invalid_call()
            self.assertEqual(0, database.connection_count)

    def test_all_seven_atomic_paths_have_one_immediate_transaction_and_required_order(self) -> None:
        operations = (
            "create",
            "lifecycle",
            "restart",
            "delete",
            "begin_intent",
            "complete_intent",
            "clear_intent",
        )
        pre_event_prefixes = {
            "create": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "INSERT INTO BOTS",
            ),
            "lifecycle": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "UPDATE BOTS SET STATUS",
            ),
            "restart": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "UPDATE BOTS SET STATUS",
            ),
            "delete": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "DELETE FROM BOTS",
            ),
            "begin_intent": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "UPDATE BOTS SET DESIRED_STATE",
            ),
            "complete_intent": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "UPDATE BOTS SET STATUS",
                "UPDATE BOTS SET PENDING_OPERATION_ID",
            ),
            "clear_intent": (
                "SELECT * FROM BOTS WHERE BOT_ID",
                "UPDATE BOTS SET PENDING_OPERATION_ID",
            ),
        }
        for operation in operations:
            with self.subTest(operation=operation):
                database, store, root = self._new_tracing_store(f"atomic-{operation}")
                self._prepare_atomic(store, root, operation)
                database.traces.clear()
                database.connection_count = 0

                self._invoke_atomic(store, root, operation)
                trace = list(database.traces)
                statements = _statements(trace)

                self.assertEqual(1, database.connection_count)
                self.assertEqual(1, len({connection_id for connection_id, _sql in trace}))
                self.assertEqual(["BEGIN IMMEDIATE", "COMMIT"], _control_statements(trace))
                begin = _statement_index(statements, "BEGIN IMMEDIATE")
                ordered_indices: list[int] = []
                search_start = begin + 1
                for prefix in pre_event_prefixes[operation]:
                    index = _statement_index(statements, prefix, start=search_start)
                    ordered_indices.append(index)
                    search_start = index + 1
                event_insert = _statement_index(
                    statements,
                    "INSERT INTO LIFECYCLE_EVENTS",
                    start=search_start,
                )
                event_select = _statement_index(
                    statements,
                    "SELECT * FROM LIFECYCLE_EVENTS WHERE EVENT_ID",
                    start=event_insert,
                )
                commit = _statement_index(statements, "COMMIT")
                self.assertEqual(sorted(ordered_indices), ordered_indices)
                self.assertLess(ordered_indices[-1], event_insert)
                self.assertLess(event_insert, event_select)
                self.assertLess(event_select, commit)
                last_event_updates = [
                    index
                    for index, sql in enumerate(statements)
                    if sql.lstrip().upper().startswith("UPDATE BOTS SET LAST_EVENT_ID")
                ]
                if operation == "delete":
                    self.assertEqual([], last_event_updates)
                else:
                    self.assertTrue(last_event_updates)
                    self.assertLess(event_insert, last_event_updates[0])
                    self.assertLess(last_event_updates[0], event_select)
                if operation.endswith("intent"):
                    projection_selects = [
                        index
                        for index, sql in enumerate(statements)
                        if sql.lstrip().upper().startswith("SELECT * FROM BOTS WHERE BOT_ID")
                    ]
                    self.assertGreaterEqual(len(projection_selects), 2)
                    self.assertLess(event_select, projection_selects[-1])
                    self.assertLess(projection_selects[-1], commit)

    def test_plain_writes_keep_implicit_transactions_and_reads_remain_transaction_free(
        self,
    ) -> None:
        write_operations = (
            "upsert",
            "status",
            "lifecycle",
            "restart",
            "delete",
        )
        for operation in write_operations:
            with self.subTest(write=operation):
                database, store, root = self._new_tracing_store(f"plain-{operation}")
                if operation != "upsert":
                    store.upsert_bot(_record(root))
                database.traces.clear()
                database.connection_count = 0

                if operation == "upsert":
                    store.upsert_bot(_record(root))
                elif operation == "status":
                    store.update_status("coder", BotStatus.starting, 1001)
                elif operation == "lifecycle":
                    store.update_lifecycle_state(
                        "coder",
                        BotStatus.running,
                        1002,
                        started_at=FIXED_NOW,
                    )
                elif operation == "restart":
                    store.update_restart_state(
                        "coder",
                        status=BotStatus.failed,
                        pid=None,
                        restart_attempts=3,
                        next_restart_at=NEXT_RESTART,
                    )
                else:
                    self.assertIs(store.delete_bot("coder"), True)

                trace = list(database.traces)
                self.assertEqual(1, database.connection_count)
                self.assertEqual(1, len({connection_id for connection_id, _sql in trace}))
                self.assertEqual(["BEGIN", "COMMIT"], _control_statements(trace))
                self.assertNotIn("BEGIN IMMEDIATE", _control_statements(trace))

        database, store, root = self._new_tracing_store("reads")
        store.upsert_bot_with_event(_record(root), event=_event("bot.create"))
        read_operations = (
            lambda: store.get_bot("coder"),
            store.list_bots,
            lambda: store.list_lifecycle_events("coder", 10, None),
            lambda: store.history_payload("coder", 10, None),
        )
        for read_operation in read_operations:
            with self.subTest(read=read_operation):
                database.traces.clear()
                database.connection_count = 0
                read_operation()
                trace = list(database.traces)
                self.assertEqual(1, database.connection_count)
                self.assertEqual(1, len({connection_id for connection_id, _sql in trace}))
                self.assertEqual([], _control_statements(trace))
                self.assertTrue(
                    all(sql.lstrip().upper().startswith("SELECT") for _identity, sql in trace)
                )
        database.traces.clear()
        database.connection_count = 0
        self.assertEqual(root / "logs" / "audit.jsonl", store.audit_log_path())
        self.assertEqual([], database.traces)
        self.assertEqual(0, database.connection_count)

    def test_sql_trigger_rolls_back_all_seven_atomic_paths_byte_for_byte(self) -> None:
        operations = (
            "create",
            "lifecycle",
            "restart",
            "delete",
            "begin_intent",
            "complete_intent",
            "clear_intent",
        )
        for operation in operations:
            with self.subTest(operation=operation):
                database, store, root = self._new_tracing_store(f"rollback-{operation}")
                self._prepare_atomic(store, root, operation)
                _install_event_rejection(database.database_path)
                before = _database_snapshot(database.database_path)
                database.traces.clear()
                database.connection_count = 0

                with self.assertRaisesRegex(
                    sqlite3.DatabaseError,
                    "injected lifecycle event failure",
                ):
                    self._invoke_atomic(store, root, operation)

                self.assertEqual(
                    ["BEGIN IMMEDIATE", "ROLLBACK"],
                    _control_statements(database.traces),
                )
                self.assertEqual(1, database.connection_count)
                self.assertEqual(before, _database_snapshot(database.database_path))

    def test_late_materialization_failures_roll_back_event_and_projection(self) -> None:
        for operation in ("create", "lifecycle", "restart", "delete"):
            with self.subTest(event=operation):
                database, store, root = self._new_tracing_store(f"late-event-{operation}")
                self._prepare_atomic(store, root, operation)
                before = _database_snapshot(database.database_path)

                with (
                    patch.object(
                        store,
                        "_row_to_lifecycle_event",
                        side_effect=sqlite3.DatabaseError("event materialization failed"),
                    ),
                    self.assertRaisesRegex(sqlite3.DatabaseError, "event materialization failed"),
                ):
                    self._invoke_atomic(store, root, operation)

                self.assertEqual(before, _database_snapshot(database.database_path))

        for operation in ("begin_intent", "complete_intent", "clear_intent"):
            with self.subTest(record=operation):
                database, store, root = self._new_tracing_store(f"late-record-{operation}")
                self._prepare_atomic(store, root, operation)
                before = _database_snapshot(database.database_path)

                with (
                    patch.object(
                        store,
                        "_row_to_record",
                        side_effect=sqlite3.DatabaseError("record materialization failed"),
                    ),
                    self.assertRaisesRegex(sqlite3.DatabaseError, "record materialization failed"),
                ):
                    self._invoke_atomic(store, root, operation)

                self.assertEqual(before, _database_snapshot(database.database_path))

    def test_audit_callback_observes_commit_and_failure_is_fail_open_for_every_atomic_path(
        self,
    ) -> None:
        operations = (
            "create",
            "lifecycle",
            "restart",
            "delete",
            "begin_intent",
            "complete_intent",
            "clear_intent",
        )
        expected_projection = {
            "create": ("stopped", "stopped", None, None, 0),
            "lifecycle": ("running", "stopped", None, None, 0),
            "restart": ("failed", "stopped", None, None, 1),
            "delete": None,
            "begin_intent": ("stopped", "running", "a" * 32, "start", 0),
            "complete_intent": ("running", "running", None, None, 0),
            "clear_intent": ("stopped", "running", None, None, 0),
        }
        for operation in operations:
            with self.subTest(operation=operation):
                database, store, root = self._new_tracing_store(f"audit-order-{operation}")
                self._prepare_atomic(store, root, operation)
                before_events = len(_database_snapshot(database.database_path)[1])
                database.traces.clear()
                database.connection_count = 0
                callback_observations: list[tuple[list[str], int, tuple[object, ...] | None]] = []

                def observe_commit(
                    _event: LifecycleEvent,
                    *,
                    _database: _TracingSQLiteDatabase = database,
                    _observations: list[
                        tuple[list[str], int, tuple[object, ...] | None]
                    ] = callback_observations,
                ) -> None:
                    with closing(sqlite3.connect(_database.database_path)) as conn:
                        event_count = conn.execute(
                            "SELECT COUNT(*) FROM lifecycle_events"
                        ).fetchone()[0]
                        projection_row = conn.execute(
                            """
                            SELECT status,
                                   desired_state,
                                   pending_operation_id,
                                   pending_action,
                                   restart_attempts
                            FROM bots
                            WHERE bot_id = 'coder'
                            """
                        ).fetchone()
                        projection = tuple(projection_row) if projection_row is not None else None
                    _observations.append(
                        (_control_statements(_database.traces), event_count, projection)
                    )
                    raise RuntimeError("audit callback failed")

                with patch.object(store, "_append_lifecycle_audit", side_effect=observe_commit):
                    result = self._invoke_atomic(store, root, operation)

                self.assertEqual(
                    [
                        (
                            ["BEGIN IMMEDIATE", "COMMIT"],
                            before_events + 1,
                            expected_projection[operation],
                        )
                    ],
                    callback_observations,
                )
                self.assertEqual(1, database.connection_count)
                self.assertEqual(
                    before_events + 1, len(_database_snapshot(database.database_path)[1])
                )
                if operation == "delete":
                    self.assertIs(result, True)

    def test_history_cursor_deleted_bot_and_event_immutability(self) -> None:
        self.store.upsert_bot_with_event(
            _record(self.root), event=_event("bot.create", operation_character="a")
        )
        self.store.update_lifecycle_with_event(
            "coder",
            BotStatus.running,
            4321,
            event=_event("bot.start", operation_character="b"),
        )
        self.store.update_restart_with_event(
            "coder",
            status=BotStatus.failed,
            pid=None,
            restart_attempts=1,
            next_restart_at=NEXT_RESTART,
            event=_event("bot.restart.schedule", operation_character="c"),
        )
        self.store.delete_bot_with_event(
            "coder",
            event=_event("bot.delete", operation_character="d"),
        )

        first_page = self.store.list_lifecycle_events("coder", 2, None)
        second_page = self.store.list_lifecycle_events(
            "coder",
            2,
            first_page[-1].event_id,
        )
        self.assertEqual(["bot.delete", "bot.restart.schedule"], [e.action for e in first_page])
        self.assertEqual(["bot.start", "bot.create"], [e.action for e in second_page])
        self.assertTrue(
            {event.event_id for event in first_page}.isdisjoint(
                event.event_id for event in second_page
            )
        )
        payload = self.store.history_payload("coder", 2, None)
        self.assertIsNotNone(payload["next_before"])
        self.assertEqual("coder", payload["bot_id"])
        self.assertEqual([], self.store.list_lifecycle_events("unknown", 10, None))
        with self.assertRaisesRegex(KeyError, "unknown bot"):
            self.store.history_payload("unknown", 10, None)

        event = first_page[0]
        with self.assertRaises(FrozenInstanceError):
            event.action = "mutated"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            event.details["kind"] = "mutated"  # type: ignore[index]
        before = _database_snapshot(self.database_path)
        for statement in (
            "UPDATE lifecycle_events SET action = 'mutated' WHERE event_id = ?",
            "DELETE FROM lifecycle_events WHERE event_id = ?",
        ):
            with (
                self.subTest(statement=statement),
                closing(sqlite3.connect(self.database_path)) as conn,
            ):
                with self.assertRaisesRegex(sqlite3.DatabaseError, "immutable"):
                    conn.execute(statement, (event.event_id,))
                conn.rollback()
        self.assertEqual(before, _database_snapshot(self.database_path))

    def test_audit_exact_bytes_mapping_bounds_hostile_input_and_symlink_fail_open(self) -> None:
        exact_root = (self.root / "exact").resolve()
        store = BotLifecycleStore(SQLiteDatabase(exact_root / "zeus.db"))
        with (
            patch("zeus.bot_lifecycle_store.datetime") as clock,
            patch("zeus.bot_lifecycle_store.append_private_bytes") as append,
        ):
            clock.now.return_value = FIXED_NOW
            store.append_audit_event("bot.test", label="Δ", api_key="secret")
        append.assert_called_once_with(
            exact_root / "logs" / "audit.jsonl",
            b'{"api_key": "[redacted]", "event": "bot.test", "label": "\\u0394", '
            b'"ts": "2026-07-21T12:34:56+00:00"}\n',
        )

        lifecycle_event = LifecycleEvent(
            event_id=7,
            bot_id="coder",
            operation_id="a" * 32,
            request_id=None,
            occurred_at=FIXED_NOW,
            source="cli",
            action="bot.start",
            outcome="success",
            status_before="stopped",
            status_after="running",
            pid_before=None,
            pid_after=4321,
            reason="operator request",
            error_code=None,
            error_message=None,
            details={"phase": "ready"},
        )
        with patch.object(store, "append_audit_event") as append_event:
            store._append_lifecycle_audit(lifecycle_event)
        append_event.assert_called_once_with(
            "bot.start",
            bot_id="coder",
            operation_id="a" * 32,
            request_id=None,
            source="cli",
            outcome="success",
            status_before="stopped",
            status_after="running",
            pid_before=None,
            pid_after=4321,
            reason="operator request",
            error_code=None,
            error_message=None,
            details=lifecycle_event.details,
        )

        class Hostile:
            def __str__(self) -> str:
                raise AssertionError("string conversion invoked")

            def __repr__(self) -> str:
                raise AssertionError("representation invoked")

        bounded = BotLifecycleStore(SQLiteDatabase(self.root / "bounded" / "zeus.db"))
        secret = "audit-sentinel"
        bounded.append_audit_event(
            "bot.hostile",
            api_key=secret,
            nonfinite=float("nan"),
            hostile=Hostile(),
        )
        bounded.append_audit_event(chr(0x1F512) * 2_048, message="ordinary")
        lines = bounded.audit_log_path().read_bytes().splitlines()
        self.assertEqual("[redacted]", json.loads(lines[0])["api_key"])
        self.assertIsNone(json.loads(lines[0])["nonfinite"])
        self.assertEqual("[unsupported]", json.loads(lines[0])["hostile"])
        self.assertNotIn(secret.encode(), b"\n".join(lines))
        self.assertNotIn(b"NaN", b"\n".join(lines))
        self.assertTrue(all(len(line) <= MAX_SANITIZED_JSON_BYTES for line in lines))
        self.assertTrue(json.loads(lines[1])["truncated"])

        symlink_root = self.root / "symlink"
        state_dir = symlink_root / "state"
        state_dir.mkdir(parents=True)
        external = symlink_root / "external"
        external.mkdir()
        sentinel = external / "sentinel.txt"
        sentinel.write_text("unchanged\n", encoding="utf-8")
        mode_before = external.stat().st_mode
        (state_dir / "logs").symlink_to(external, target_is_directory=True)
        unsafe = BotLifecycleStore(SQLiteDatabase(state_dir / "zeus.db"))

        unsafe.append_audit_event("bot.test", message="fail open")

        self.assertEqual("unchanged\n", sentinel.read_text(encoding="utf-8"))
        self.assertEqual(mode_before, external.stat().st_mode)
        self.assertFalse((external / "audit.jsonl").exists())

    def test_state_facade_forwards_all_eighteen_methods_with_exact_signatures(self) -> None:
        database_path = Path("state") / "zeus.db"
        database = MagicMock(spec=SQLiteDatabase)
        database.database_path = database_path
        schema = MagicMock(spec=SchemaManager)
        idempotency = MagicMock(spec=IdempotencyStore)
        reconcile = MagicMock(spec=ReconcileStore)
        delegate = MagicMock(spec=BotLifecycleStore)
        record = _record(Path("profiles"))
        event_input = _event("bot.test")
        event = MagicMock(spec=LifecycleEvent)
        history: dict[str, object] = {
            "bot_id": "coder",
            "events": [],
            "next_before": None,
        }
        audit_path = Path("state") / "logs" / "audit.jsonl"
        delegate.begin_lifecycle_intent.return_value = record
        delegate.complete_lifecycle_intent.return_value = record
        delegate.clear_stale_intent.return_value = record
        delegate.audit_log_path.return_value = audit_path
        void_sentinel = object()
        delegate.append_audit_event.return_value = void_sentinel
        delegate.upsert_bot.return_value = void_sentinel
        delegate.update_status.return_value = void_sentinel
        delegate.update_lifecycle_state.return_value = void_sentinel
        delegate.update_restart_state.return_value = void_sentinel
        delegate.upsert_bot_with_event.return_value = event
        delegate.get_bot.return_value = record
        delegate.list_bots.return_value = [record]
        delegate.update_lifecycle_with_event.return_value = event
        delegate.update_restart_with_event.return_value = event
        delegate.delete_bot.return_value = True
        delegate.delete_bot_with_event.return_value = True
        delegate.list_lifecycle_events.return_value = [event]
        delegate.history_payload.return_value = history

        with (
            patch("zeus.state.SQLiteDatabase", return_value=database) as database_type,
            patch("zeus.state.SchemaManager", return_value=schema) as schema_type,
            patch("zeus.state.IdempotencyStore", return_value=idempotency) as idempotency_type,
            patch("zeus.state.ReconcileStore", return_value=reconcile) as reconcile_type,
            patch("zeus.state.BotLifecycleStore", return_value=delegate) as lifecycle_type,
        ):
            facade = StateStore(database_path)
            actual_begin = facade.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="cli",
                request_id=None,
                reason="begin",
            )
            actual_complete = facade.complete_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                desired_revision=1,
                status=BotStatus.running,
                pid=1234,
                source="cli",
                outcome="success",
                request_id=None,
                reason="complete",
                error_code=None,
                error_message=None,
                started_at=FIXED_NOW,
                ready_at=FIXED_NOW,
                stopped_at=None,
                last_exit_code=None,
                last_error=None,
                last_transition_reason="ready",
                reset_restart=True,
                clear_ready_at=False,
                clear_stopped_at=True,
            )
            actual_clear = facade.clear_stale_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                desired_revision=1,
                source="recovery",
                reason="clear",
                request_id=None,
            )
            actual_audit_path = facade.audit_log_path()
            actual_audit = methodcaller("append_audit_event", "bot.test", bot_id="coder")(facade)
            actual_upsert = methodcaller("upsert_bot", record)(facade)
            actual_created = facade.upsert_bot_with_event(record, event=event_input)
            actual_record = facade.get_bot("coder")
            actual_records = facade.list_bots()
            actual_status = methodcaller(
                "update_status",
                "coder",
                BotStatus.running,
                1234,
                reset_restart=True,
            )(facade)
            actual_lifecycle_state = methodcaller(
                "update_lifecycle_state",
                "coder",
                BotStatus.running,
                1234,
                started_at=FIXED_NOW,
                ready_at=FIXED_NOW,
                stopped_at=None,
                last_exit_code=0,
                last_error=None,
                last_transition_reason="ready",
                reset_restart=True,
                clear_ready_at=False,
                clear_stopped_at=True,
            )(facade)
            actual_lifecycle = facade.update_lifecycle_with_event(
                "coder",
                BotStatus.running,
                1234,
                event=event_input,
                started_at=FIXED_NOW,
                ready_at=FIXED_NOW,
                stopped_at=None,
                last_exit_code=0,
                last_error=None,
                last_transition_reason="ready",
                reset_restart=True,
                clear_ready_at=False,
                clear_stopped_at=True,
            )
            actual_restart_state = methodcaller(
                "update_restart_state",
                "coder",
                status=BotStatus.failed,
                pid=None,
                restart_attempts=2,
                next_restart_at=NEXT_RESTART,
            )(facade)
            actual_restart = facade.update_restart_with_event(
                "coder",
                status=BotStatus.failed,
                pid=None,
                restart_attempts=2,
                next_restart_at=NEXT_RESTART,
                event=event_input,
            )
            actual_delete = facade.delete_bot("coder")
            actual_delete_event = facade.delete_bot_with_event("coder", event=event_input)
            actual_events = facade.list_lifecycle_events("coder", 10, 20)
            actual_history = facade.history_payload("coder", 10, 20)

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
        self.assertEqual([call(database)], idempotency_type.call_args_list)
        self.assertEqual([call(database)], reconcile_type.call_args_list)
        self.assertEqual([call(database)], lifecycle_type.call_args_list)
        database.connect.assert_not_called()
        self.assertIs(database_path, facade.database_path)
        self.assertIs(record, actual_begin)
        self.assertIs(record, actual_complete)
        self.assertIs(record, actual_clear)
        self.assertIs(audit_path, actual_audit_path)
        self.assertIsNone(actual_audit)
        self.assertIsNone(actual_upsert)
        self.assertIs(event, actual_created)
        self.assertIs(record, actual_record)
        self.assertIs(delegate.list_bots.return_value, actual_records)
        self.assertIsNone(actual_status)
        self.assertIsNone(actual_lifecycle_state)
        self.assertIs(event, actual_lifecycle)
        self.assertIsNone(actual_restart_state)
        self.assertIs(event, actual_restart)
        self.assertIs(actual_delete, True)
        self.assertIs(actual_delete_event, True)
        self.assertIs(delegate.list_lifecycle_events.return_value, actual_events)
        self.assertIs(history, actual_history)

        delegate.begin_lifecycle_intent.assert_called_once_with(
            "coder",
            action="start",
            operation_id="a" * 32,
            source="cli",
            request_id=None,
            reason="begin",
        )
        delegate.complete_lifecycle_intent.assert_called_once_with(
            "coder",
            action="start",
            operation_id="a" * 32,
            desired_revision=1,
            status=BotStatus.running,
            pid=1234,
            source="cli",
            outcome="success",
            request_id=None,
            reason="complete",
            error_code=None,
            error_message=None,
            started_at=FIXED_NOW,
            ready_at=FIXED_NOW,
            stopped_at=None,
            last_exit_code=None,
            last_error=None,
            last_transition_reason="ready",
            reset_restart=True,
            clear_ready_at=False,
            clear_stopped_at=True,
        )
        delegate.clear_stale_intent.assert_called_once_with(
            "coder",
            action="start",
            operation_id="a" * 32,
            desired_revision=1,
            source="recovery",
            reason="clear",
            request_id=None,
        )
        delegate.audit_log_path.assert_called_once_with()
        delegate.append_audit_event.assert_called_once_with("bot.test", bot_id="coder")
        delegate.upsert_bot.assert_called_once_with(record)
        delegate.upsert_bot_with_event.assert_called_once_with(record, event=event_input)
        delegate.get_bot.assert_called_once_with("coder")
        delegate.list_bots.assert_called_once_with()
        delegate.update_status.assert_called_once_with(
            "coder", BotStatus.running, 1234, reset_restart=True
        )
        lifecycle_kwargs = {
            "started_at": FIXED_NOW,
            "ready_at": FIXED_NOW,
            "stopped_at": None,
            "last_exit_code": 0,
            "last_error": None,
            "last_transition_reason": "ready",
            "reset_restart": True,
            "clear_ready_at": False,
            "clear_stopped_at": True,
        }
        delegate.update_lifecycle_state.assert_called_once_with(
            "coder", BotStatus.running, 1234, **lifecycle_kwargs
        )
        delegate.update_lifecycle_with_event.assert_called_once_with(
            "coder",
            BotStatus.running,
            1234,
            event=event_input,
            **lifecycle_kwargs,
        )
        delegate.update_restart_state.assert_called_once_with(
            "coder",
            status=BotStatus.failed,
            pid=None,
            restart_attempts=2,
            next_restart_at=NEXT_RESTART,
        )
        delegate.update_restart_with_event.assert_called_once_with(
            "coder",
            status=BotStatus.failed,
            pid=None,
            restart_attempts=2,
            next_restart_at=NEXT_RESTART,
            event=event_input,
        )
        delegate.delete_bot.assert_called_once_with("coder")
        delegate.delete_bot_with_event.assert_called_once_with("coder", event=event_input)
        delegate.list_lifecycle_events.assert_called_once_with("coder", 10, 20)
        delegate.history_payload.assert_called_once_with("coder", 10, 20)
        for method_name in PUBLIC_METHODS:
            self.assertEqual(
                inspect.signature(getattr(BotLifecycleStore, method_name)),
                inspect.signature(getattr(StateStore, method_name)),
            )

        def assert_exception_identity(
            method_name: str,
            invoke: Callable[[], object],
        ) -> None:
            error = RuntimeError(f"facade sentinel: {method_name}")
            method = getattr(delegate, method_name)
            method.side_effect = error
            try:
                with self.assertRaises(RuntimeError) as caught:
                    invoke()
                self.assertIs(error, caught.exception)
            finally:
                method.side_effect = None

        exception_cases: tuple[tuple[str, Callable[[], object]], ...] = (
            (
                "begin_lifecycle_intent",
                lambda: facade.begin_lifecycle_intent(
                    "other",
                    action="start",
                    operation_id="c" * 32,
                    source="cli",
                ),
            ),
            ("audit_log_path", facade.audit_log_path),
            (
                "append_audit_event",
                lambda: facade.append_audit_event("bot.test", bot_id="other"),
            ),
            (
                "upsert_bot_with_event",
                lambda: facade.upsert_bot_with_event(record, event=event_input),
            ),
            ("get_bot", lambda: facade.get_bot("other")),
            ("list_bots", facade.list_bots),
            (
                "update_status",
                lambda: facade.update_status("other", BotStatus.failed),
            ),
            ("delete_bot", lambda: facade.delete_bot("other")),
            (
                "list_lifecycle_events",
                lambda: facade.list_lifecycle_events("other", 10, None),
            ),
            (
                "history_payload",
                lambda: facade.history_payload("other", 10, None),
            ),
        )
        for method_name, invoke in exception_cases:
            with self.subTest(exception=method_name):
                assert_exception_identity(method_name, invoke)


if __name__ == "__main__":
    unittest.main()
