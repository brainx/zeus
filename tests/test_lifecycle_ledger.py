from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.lifecycle import LifecycleEvent, LifecycleEventInput, serialize_lifecycle_details
from zeus.models import BotRecord, BotStatus, DesiredState
from zeus.reconciliation import BotReconcileResult, ReconcileOutcome, ReconcileRunStart
from zeus.sanitization import sanitize_details, sanitize_text
from zeus.state import StateStore


def create_v2_database_with_bots(root: Path, *bot_ids: str) -> Path:
    database = root / "zeus.db"
    with closing(sqlite3.connect(database)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (2);
            CREATE TABLE bots (
                bot_id TEXT PRIMARY KEY,
                template_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                profile_path TEXT NOT NULL,
                status TEXT NOT NULL,
                pid INTEGER,
                restart_policy TEXT NOT NULL DEFAULT 'manual',
                restart_backoff_seconds REAL NOT NULL DEFAULT 5.0,
                restart_max_attempts INTEGER NOT NULL DEFAULT 5,
                restart_attempts INTEGER NOT NULL DEFAULT 0,
                next_restart_at TEXT,
                started_at TEXT,
                ready_at TEXT,
                stopped_at TEXT,
                last_exit_code INTEGER,
                last_error TEXT,
                last_transition_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        for index, bot_id in enumerate(bot_ids, start=1):
            timestamp = f"2026-01-01T00:00:0{index}+00:00"
            conn.execute(
                """
                INSERT INTO bots (
                    bot_id, template_id, display_name, profile_path, status, pid,
                    created_at, updated_at
                ) VALUES (?, 'coding-bot', ?, ?, 'running', ?, ?, ?)
                """,
                (bot_id, bot_id.title(), f"/profiles/{bot_id}", index, timestamp, timestamp),
            )
        conn.commit()
    return database


class LifecycleLedgerTests(unittest.TestCase):
    def _event(self, *, bot_id: str = "coder", action: str = "bot.test") -> LifecycleEventInput:
        return LifecycleEventInput(
            bot_id=bot_id,
            operation_id="a" * 32,
            source="cli",
            action=action,
            outcome="success",
            reason="test transition",
        )

    def _record(self, root: Path, *, status: BotStatus = BotStatus.stopped) -> BotRecord:
        return BotRecord(
            bot_id="coder",
            template_id="coding-bot",
            display_name="Coder",
            profile_path=str(root / "profiles" / "coder"),
            status=status,
        )

    def _invoke_atomic_mutation(
        self,
        store: StateStore,
        root: Path,
        mutation: str,
    ) -> LifecycleEvent | bool:
        if mutation == "upsert":
            return store.upsert_bot_with_event(
                self._record(root),
                event=self._event(action="bot.create"),
            )
        if mutation == "lifecycle":
            return store.update_lifecycle_with_event(
                "coder",
                BotStatus.running,
                pid=4321,
                event=self._event(action="bot.start"),
            )
        if mutation == "restart":
            return store.update_restart_with_event(
                "coder",
                status=BotStatus.failed,
                pid=None,
                restart_attempts=1,
                next_restart_at=datetime(2026, 1, 1, tzinfo=UTC),
                event=self._event(action="bot.restart.schedule"),
            )
        if mutation == "delete":
            return store.delete_bot_with_event(
                "coder",
                event=self._event(action="bot.delete"),
            )
        raise AssertionError(f"unknown mutation: {mutation}")

    def test_v2_migrates_to_v3_with_deterministic_snapshot_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = create_v2_database_with_bots(Path(tmp), "zeta", "alpha")

            StateStore(database).init()

            with closing(sqlite3.connect(database)) as conn:
                conn.row_factory = sqlite3.Row
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                columns = {row[1] for row in conn.execute("PRAGMA table_info(bots)").fetchall()}
                events = conn.execute(
                    """
                    SELECT event_id, bot_id, operation_id, occurred_at, source, action,
                           outcome, status_before, status_after, pid_before, pid_after,
                           reason, details_json
                    FROM lifecycle_events
                    WHERE operation_id = 'migration-v3'
                    ORDER BY event_id
                    """
                ).fetchall()
                desired_events = conn.execute(
                    """
                    SELECT event_id, bot_id FROM lifecycle_events
                    WHERE operation_id = 'migration-v5' ORDER BY event_id
                    """
                ).fetchall()
                projections = conn.execute(
                    "SELECT bot_id, last_event_id FROM bots ORDER BY bot_id"
                ).fetchall()

            self.assertEqual(6, version)
            self.assertIn("last_event_id", columns)
            self.assertEqual(["alpha", "zeta"], [row["bot_id"] for row in events])
            self.assertEqual(
                ["migration.snapshot", "migration.snapshot"],
                [row["action"] for row in events],
            )
            self.assertEqual(
                ["migration-v3", "migration-v3"],
                [row["operation_id"] for row in events],
            )
            self.assertEqual(["migration", "migration"], [row["source"] for row in events])
            self.assertEqual(["success", "success"], [row["outcome"] for row in events])
            self.assertEqual(["running", "running"], [row["status_before"] for row in events])
            self.assertEqual(["running", "running"], [row["status_after"] for row in events])
            self.assertEqual([1, 2], [row["event_id"] for row in events])
            self.assertEqual(
                {row["bot_id"]: row["event_id"] for row in desired_events},
                {row["bot_id"]: row["last_event_id"] for row in projections},
            )
            self.assertTrue(all(json.loads(row["details_json"]) == {} for row in events))

    def test_v3_schema_matches_contract_and_events_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = create_v2_database_with_bots(Path(tmp), "coder")
            StateStore(database).init()

            with closing(sqlite3.connect(database)) as conn:
                columns = [row[1] for row in conn.execute("PRAGMA table_info(lifecycle_events)")]
                indexes = {
                    row[1] for row in conn.execute("PRAGMA index_list(lifecycle_events)").fetchall()
                }
                foreign_keys = conn.execute("PRAGMA foreign_key_list(lifecycle_events)").fetchall()
                self.assertEqual(
                    [
                        "event_id",
                        "bot_id",
                        "operation_id",
                        "request_id",
                        "occurred_at",
                        "source",
                        "action",
                        "outcome",
                        "status_before",
                        "status_after",
                        "pid_before",
                        "pid_after",
                        "reason",
                        "error_code",
                        "error_message",
                        "details_json",
                    ],
                    columns,
                )
                self.assertEqual(
                    {"idx_lifecycle_events_bot", "idx_lifecycle_events_operation"},
                    indexes,
                )
                self.assertEqual([], foreign_keys)
                with self.assertRaises(sqlite3.DatabaseError):
                    conn.execute(
                        "UPDATE lifecycle_events SET action = 'changed' WHERE event_id = 1"
                    )
                with self.assertRaises(sqlite3.DatabaseError):
                    conn.execute("DELETE FROM lifecycle_events WHERE event_id = 1")

    def test_v2_migration_failure_rolls_back_schema_version_data_and_ddl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = create_v2_database_with_bots(Path(tmp), "coder")
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    """
                    CREATE TRIGGER inject_v3_migration_failure
                    BEFORE UPDATE ON bots
                    BEGIN
                        SELECT RAISE(ABORT, 'injected migration failure');
                    END
                    """
                )
                conn.commit()

            with self.assertRaisesRegex(sqlite3.DatabaseError, "injected migration failure"):
                StateStore(database).init()

            with closing(sqlite3.connect(database)) as conn:
                version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
                row = conn.execute(
                    "SELECT status, pid, updated_at FROM bots WHERE bot_id = 'coder'"
                ).fetchone()
                columns = {item[1] for item in conn.execute("PRAGMA table_info(bots)").fetchall()}
                lifecycle_table = conn.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type = 'table' AND name = 'lifecycle_events'
                    """
                ).fetchone()

            self.assertEqual(2, version)
            self.assertEqual(("running", 1, "2026-01-01T00:00:01+00:00"), row)
            self.assertNotIn("last_event_id", columns)
            self.assertIsNone(lifecycle_table)

    def test_newer_schema_is_rejected_without_changes(self) -> None:
        for operation in ("init", "migrate"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                database = create_v2_database_with_bots(Path(tmp), "coder")
                with closing(sqlite3.connect(database)) as conn:
                    conn.execute("UPDATE schema_version SET version = 7")
                    conn.commit()
                    before = list(conn.iterdump())
                    self.assertEqual("delete", conn.execute("PRAGMA journal_mode").fetchone()[0])

                with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                    getattr(StateStore(database), operation)()

                with closing(sqlite3.connect(database)) as conn:
                    self.assertEqual("delete", conn.execute("PRAGMA journal_mode").fetchone()[0])
                    self.assertEqual(before, list(conn.iterdump()))

    def test_history_is_newest_first_uses_exclusive_cursor_and_survives_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = create_v2_database_with_bots(Path(tmp), "coder")
            store = StateStore(database)
            store.init()
            with closing(sqlite3.connect(database)) as conn:
                for action in ("bot.start", "bot.ready", "bot.stop"):
                    conn.execute(
                        """
                        INSERT INTO lifecycle_events (
                            bot_id, operation_id, occurred_at, source, action, outcome
                        ) VALUES ('coder', 'operation', '2026-01-02T00:00:00+00:00',
                                  'cli', ?, 'success')
                        """,
                        (action,),
                    )
                conn.execute("DELETE FROM bots WHERE bot_id = 'coder'")
                conn.commit()

            first_page = store.list_lifecycle_events("coder", limit=2, before=None)
            second_page = store.list_lifecycle_events(
                "coder", limit=2, before=first_page[-1].event_id
            )

            self.assertEqual(["bot.stop", "bot.ready"], [event.action for event in first_page])
            self.assertEqual(
                ["bot.start", "migration.desired_state_snapshot"],
                [event.action for event in second_page],
            )
            self.assertGreater(first_page[0].event_id, first_page[1].event_id)
            self.assertTrue(
                set(event.event_id for event in first_page).isdisjoint(
                    event.event_id for event in second_page
                )
            )

    def test_history_rejects_unsafe_limits_and_cursors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")
            store.init()
            for invalid_limit in (True, 0, 1001, 1.5, "1"):
                with self.subTest(limit=invalid_limit), self.assertRaises((TypeError, ValueError)):
                    store.list_lifecycle_events(
                        "coder",
                        limit=invalid_limit,  # type: ignore[arg-type]
                        before=None,
                    )
            for invalid_before in (True, 0, -1, 1.5, "1"):
                with (
                    self.subTest(before=invalid_before),
                    self.assertRaises((TypeError, ValueError)),
                ):
                    store.list_lifecycle_events(
                        "coder",
                        limit=50,
                        before=invalid_before,  # type: ignore[arg-type]
                    )

    def test_pending_intent_projection_and_event_are_committed_as_one_fence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(self._record(root))

            pending = store.begin_lifecycle_intent(
                "coder",
                action="start",
                operation_id="a" * 32,
                source="api",
                request_id="b" * 32,
                reason="gateway start requested",
            )

            history = store.list_lifecycle_events("coder", limit=10, before=None)
            self.assertEqual(1, len(history))
            intent = history[0]
            with closing(sqlite3.connect(store.database_path)) as conn:
                last_event_id = conn.execute(
                    "SELECT last_event_id FROM bots WHERE bot_id = 'coder'"
                ).fetchone()[0]
            self.assertEqual(intent.event_id, last_event_id)
            self.assertEqual(DesiredState.running, pending.desired_state)
            self.assertEqual(1, pending.desired_revision)
            self.assertEqual("a" * 32, pending.pending_operation_id)
            self.assertEqual("start", pending.pending_action)
            self.assertEqual(
                {
                    "bot_id": "coder",
                    "operation_id": "a" * 32,
                    "request_id": "b" * 32,
                    "source": "api",
                    "action": "bot.start.intent",
                    "outcome": "pending",
                    "status_before": "stopped",
                    "status_after": "stopped",
                    "pid_before": None,
                    "pid_after": None,
                    "reason": "gateway start requested",
                    "error_code": None,
                    "error_message": None,
                    "details": {
                        "action": "start",
                        "desired_revision": 1,
                        "desired_state": "running",
                    },
                },
                {
                    "bot_id": intent.bot_id,
                    "operation_id": intent.operation_id,
                    "request_id": intent.request_id,
                    "source": intent.source,
                    "action": intent.action,
                    "outcome": intent.outcome,
                    "status_before": intent.status_before,
                    "status_after": intent.status_after,
                    "pid_before": intent.pid_before,
                    "pid_after": intent.pid_after,
                    "reason": intent.reason,
                    "error_code": intent.error_code,
                    "error_message": intent.error_message,
                    "details": dict(intent.details),
                },
            )

    def test_event_input_is_frozen_and_recursively_redacts_bounded_details(self) -> None:
        nested_items = [{"visible": "value"}]
        nested: dict[str, object] = {
            "safe": "original",
            "items": nested_items,
        }
        event = LifecycleEventInput(
            bot_id="coder",
            operation_id="operation",
            source="cli",
            action="bot.start",
            outcome="success",
            details={
                "safe": "x" * 10_000,
                "api_key": "plain-secret",
                "nested": {
                    "authorization": "Bearer token-secret",
                    "message": "TOKEN=embedded-secret",
                    "request_body": {"field": "raw-body"},
                    "client_address": "10.0.0.1:1234",
                    "traceback": "secret stack trace",
                },
                "mutable": nested,
            },
        )

        nested["safe"] = "changed-after-construction"
        nested_items[0]["visible"] = "changed-after-construction"
        serialized = serialize_lifecycle_details(event.details)
        self.assertLessEqual(len(serialized), 8192)
        for secret in (
            "plain-secret",
            "token-secret",
            "embedded-secret",
            "raw-body",
            "10.0.0.1",
            "secret stack trace",
        ):
            self.assertNotIn(secret, serialized)
        self.assertIn("[redacted]", serialized)
        self.assertNotIn("changed-after-construction", serialized)
        with self.assertRaises(FrozenInstanceError):
            event.action = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            event.details["new"] = "value"  # type: ignore[index]
        with self.assertRaises(TypeError):
            event.details["mutable"]["safe"] = "changed"  # type: ignore[index]
        with self.assertRaises(TypeError):
            event.details["mutable"]["items"][0]["visible"] = "changed"  # type: ignore[index]

    def test_event_details_normalize_forbidden_names_and_are_json_compatible(self) -> None:
        secrets = {
            "authorizationHeader": "authorization-secret",
            "RequestBody": "request-secret",
            "response-body": "response-secret",
            "raw query": "raw-query-secret",
            "queryString": "query-secret",
            "forwardedFor": "forwarded-secret",
            "xForwardedFor": "x-forwarded-secret",
            "clientAddress": "address-secret",
            "clientIp": "ip-secret",
            "client.port": "port-secret",
            "remoteAddr": "remote-secret",
            "traceback": "traceback-secret",
            "exceptionTrace": "exception-secret",
            "idempotencyKey": "idempotency-secret",
            "apiKey": "api-secret",
            "accessToken": "token-secret",
            "clientSecret": "client-secret",
            "db_password": "password-secret",
        }
        event = LifecycleEventInput(
            bot_id="coder",
            operation_id="operation",
            source="api",
            action="bot.start",
            outcome="success",
            details={"outer": {"items": [secrets]}},
        )

        serialized = serialize_lifecycle_details(event.details)
        for secret in secrets.values():
            self.assertNotIn(secret, serialized)
        self.assertEqual(len(secrets), serialized.count("[redacted]"))

        stored = LifecycleEvent(
            event_id=1,
            bot_id="coder",
            operation_id="operation",
            request_id=None,
            occurred_at=datetime.now(UTC),
            source="api",
            action="bot.start",
            outcome="success",
            status_before="stopped",
            status_after="running",
            pid_before=None,
            pid_after=123,
            reason="started",
            error_code=None,
            error_message=None,
            details={"nested": {"items": ["value"]}},
        )
        with self.assertRaises(TypeError):
            stored.details["nested"]["items"][0] = "changed"  # type: ignore[index]
        self.assertEqual(
            {"nested": {"items": ["value"]}},
            stored.to_dict()["details"],
        )
        json.dumps(stored.to_dict(), sort_keys=True)

    def test_sanitizer_bounds_cycles_nonfinite_numbers_and_free_text_secrets(self) -> None:
        secret = "lifecycle-sentinel-9a21"
        cycle: list[object] = []
        cycle.append(cycle)
        deep: object = "leaf"
        for _ in range(12):
            deep = {"next": deep}

        sanitized = sanitize_details(
            {
                "api_key": secret,
                "messages": [
                    f"API_KEY={secret}",
                    f"authorization=Bearer {secret}",
                    f"request failed with Bearer {secret}",
                ],
                "cycle": cycle,
                "deep": deep,
                "nan": float("nan"),
                "positive_infinity": float("inf"),
                "negative_infinity": float("-inf"),
            }
        )
        encoded = json.dumps(
            sanitized,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        self.assertFalse(secret.encode("utf-8") in encoded)
        self.assertLessEqual(len(encoded), 8192)
        self.assertIsNone(sanitized["nan"])  # type: ignore[index]
        self.assertIsNone(sanitized["positive_infinity"])  # type: ignore[index]
        self.assertIsNone(sanitized["negative_infinity"])  # type: ignore[index]
        self.assertIn(b"[cycle]", encoded)
        self.assertIn(b"[truncated]", encoded)

        oversized = json.dumps(
            sanitize_details({"message": "Δ" * 20_000}),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        self.assertLessEqual(len(oversized), 8192)

        bounded_collection = sanitize_details({"items": list(range(1_000))})
        self.assertLessEqual(len(bounded_collection["items"]), 64)  # type: ignore[index]

    def test_sanitizer_redacts_values_for_oversized_sensitive_keys(self) -> None:
        secret = "long-key-sentinel-cb30"
        sanitized = sanitize_details({f"{'x' * 256}_api_key": secret})
        encoded = json.dumps(sanitized, allow_nan=False).encode("utf-8")

        self.assertFalse(secret.encode("utf-8") in encoded)

    def test_sanitizer_never_invokes_hostile_string_or_repr_methods(self) -> None:
        class Hostile:
            def __str__(self) -> str:
                raise AssertionError("string conversion invoked")

            def __repr__(self) -> str:
                raise AssertionError("representation invoked")

        class HostileString(str):
            def __str__(self) -> str:
                raise AssertionError("string conversion invoked")

            def __repr__(self) -> str:
                raise AssertionError("representation invoked")

        hostile_key = Hostile()
        hostile_value = Hostile()

        sanitized = sanitize_details(
            {
                "value": hostile_value,
                "text": HostileString("TOKEN=hostile-string-sentinel"),
                hostile_key: "untrusted key value",
            }
        )

        self.assertEqual("[unsupported]", sanitized["value"])  # type: ignore[index]
        self.assertEqual("[unsupported]", sanitized["text"])  # type: ignore[index]
        json.dumps(sanitized, allow_nan=False)

    def test_lifecycle_text_fields_are_redacted_before_sqlite_persistence(self) -> None:
        secret = "event-sentinel-84c2"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            event = LifecycleEventInput(
                bot_id="coder",
                operation_id="a" * 32,
                source="cli",
                action="bot.start",
                outcome="failure",
                reason=f"readiness failed with Bearer {secret}",
                error_code="readiness_failed",
                error_message=f"cleanup failed: API_KEY={secret}",
            )

            store.upsert_bot_with_event(self._record(root), event=event)

            with closing(sqlite3.connect(store.database_path)) as conn:
                row = conn.execute(
                    "SELECT reason, error_message, details_json FROM lifecycle_events"
                ).fetchone()
            assert row is not None
            persisted = "\n".join(str(value) for value in row if value is not None)
            self.assertFalse(secret in persisted)

    def test_authorization_credentials_are_redacted_from_all_persistence_sinks(self) -> None:
        credentials = (
            "basic-credential-sentinel-47d1",
            "digest-credential-sentinel-8a20",
            "custom-credential-sentinel-53fe",
        )
        messages = (
            f"Authorization: Basic {credentials[0]}",
            f'authorization=Digest username="operator", response="{credentials[1]}"',
            f"Authorization: CustomScheme {credentials[2]}",
        )
        started_at = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            event = LifecycleEventInput(
                bot_id="coder",
                operation_id="a" * 32,
                source="cli",
                action="bot.start",
                outcome="failure",
                reason=messages[0],
                error_code="authorization_failed",
                error_message=messages[1],
                details={"message": messages[2]},
            )
            store.upsert_bot_with_event(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / "profiles" / "coder"),
                    last_error=messages[0],
                    last_transition_reason=messages[1],
                ),
                event=event,
            )
            store.append_audit_event(
                "bot.authorization_failed",
                cleanup_errors=list(messages),
            )
            run = ReconcileRunStart(
                run_id="authorization-sanitization",
                scope="fleet",
                requested_bot_id=None,
                source="cli",
                force=False,
                reset_restart=False,
                started_at=started_at,
            )
            result = BotReconcileResult(
                bot_id="coder",
                outcome=ReconcileOutcome.error,
                desired_state="running",
                observed_status="failed",
                pid=None,
                action="inspect",
                message="; ".join(messages),
                error_code="authorization_failed",
                event_id=None,
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
            )
            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)

            with closing(sqlite3.connect(store.database_path)) as conn:
                lifecycle_row = conn.execute(
                    "SELECT reason, error_message, details_json FROM lifecycle_events"
                ).fetchone()
                bot_row = conn.execute(
                    "SELECT last_error, last_transition_reason FROM bots WHERE bot_id = 'coder'"
                ).fetchone()
                reconcile_row = conn.execute(
                    "SELECT message FROM reconcile_results WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()
            assert lifecycle_row is not None
            assert bot_row is not None
            assert reconcile_row is not None
            observed = (
                *(sanitize_text(message) for message in messages),
                *lifecycle_row,
                *bot_row,
                *reconcile_row,
                result.message,
                store.audit_log_path().read_text(encoding="utf-8"),
            )
            for credential in credentials:
                self.assertFalse(
                    any(credential in value for value in observed if isinstance(value, str))
                )

    def test_authorization_label_variants_and_folded_credentials_are_redacted(self) -> None:
        credentials = tuple(f"authorization-variant-sentinel-{index:02d}" for index in range(12))
        messages = (
            f"Authorization Header: Basic {credentials[0]}",
            f'authorization_header=Digest response="{credentials[1]}"',
            f"Authorization Headers: CustomScheme {credentials[2]}",
            f"authorizationHeaders=Bearer {credentials[3]}",
            f"authorization-header: Basic {credentials[4]}",
            f'authorization.headers=Digest response="{credentials[5]}"',
            f"authorizationHeader=CustomScheme {credentials[6]}",
            f"authorization/header: Basic {credentials[7]}",
            f"Authorization: Basic\r\n  {credentials[8]}",
            f'Authorization Header: Digest\n\tresponse="{credentials[9]}"',
            f"authorization_headers=CustomScheme\r\n  {credentials[10]}",
            f"authorizationHeaders: Bearer\n\t{credentials[11]}",
        )
        combined = "\nnext authorization case\n".join(messages)
        started_at = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            event = LifecycleEventInput(
                bot_id="coder",
                operation_id="b" * 32,
                source="cli",
                action="bot.start",
                outcome="failure",
                reason=combined,
                error_code="authorization_failed",
                error_message=combined,
                details={"message": combined},
            )
            store.upsert_bot_with_event(
                BotRecord(
                    bot_id="coder",
                    template_id="coding-bot",
                    display_name="Coder",
                    profile_path=str(root / "profiles" / "coder"),
                    last_error=combined,
                    last_transition_reason=combined,
                ),
                event=event,
            )
            store.append_audit_event(
                "bot.authorization_failed",
                cleanup_errors=list(messages),
            )
            run = ReconcileRunStart(
                run_id="authorization-variant-sanitization",
                scope="fleet",
                requested_bot_id=None,
                source="cli",
                force=False,
                reset_restart=False,
                started_at=started_at,
            )
            result = BotReconcileResult(
                bot_id="coder",
                outcome=ReconcileOutcome.error,
                desired_state="running",
                observed_status="failed",
                pid=None,
                action="inspect",
                message=combined,
                error_code="authorization_failed",
                event_id=None,
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
            )
            store.begin_reconcile_run(run)
            store.append_reconcile_result(run.run_id, result)

            with closing(sqlite3.connect(store.database_path)) as conn:
                lifecycle_row = conn.execute(
                    "SELECT reason, error_message, details_json FROM lifecycle_events"
                ).fetchone()
                bot_row = conn.execute(
                    "SELECT last_error, last_transition_reason FROM bots WHERE bot_id = 'coder'"
                ).fetchone()
                reconcile_row = conn.execute(
                    "SELECT message FROM reconcile_results WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()
            assert lifecycle_row is not None
            assert bot_row is not None
            assert reconcile_row is not None
            observed_by_sink = {
                "direct": tuple(sanitize_text(message) for message in messages),
                "lifecycle": lifecycle_row,
                "bot_projection": bot_row,
                "reconciliation": (*reconcile_row, result.message),
                "audit": (store.audit_log_path().read_text(encoding="utf-8"),),
            }
            for case_index, credential in enumerate(credentials):
                for sink_name, observed in observed_by_sink.items():
                    with self.subTest(case=case_index, sink=sink_name):
                        self.assertFalse(
                            any(credential in value for value in observed if isinstance(value, str))
                        )

    def test_audit_non_bmp_event_fallback_is_strictly_byte_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "zeus.db")

            store.append_audit_event(chr(0x1F512) * 2_048, message="ordinary")

            line = store.audit_log_path().read_bytes()
            self.assertLessEqual(len(line), 8192)
            self.assertEqual(1, len(line.splitlines()))
            self.assertTrue(json.loads(line)["truncated"])

    def test_upsert_bot_with_event_rolls_back_projection_when_event_insert_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()

            with (
                patch.object(
                    store,
                    "_insert_lifecycle_event",
                    side_effect=sqlite3.Error("boom"),
                ),
                self.assertRaisesRegex(sqlite3.Error, "boom"),
            ):
                store.upsert_bot_with_event(self._record(root), event=self._event())

            self.assertIsNone(store.get_bot("coder"))
            self.assertEqual([], store.list_lifecycle_events("coder", limit=50, before=None))

    def test_update_lifecycle_with_event_rolls_back_when_event_insert_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(self._record(root))

            with (
                patch.object(
                    store,
                    "_insert_lifecycle_event",
                    side_effect=sqlite3.Error("boom"),
                ),
                self.assertRaisesRegex(sqlite3.Error, "boom"),
            ):
                store.update_lifecycle_with_event(
                    "coder",
                    BotStatus.running,
                    pid=4321,
                    event=self._event(action="bot.start"),
                )

            record = store.get_bot("coder")
            assert record is not None
            self.assertEqual(BotStatus.stopped, record.status)
            self.assertIsNone(record.pid)
            self.assertEqual([], store.list_lifecycle_events("coder", limit=50, before=None))

    def test_update_restart_with_event_rolls_back_projection_when_event_insert_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(self._record(root))

            with (
                patch.object(
                    store,
                    "_insert_lifecycle_event",
                    side_effect=sqlite3.Error("boom"),
                ),
                self.assertRaisesRegex(sqlite3.Error, "boom"),
            ):
                store.update_restart_with_event(
                    "coder",
                    status=BotStatus.failed,
                    pid=None,
                    restart_attempts=1,
                    next_restart_at=datetime(2026, 1, 1, tzinfo=UTC),
                    event=self._event(action="bot.restart.schedule"),
                )

            record = store.get_bot("coder")
            assert record is not None
            self.assertEqual(BotStatus.stopped, record.status)
            self.assertEqual(0, record.restart_attempts)
            self.assertIsNone(record.next_restart_at)
            self.assertEqual([], store.list_lifecycle_events("coder", limit=50, before=None))

    def test_delete_bot_with_event_rolls_back_projection_when_event_insert_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            store.upsert_bot(self._record(root))

            with (
                patch.object(
                    store,
                    "_insert_lifecycle_event",
                    side_effect=sqlite3.Error("boom"),
                ),
                self.assertRaisesRegex(sqlite3.Error, "boom"),
            ):
                store.delete_bot_with_event("coder", event=self._event(action="bot.delete"))

            self.assertIsNotNone(store.get_bot("coder"))
            self.assertEqual([], store.list_lifecycle_events("coder", limit=50, before=None))

    def test_atomic_mutations_roll_back_when_event_materialization_fails(self) -> None:
        for mutation in ("upsert", "lifecycle", "restart", "delete"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = StateStore(root / "zeus.db")
                store.init()
                if mutation != "upsert":
                    store.upsert_bot(self._record(root))

                with (
                    patch.object(
                        store,
                        "_row_to_lifecycle_event",
                        side_effect=sqlite3.Error("materialization failed"),
                    ),
                    self.assertRaisesRegex(sqlite3.Error, "materialization failed"),
                ):
                    self._invoke_atomic_mutation(store, root, mutation)

                record = store.get_bot("coder")
                if mutation == "upsert":
                    self.assertIsNone(record)
                else:
                    assert record is not None
                    self.assertEqual(BotStatus.stopped, record.status)
                    self.assertIsNone(record.pid)
                    self.assertEqual(0, record.restart_attempts)
                    self.assertIsNone(record.next_restart_at)
                self.assertEqual([], store.list_lifecycle_events("coder", limit=50, before=None))

    def test_atomic_mutations_ignore_post_commit_audit_failures(self) -> None:
        expected_actions = {
            "upsert": "bot.create",
            "lifecycle": "bot.start",
            "restart": "bot.restart.schedule",
            "delete": "bot.delete",
        }
        for mutation in ("upsert", "lifecycle", "restart", "delete"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = StateStore(root / "zeus.db")
                store.init()
                if mutation != "upsert":
                    store.upsert_bot(self._record(root))

                with patch.object(
                    store,
                    "_append_lifecycle_audit",
                    side_effect=RuntimeError("audit failed"),
                ):
                    result = self._invoke_atomic_mutation(store, root, mutation)

                if mutation == "delete":
                    self.assertIs(result, True)
                    self.assertIsNone(store.get_bot("coder"))
                else:
                    self.assertIsInstance(result, LifecycleEvent)
                    self.assertEqual(expected_actions[mutation], result.action)
                    self.assertIsNotNone(store.get_bot("coder"))
                events = store.list_lifecycle_events("coder", limit=50, before=None)
                self.assertEqual([expected_actions[mutation]], [event.action for event in events])

    def test_atomic_mutations_advance_last_event_and_delete_preserves_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()

            created = store.upsert_bot_with_event(
                self._record(root),
                event=self._event(action="bot.create"),
            )
            started = store.update_lifecycle_with_event(
                "coder",
                BotStatus.running,
                pid=4321,
                event=self._event(action="bot.start"),
            )
            scheduled = store.update_restart_with_event(
                "coder",
                status=BotStatus.failed,
                pid=None,
                restart_attempts=1,
                next_restart_at=datetime(2026, 1, 1, tzinfo=UTC),
                event=self._event(action="bot.restart.schedule"),
            )

            with closing(sqlite3.connect(store.database_path)) as conn:
                last_event_id = conn.execute(
                    "SELECT last_event_id FROM bots WHERE bot_id = 'coder'"
                ).fetchone()[0]
            self.assertEqual(scheduled.event_id, last_event_id)
            self.assertEqual((None, "stopped"), (created.status_before, created.status_after))
            self.assertEqual(
                ("stopped", "running", None, 4321),
                (
                    started.status_before,
                    started.status_after,
                    started.pid_before,
                    started.pid_after,
                ),
            )

            store.delete_bot_with_event("coder", event=self._event(action="bot.delete"))

            self.assertIsNone(store.get_bot("coder"))
            history = store.list_lifecycle_events("coder", limit=50, before=None)
            self.assertEqual(4, len(history))
            self.assertEqual("bot.delete", history[0].action)
            self.assertEqual("failed", history[0].status_before)
            self.assertIsNone(history[0].status_after)


if __name__ == "__main__":
    unittest.main()
