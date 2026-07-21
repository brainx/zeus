from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager, closing
from pathlib import Path
from typing import Protocol

from zeus.lifecycle import serialize_lifecycle_details

SCHEMA_VERSION = 6


class _SchemaDatabase(Protocol):
    def connect(self) -> sqlite3.Connection: ...

    def immediate(self) -> AbstractContextManager[sqlite3.Connection]: ...


def _assert_schema_compatible(conn: sqlite3.Connection) -> None:
    table = conn.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'schema_version'
        """
    ).fetchone()
    if table is None:
        return
    row = conn.execute("SELECT version FROM schema_version ORDER BY rowid LIMIT 1").fetchone()
    if row is not None and int(row["version"]) > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {int(row['version'])} is newer than supported "
            f"version {SCHEMA_VERSION}"
        )


def _preflight_schema_compatibility(database_path: Path) -> None:
    if not database_path.exists():
        return
    uri = f"{database_path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        _assert_schema_compatible(conn)


class SchemaManager:
    def __init__(self, database: _SchemaDatabase) -> None:
        self._database = database

    def init(self) -> None:
        with self._database.immediate() as conn:
            self._create_bots_table(conn)
            self._migrate(conn)

    def migrate(self) -> None:
        with self._database.immediate() as conn:
            self._migrate(conn)

    def _create_bots_table(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bots (
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
                last_event_id INTEGER,
                desired_state TEXT NOT NULL DEFAULT 'stopped'
                    CHECK (desired_state IN ('running', 'stopped')),
                desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision >= 0),
                desired_updated_at TEXT,
                pending_operation_id TEXT,
                pending_action TEXT CHECK (
                    pending_action IS NULL OR pending_action IN ('start', 'stop', 'restart')
                ),
                pending_since TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (
                    (pending_operation_id IS NULL
                     AND pending_action IS NULL
                     AND pending_since IS NULL)
                    OR
                    (pending_operation_id IS NOT NULL AND pending_action IS NOT NULL
                     AND pending_since IS NOT NULL)
                )
            )
            """
        )

    def _migrate(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            )
            """
        )
        row = conn.execute("SELECT version FROM schema_version ORDER BY rowid LIMIT 1").fetchone()
        current_version = int(row["version"]) if row else 0
        if row is None:
            conn.execute("INSERT INTO schema_version (version) VALUES (0)")
        if current_version > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {current_version} is newer than supported "
                f"version {SCHEMA_VERSION}"
            )
        if current_version < 1:
            self._ensure_restart_schema(conn)
            conn.execute("UPDATE schema_version SET version = ?", (1,))
            current_version = 1
        if current_version < 2:
            self._ensure_lifecycle_schema(conn)
            conn.execute("UPDATE schema_version SET version = ?", (2,))
            current_version = 2
        if current_version < 3:
            self._migrate_v2_to_v3(conn)
            conn.execute("UPDATE schema_version SET version = ?", (3,))
            current_version = 3
        if current_version < 4:
            self._migrate_v3_to_v4(conn)
            conn.execute("UPDATE schema_version SET version = ?", (4,))
            current_version = 4
        if current_version < 5:
            self._migrate_v4_to_v5(conn)
            conn.execute("UPDATE schema_version SET version = ?", (5,))
            current_version = 5
        if current_version < 6:
            self._migrate_v5_to_v6(conn)
            conn.execute("UPDATE schema_version SET version = ?", (6,))

    def _ensure_restart_schema(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(bots)").fetchall()}
        migrations = {
            "restart_policy": (
                "ALTER TABLE bots ADD COLUMN restart_policy TEXT NOT NULL DEFAULT 'manual'"
            ),
            "restart_backoff_seconds": (
                "ALTER TABLE bots ADD COLUMN restart_backoff_seconds REAL NOT NULL DEFAULT 5.0"
            ),
            "restart_max_attempts": (
                "ALTER TABLE bots ADD COLUMN restart_max_attempts INTEGER NOT NULL DEFAULT 5"
            ),
            "restart_attempts": (
                "ALTER TABLE bots ADD COLUMN restart_attempts INTEGER NOT NULL DEFAULT 0"
            ),
            "next_restart_at": "ALTER TABLE bots ADD COLUMN next_restart_at TEXT",
        }
        for column, statement in migrations.items():
            if column not in columns:
                conn.execute(statement)

    def _ensure_lifecycle_schema(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(bots)").fetchall()}
        migrations = {
            "started_at": "ALTER TABLE bots ADD COLUMN started_at TEXT",
            "ready_at": "ALTER TABLE bots ADD COLUMN ready_at TEXT",
            "stopped_at": "ALTER TABLE bots ADD COLUMN stopped_at TEXT",
            "last_exit_code": "ALTER TABLE bots ADD COLUMN last_exit_code INTEGER",
            "last_error": "ALTER TABLE bots ADD COLUMN last_error TEXT",
            "last_transition_reason": ("ALTER TABLE bots ADD COLUMN last_transition_reason TEXT"),
        }
        for column, statement in migrations.items():
            if column not in columns:
                conn.execute(statement)

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(bots)").fetchall()}
        if "last_event_id" not in columns:
            conn.execute("ALTER TABLE bots ADD COLUMN last_event_id INTEGER")
        conn.execute(
            """
            CREATE TABLE lifecycle_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_id TEXT,
                occurred_at TEXT NOT NULL,
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status_before TEXT,
                status_after TEXT,
                pid_before INTEGER,
                pid_after INTEGER,
                reason TEXT NOT NULL DEFAULT '',
                error_code TEXT,
                error_message TEXT,
                details_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_lifecycle_events_bot
            ON lifecycle_events (bot_id, event_id DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_lifecycle_events_operation
            ON lifecycle_events (operation_id, event_id)
            """
        )
        conn.execute(
            """
            CREATE TRIGGER lifecycle_events_reject_update
            BEFORE UPDATE ON lifecycle_events
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle events are immutable');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER lifecycle_events_reject_delete
            BEFORE DELETE ON lifecycle_events
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle events are immutable');
            END
            """
        )

        rows = conn.execute(
            "SELECT bot_id, status, pid, updated_at FROM bots ORDER BY bot_id"
        ).fetchall()
        for row in rows:
            cursor = conn.execute(
                """
                INSERT INTO lifecycle_events (
                    bot_id,
                    operation_id,
                    occurred_at,
                    source,
                    action,
                    outcome,
                    status_before,
                    status_after,
                    pid_before,
                    pid_after,
                    reason,
                    details_json
                ) VALUES (?, 'migration-v3', ?, 'migration', 'migration.snapshot',
                          'success', ?, ?, ?, ?, 'schema v3 snapshot', '{}')
                """,
                (
                    row["bot_id"],
                    row["updated_at"],
                    row["status"],
                    row["status"],
                    row["pid"],
                    row["pid"],
                ),
            )
            conn.execute(
                "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                (cursor.lastrowid, row["bot_id"]),
            )

        invalid_projection = conn.execute(
            """
            SELECT bots.bot_id
            FROM bots
            LEFT JOIN lifecycle_events
              ON lifecycle_events.event_id = bots.last_event_id
             AND lifecycle_events.bot_id = bots.bot_id
            WHERE lifecycle_events.event_id IS NULL
            LIMIT 1
            """
        ).fetchone()
        if invalid_projection is not None:
            raise sqlite3.IntegrityError("lifecycle snapshot invariant failed")

    def _migrate_v3_to_v4(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE idempotency_records (
                key_hash TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('in_progress', 'completed')),
                owner_instance_id TEXT NOT NULL,
                response_status INTEGER NULL,
                response_json TEXT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX idx_idempotency_records_expires
            ON idempotency_records (expires_at)
            """
        )

    def _migrate_v4_to_v5(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(bots)").fetchall()}
        migrations = {
            "desired_state": (
                "ALTER TABLE bots ADD COLUMN desired_state TEXT NOT NULL DEFAULT 'stopped' "
                "CHECK (desired_state IN ('running', 'stopped'))"
            ),
            "desired_revision": (
                "ALTER TABLE bots ADD COLUMN desired_revision INTEGER NOT NULL DEFAULT 0 "
                "CHECK (desired_revision >= 0)"
            ),
            "desired_updated_at": "ALTER TABLE bots ADD COLUMN desired_updated_at TEXT",
            "pending_operation_id": "ALTER TABLE bots ADD COLUMN pending_operation_id TEXT",
            "pending_action": (
                "ALTER TABLE bots ADD COLUMN pending_action TEXT CHECK "
                "(pending_action IS NULL OR pending_action IN ('start', 'stop', 'restart'))"
            ),
            "pending_since": "ALTER TABLE bots ADD COLUMN pending_since TEXT",
        }
        for column, statement in migrations.items():
            if column not in columns:
                conn.execute(statement)

        conn.execute(
            """
            CREATE TRIGGER bots_desired_intent_reject_partial_insert
            BEFORE INSERT ON bots
            WHEN NOT (
                (NEW.pending_operation_id IS NULL AND NEW.pending_action IS NULL
                 AND NEW.pending_since IS NULL)
                OR
                (NEW.pending_operation_id IS NOT NULL AND NEW.pending_action IS NOT NULL
                 AND NEW.pending_since IS NOT NULL)
            )
            BEGIN
                SELECT RAISE(ABORT, 'pending lifecycle intent must be all null or all populated');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER bots_desired_intent_reject_partial_update
            BEFORE UPDATE ON bots
            WHEN NOT (
                (NEW.pending_operation_id IS NULL AND NEW.pending_action IS NULL
                 AND NEW.pending_since IS NULL)
                OR
                (NEW.pending_operation_id IS NOT NULL AND NEW.pending_action IS NOT NULL
                 AND NEW.pending_since IS NOT NULL)
            )
            BEGIN
                SELECT RAISE(ABORT, 'pending lifecycle intent must be all null or all populated');
            END
            """
        )

        conn.execute(
            """
            UPDATE bots
            SET desired_state = CASE
                    WHEN status IN ('running', 'starting') THEN 'running'
                    WHEN status IN ('failed', 'unknown') AND restart_policy = 'on-failure'
                        THEN 'running'
                    ELSE 'stopped'
                END,
                desired_revision = 0,
                desired_updated_at = updated_at,
                pending_operation_id = NULL,
                pending_action = NULL,
                pending_since = NULL
            """
        )

        rows = conn.execute(
            """
            SELECT bot_id, status, pid, desired_state, desired_revision, desired_updated_at
            FROM bots ORDER BY bot_id
            """
        ).fetchall()
        for row in rows:
            details = serialize_lifecycle_details(
                {
                    "desired_state": str(row["desired_state"]),
                    "desired_revision": int(row["desired_revision"]),
                }
            )
            cursor = conn.execute(
                """
                INSERT INTO lifecycle_events (
                    bot_id, operation_id, occurred_at, source, action, outcome,
                    status_before, status_after, pid_before, pid_after, reason, details_json
                ) VALUES (?, 'migration-v5', ?, 'migration',
                          'migration.desired_state_snapshot', 'success', ?, ?, ?, ?,
                          'schema v5 desired-state snapshot', ?)
                """,
                (
                    row["bot_id"],
                    row["desired_updated_at"],
                    row["status"],
                    row["status"],
                    row["pid"],
                    row["pid"],
                    details,
                ),
            )
            conn.execute(
                "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                (cursor.lastrowid, row["bot_id"]),
            )

        invalid_projection = conn.execute(
            """
            SELECT bots.bot_id
            FROM bots
            LEFT JOIN lifecycle_events
              ON lifecycle_events.event_id = bots.last_event_id
             AND lifecycle_events.bot_id = bots.bot_id
            WHERE lifecycle_events.event_id IS NULL
            LIMIT 1
            """
        ).fetchone()
        if invalid_projection is not None:
            raise sqlite3.IntegrityError("desired-state snapshot invariant failed")

    def _migrate_v5_to_v6(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE reconcile_runs (
                run_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL CHECK (scope IN ('fleet', 'bot')),
                requested_bot_id TEXT,
                source TEXT NOT NULL,
                force INTEGER NOT NULL CHECK (force IN (0, 1)),
                reset_restart INTEGER NOT NULL CHECK (reset_restart IN (0, 1)),
                started_at TEXT NOT NULL,
                finished_at TEXT,
                outcome TEXT NOT NULL CHECK (
                    outcome IN ('running', 'succeeded', 'completed_with_errors', 'interrupted')
                ),
                total INTEGER NOT NULL DEFAULT 0 CHECK (total >= 0),
                healthy_count INTEGER NOT NULL DEFAULT 0 CHECK (healthy_count >= 0),
                changed_count INTEGER NOT NULL DEFAULT 0 CHECK (changed_count >= 0),
                pending_count INTEGER NOT NULL DEFAULT 0 CHECK (pending_count >= 0),
                action_required_count INTEGER NOT NULL DEFAULT 0
                    CHECK (action_required_count >= 0),
                error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
                skipped_count INTEGER NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
                CHECK (
                    total = healthy_count + changed_count + pending_count
                          + action_required_count + error_count + skipped_count
                ),
                CHECK (
                    (scope = 'fleet' AND requested_bot_id IS NULL)
                    OR (scope = 'bot' AND requested_bot_id IS NOT NULL)
                ),
                CHECK (
                    (outcome = 'running' AND finished_at IS NULL)
                    OR (outcome != 'running' AND finished_at IS NOT NULL)
                ),
                CHECK (finished_at IS NULL OR finished_at >= started_at)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE reconcile_results (
                run_id TEXT NOT NULL,
                bot_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                outcome TEXT NOT NULL CHECK (
                    outcome IN (
                        'healthy', 'changed', 'pending',
                        'action_required', 'error', 'skipped'
                    )
                ),
                desired_state TEXT CHECK (
                    desired_state IS NULL OR desired_state IN ('running', 'stopped')
                ),
                observed_status TEXT CHECK (
                    observed_status IS NULL
                    OR observed_status IN ('stopped', 'starting', 'running', 'failed', 'unknown')
                ),
                pid INTEGER CHECK (pid IS NULL OR pid > 0),
                action TEXT NOT NULL CHECK (length(action) <= 2048),
                message TEXT NOT NULL CHECK (length(message) <= 2048),
                error_code TEXT CHECK (error_code IS NULL OR length(error_code) <= 2048),
                event_id INTEGER CHECK (event_id IS NULL OR event_id > 0),
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                PRIMARY KEY (run_id, bot_id),
                UNIQUE (run_id, ordinal),
                CHECK (finished_at >= started_at),
                FOREIGN KEY (run_id) REFERENCES reconcile_runs(run_id) ON DELETE CASCADE
            )
            """
        )
