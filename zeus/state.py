from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from zeus.idempotency import IdempotencyClaim
from zeus.lifecycle import (
    LifecycleEvent,
    LifecycleEventInput,
    deserialize_lifecycle_details,
    serialize_lifecycle_details,
)
from zeus.models import BotRecord, BotStatus, DesiredState, RestartPolicy
from zeus.private_io import append_private_bytes, nofollow_absolute_path
from zeus.reconciliation import (
    BotReconcileResult,
    PersistedReconcileRun,
    ReconcileOutcome,
    ReconcileRunStart,
    ReconcileRunSummary,
)
from zeus.sanitization import MAX_SANITIZED_JSON_BYTES, sanitize_details, sanitize_text

SCHEMA_VERSION = 6
LIFECYCLE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
LIFECYCLE_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
IDEMPOTENCY_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
IDEMPOTENCY_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
MAX_IDEMPOTENCY_RESPONSE_BYTES = 1_000_000
LIFECYCLE_SOURCES = frozenset({"api", "cli", "migration", "reconcile", "recovery", "system"})
LIFECYCLE_INTENT_ACTIONS = frozenset({"start", "stop", "restart"})
RECONCILE_COUNTER_COLUMNS = {
    ReconcileOutcome.healthy: "healthy_count",
    ReconcileOutcome.changed: "changed_count",
    ReconcileOutcome.pending: "pending_count",
    ReconcileOutcome.action_required: "action_required_count",
    ReconcileOutcome.error: "error_count",
    ReconcileOutcome.skipped: "skipped_count",
}


def _sanitize_optional_persisted_text(value: str | None) -> str | None:
    if value is None:
        return None
    return sanitize_text(value)


def _validate_idempotency_hash(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"idempotency {label} must be a string")
    if IDEMPOTENCY_HASH_RE.fullmatch(value) is None:
        raise ValueError(f"idempotency {label} is invalid")
    return value


def _validate_idempotency_owner(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("idempotency owner must be a string")
    if IDEMPOTENCY_OWNER_RE.fullmatch(value) is None:
        raise ValueError("idempotency owner is invalid")
    return value


def _validate_idempotency_timestamp(value: datetime, label: str) -> str:
    if not isinstance(value, datetime):
        raise TypeError(f"idempotency {label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"idempotency {label} is invalid")
    return value.astimezone(UTC).isoformat()


def _validate_idempotency_status(value: int) -> int:
    if type(value) is not int or not 200 <= value <= 599:
        raise ValueError("idempotency response status is invalid")
    return value


def _reject_non_finite_json(_value: str) -> object:
    raise ValueError("idempotency response JSON is invalid")


def _validate_idempotency_response_json(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("idempotency response JSON must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("idempotency response JSON is invalid") from None
    if len(encoded) > MAX_IDEMPOTENCY_RESPONSE_BYTES:
        raise ValueError("idempotency response JSON is too large")
    try:
        json.loads(value, parse_constant=_reject_non_finite_json)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise ValueError("idempotency response JSON is invalid") from None
    return value


def _parse_idempotency_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise TypeError(f"stored idempotency {label} must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"stored idempotency {label} is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"stored idempotency {label} is invalid")
    normalized = parsed.astimezone(UTC)
    if normalized.isoformat() != value:
        raise ValueError(f"stored idempotency {label} is invalid")
    return normalized


def _validate_reconcile_run_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("reconciliation run_id must be a string")
    if not value or len(value) > 128:
        raise ValueError("reconciliation run_id must be between 1 and 128 characters")
    if any(ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise ValueError("reconciliation run_id must not contain control characters")
    return value


def _serialize_reconcile_timestamp(value: datetime, label: str) -> str:
    if not isinstance(value, datetime):
        raise TypeError(f"reconciliation {label} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"reconciliation {label} must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_reconcile_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise TypeError(f"stored reconciliation {label} must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"stored reconciliation {label} is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"stored reconciliation {label} is invalid")
    normalized = parsed.astimezone(UTC)
    if normalized.isoformat() != value:
        raise ValueError(f"stored reconciliation {label} is not normalized")
    return normalized


def _validate_stored_nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"stored reconciliation {label} must be a non-negative integer")
    return value


def _validate_stored_optional_positive_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise ValueError(f"stored reconciliation {label} must be a positive integer or null")
    return value


def _validate_stored_boolean_flag(value: object, label: str) -> bool:
    if type(value) is not int or value not in {0, 1}:
        raise ValueError(f"stored reconciliation {label} must be exactly 0 or 1")
    return value == 1


@dataclass(frozen=True)
class _ValidatedIdempotencyRow:
    request_hash: str
    state: str
    owner_instance_id: str
    response_status: int | None
    response_json: str | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime


def _validate_idempotency_row(row: sqlite3.Row) -> _ValidatedIdempotencyRow:
    _validate_idempotency_hash(row["key_hash"], "stored key hash")
    request_hash = _validate_idempotency_hash(row["request_hash"], "stored request hash")
    owner = _validate_idempotency_owner(row["owner_instance_id"])
    state = row["state"]
    if state not in {"in_progress", "completed"}:
        raise ValueError("stored idempotency state is invalid")
    created_at = _parse_idempotency_timestamp(row["created_at"], "creation timestamp")
    updated_at = _parse_idempotency_timestamp(row["updated_at"], "update timestamp")
    expires_at = _parse_idempotency_timestamp(row["expires_at"], "expiry timestamp")
    response_status = row["response_status"]
    response_json = row["response_json"]
    if state == "in_progress":
        if created_at > updated_at or updated_at > expires_at:
            raise ValueError("stored in-progress idempotency timestamps are invalid")
        if response_status is not None or response_json is not None:
            raise ValueError("stored in-progress idempotency response is invalid")
        safe_status = None
        safe_json = None
    else:
        if created_at > updated_at or updated_at > expires_at:
            raise ValueError("stored completed idempotency timestamps are invalid")
        if response_status is None or response_json is None:
            raise ValueError("stored completed idempotency response is incomplete")
        safe_status = _validate_idempotency_status(response_status)
        safe_json = _validate_idempotency_response_json(response_json)
    return _ValidatedIdempotencyRow(
        request_hash=request_hash,
        state=state,
        owner_instance_id=owner,
        response_status=safe_status,
        response_json=safe_json,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
    )


def _idempotency_claim_from_row(
    row: sqlite3.Row,
    *,
    request_hash: str,
    owner_instance_id: str,
) -> IdempotencyClaim:
    validated = _validate_idempotency_row(row)
    if validated.request_hash != request_hash:
        return IdempotencyClaim("conflict")
    if validated.state == "completed":
        if validated.response_status is None or validated.response_json is None:
            raise AssertionError("validated completed idempotency response is incomplete")
        return IdempotencyClaim(
            "replay",
            validated.response_status,
            validated.response_json,
        )
    if validated.owner_instance_id == owner_instance_id:
        return IdempotencyClaim("in_progress")
    return IdempotencyClaim("indeterminate")


class StateStore:
    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)

    def connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._preflight_schema_compatibility()
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        try:
            self._assert_schema_compatible(conn)
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except Exception:
            conn.close()
            raise

    def _preflight_schema_compatibility(self) -> None:
        if not self.database_path.exists():
            return
        uri = f"{self.database_path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            self._assert_schema_compatible(conn)

    def _assert_schema_compatible(self, conn: sqlite3.Connection) -> None:
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

    def init(self) -> None:
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._create_bots_table(conn)
                self._migrate(conn)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

    def migrate(self) -> None:
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._migrate(conn)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

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

    def begin_reconcile_run(self, run: ReconcileRunStart) -> None:
        if not isinstance(run, ReconcileRunStart):
            raise TypeError("run must be a ReconcileRunStart")
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO reconcile_runs (
                        run_id,
                        scope,
                        requested_bot_id,
                        source,
                        force,
                        reset_restart,
                        started_at,
                        finished_at,
                        outcome
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'running')
                    """,
                    (
                        run.run_id,
                        run.scope,
                        run.requested_bot_id,
                        run.source,
                        int(run.force),
                        int(run.reset_restart),
                        _serialize_reconcile_timestamp(run.started_at, "start timestamp"),
                    ),
                )
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

    def append_reconcile_result(
        self,
        run_id: str,
        result: BotReconcileResult,
    ) -> None:
        safe_run_id = _validate_reconcile_run_id(run_id)
        if not isinstance(result, BotReconcileResult):
            raise TypeError("result must be a BotReconcileResult")
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                run_row = conn.execute(
                    "SELECT * FROM reconcile_runs WHERE run_id = ?",
                    (safe_run_id,),
                ).fetchone()
                if run_row is None:
                    raise KeyError(f"unknown reconciliation run: {safe_run_id}")
                if run_row["outcome"] != "running":
                    raise RuntimeError("reconciliation run is not running")
                current_run = self._materialize_reconcile_run(conn, safe_run_id)
                if current_run is None:
                    raise sqlite3.IntegrityError("reconciliation run disappeared")
                if current_run.scope == "bot" and result.bot_id != current_run.requested_bot_id:
                    raise ValueError("reconciliation result must match the requested bot")
                if result.started_at < current_run.started_at:
                    raise ValueError("reconciliation result starts before its run")
                if result.event_id is not None:
                    event_row = conn.execute(
                        "SELECT bot_id FROM lifecycle_events WHERE event_id = ?",
                        (result.event_id,),
                    ).fetchone()
                    if event_row is None or event_row["bot_id"] != result.bot_id:
                        raise ValueError(
                            "reconciliation lifecycle event must exist and match the result bot"
                        )
                conn.execute(
                    """
                    INSERT INTO reconcile_results (
                        run_id,
                        bot_id,
                        ordinal,
                        outcome,
                        desired_state,
                        observed_status,
                        pid,
                        action,
                        message,
                        error_code,
                        event_id,
                        started_at,
                        finished_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        safe_run_id,
                        result.bot_id,
                        current_run.total,
                        result.outcome.value,
                        result.desired_state,
                        result.observed_status,
                        result.pid,
                        result.action,
                        result.message,
                        result.error_code,
                        result.event_id,
                        _serialize_reconcile_timestamp(
                            result.started_at,
                            "result start timestamp",
                        ),
                        _serialize_reconcile_timestamp(
                            result.finished_at,
                            "result finish timestamp",
                        ),
                    ),
                )
                cursor = conn.execute(
                    """
                    UPDATE reconcile_runs
                    SET total = total + 1,
                        healthy_count = healthy_count + ?,
                        changed_count = changed_count + ?,
                        pending_count = pending_count + ?,
                        action_required_count = action_required_count + ?,
                        error_count = error_count + ?,
                        skipped_count = skipped_count + ?
                    WHERE run_id = ? AND outcome = 'running'
                    """,
                    (
                        int(result.outcome is ReconcileOutcome.healthy),
                        int(result.outcome is ReconcileOutcome.changed),
                        int(result.outcome is ReconcileOutcome.pending),
                        int(result.outcome is ReconcileOutcome.action_required),
                        int(result.outcome is ReconcileOutcome.error),
                        int(result.outcome is ReconcileOutcome.skipped),
                        safe_run_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.IntegrityError("reconciliation result counter update failed")
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

    def finish_reconcile_run(
        self,
        summary: ReconcileRunSummary,
    ) -> PersistedReconcileRun:
        if not isinstance(summary, ReconcileRunSummary):
            raise TypeError("summary must be a ReconcileRunSummary")
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                run_row = conn.execute(
                    "SELECT * FROM reconcile_runs WHERE run_id = ?",
                    (summary.run_id,),
                ).fetchone()
                if run_row is None:
                    raise KeyError(f"unknown reconciliation run: {summary.run_id}")
                if run_row["outcome"] != "running":
                    raise RuntimeError("reconciliation run is not running")
                if run_row["scope"] != summary.scope:
                    raise RuntimeError("reconciliation summary scope does not match run")
                stored_started_at = _parse_reconcile_timestamp(
                    run_row["started_at"],
                    "run start timestamp",
                )
                if stored_started_at != summary.started_at:
                    raise RuntimeError("reconciliation summary start timestamp does not match run")
                persisted_results = self._reconcile_results_in_transaction(conn, summary.run_id)
                if tuple(summary.results) != persisted_results:
                    raise RuntimeError("persisted reconciliation results do not match summary")
                observed_counts = self._reconcile_counts_from_results(persisted_results)
                stored_counts = self._reconcile_counts_from_run_row(run_row)
                stored_total = _validate_stored_nonnegative_integer(
                    run_row["total"],
                    "total",
                )
                if stored_counts != observed_counts or stored_total != len(persisted_results):
                    raise RuntimeError("persisted reconciliation counters do not match results")
                if dict(summary.counts) != observed_counts or summary.total != len(
                    persisted_results
                ):
                    raise RuntimeError("reconciliation summary counters do not match results")
                if any(result.finished_at > summary.finished_at for result in persisted_results):
                    raise RuntimeError("reconciliation summary finishes before a persisted result")
                cursor = conn.execute(
                    """
                    UPDATE reconcile_runs
                    SET finished_at = ?,
                        outcome = ?,
                        total = ?,
                        healthy_count = ?,
                        changed_count = ?,
                        pending_count = ?,
                        action_required_count = ?,
                        error_count = ?,
                        skipped_count = ?
                    WHERE run_id = ? AND outcome = 'running'
                    """,
                    (
                        _serialize_reconcile_timestamp(
                            summary.finished_at,
                            "finish timestamp",
                        ),
                        summary.outcome,
                        summary.total,
                        summary.counts[ReconcileOutcome.healthy.value],
                        summary.counts[ReconcileOutcome.changed.value],
                        summary.counts[ReconcileOutcome.pending.value],
                        summary.counts[ReconcileOutcome.action_required.value],
                        summary.counts[ReconcileOutcome.error.value],
                        summary.counts[ReconcileOutcome.skipped.value],
                        summary.run_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise sqlite3.IntegrityError("reconciliation run finalization failed")
                finished = self._materialize_reconcile_run(conn, summary.run_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        if finished is None:
            raise sqlite3.IntegrityError("finished reconciliation run is missing")
        return finished

    def interrupt_stale_reconcile_runs(self, *, interrupted_at: datetime) -> int:
        safe_interrupted_at = _serialize_reconcile_timestamp(
            interrupted_at,
            "interruption timestamp",
        )
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    "SELECT * FROM reconcile_runs WHERE outcome = 'running' ORDER BY run_id"
                ).fetchall()
                for row in rows:
                    run_id = str(row["run_id"])
                    current_run = self._materialize_reconcile_run(conn, run_id)
                    if current_run is None:
                        raise sqlite3.IntegrityError("reconciliation run disappeared")
                    if interrupted_at < current_run.started_at:
                        raise ValueError("interruption timestamp precedes a running reconciliation")
                    if any(result.finished_at > interrupted_at for result in current_run.results):
                        raise ValueError(
                            "reconciliation result finishes after the interruption timestamp"
                        )
                    cursor = conn.execute(
                        """
                        UPDATE reconcile_runs
                        SET outcome = 'interrupted', finished_at = ?
                        WHERE run_id = ? AND outcome = 'running'
                        """,
                        (safe_interrupted_at, run_id),
                    )
                    if cursor.rowcount != 1:
                        raise sqlite3.IntegrityError("reconciliation interruption update failed")
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        return len(rows)

    def get_reconcile_run(self, run_id: str) -> PersistedReconcileRun | None:
        safe_run_id = _validate_reconcile_run_id(run_id)
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN")
                run = self._materialize_reconcile_run(conn, safe_run_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        return run

    def _materialize_reconcile_run(
        self,
        conn: sqlite3.Connection,
        run_id: str,
    ) -> PersistedReconcileRun | None:
        row = conn.execute(
            "SELECT * FROM reconcile_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        results = self._reconcile_results_in_transaction(conn, run_id)
        finished_at = row["finished_at"]
        return PersistedReconcileRun(
            run_id=str(row["run_id"]),
            scope=str(row["scope"]),
            requested_bot_id=(
                str(row["requested_bot_id"]) if row["requested_bot_id"] is not None else None
            ),
            source=str(row["source"]),
            force=_validate_stored_boolean_flag(row["force"], "force flag"),
            reset_restart=_validate_stored_boolean_flag(
                row["reset_restart"],
                "reset-restart flag",
            ),
            started_at=_parse_reconcile_timestamp(row["started_at"], "run start timestamp"),
            finished_at=(
                _parse_reconcile_timestamp(finished_at, "run finish timestamp")
                if finished_at is not None
                else None
            ),
            outcome=str(row["outcome"]),
            total=_validate_stored_nonnegative_integer(row["total"], "total"),
            counts=self._reconcile_counts_from_run_row(row),
            results=results,
        )

    def _reconcile_results_in_transaction(
        self,
        conn: sqlite3.Connection,
        run_id: str,
    ) -> tuple[BotReconcileResult, ...]:
        rows = conn.execute(
            "SELECT * FROM reconcile_results WHERE run_id = ? ORDER BY ordinal",
            (run_id,),
        ).fetchall()
        results: list[BotReconcileResult] = []
        for expected_ordinal, row in enumerate(rows):
            ordinal = _validate_stored_nonnegative_integer(row["ordinal"], "result ordinal")
            if ordinal != expected_ordinal:
                raise ValueError("stored reconciliation ordinals are not contiguous")
            bot_id = str(row["bot_id"])
            event_id = _validate_stored_optional_positive_integer(
                row["event_id"],
                "result event id",
            )
            if event_id is not None:
                event_row = conn.execute(
                    "SELECT bot_id FROM lifecycle_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if event_row is None or event_row["bot_id"] != bot_id:
                    raise ValueError(
                        "stored reconciliation lifecycle event does not match the result bot"
                    )
            results.append(
                BotReconcileResult(
                    bot_id=bot_id,
                    outcome=ReconcileOutcome(str(row["outcome"])),
                    desired_state=(
                        str(row["desired_state"]) if row["desired_state"] is not None else None
                    ),
                    observed_status=(
                        str(row["observed_status"]) if row["observed_status"] is not None else None
                    ),
                    pid=_validate_stored_optional_positive_integer(row["pid"], "result pid"),
                    action=str(row["action"]),
                    message=str(row["message"]),
                    error_code=(str(row["error_code"]) if row["error_code"] is not None else None),
                    event_id=event_id,
                    started_at=_parse_reconcile_timestamp(
                        row["started_at"],
                        "result start timestamp",
                    ),
                    finished_at=_parse_reconcile_timestamp(
                        row["finished_at"],
                        "result finish timestamp",
                    ),
                )
            )
        return tuple(results)

    def _reconcile_counts_from_run_row(self, row: sqlite3.Row) -> dict[str, int]:
        return {
            outcome.value: _validate_stored_nonnegative_integer(
                row[column],
                f"{outcome.value} counter",
            )
            for outcome, column in RECONCILE_COUNTER_COLUMNS.items()
        }

    def _reconcile_counts_from_results(
        self,
        results: tuple[BotReconcileResult, ...],
    ) -> dict[str, int]:
        counts = {outcome.value: 0 for outcome in ReconcileOutcome}
        for result in results:
            counts[result.outcome.value] += 1
        return counts

    def claim_idempotency(
        self,
        *,
        key_hash: str,
        request_hash: str,
        owner_instance_id: str,
        expires_at: datetime,
        max_records: int = 10_000,
    ) -> IdempotencyClaim:
        safe_key_hash = _validate_idempotency_hash(key_hash, "key hash")
        safe_request_hash = _validate_idempotency_hash(request_hash, "request hash")
        safe_owner = _validate_idempotency_owner(owner_instance_id)
        safe_expiry = _validate_idempotency_timestamp(expires_at, "expiry timestamp")
        if type(max_records) is not int or not 1 <= max_records <= 1_000_000:
            raise ValueError("idempotency capacity is invalid")
        current_time = datetime.now(UTC)
        if datetime.fromisoformat(safe_expiry) < current_time:
            raise ValueError("idempotency expiry timestamp is invalid")
        now = current_time.isoformat()

        try:
            conn = self.connect()
        except (OSError, sqlite3.Error):
            return IdempotencyClaim("unavailable")
        with closing(conn):
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM idempotency_records WHERE key_hash = ?",
                    (safe_key_hash,),
                ).fetchone()
                if row is not None:
                    validated = _validate_idempotency_row(row)
                    reclaimable = validated.expires_at <= current_time and (
                        validated.state == "completed" or validated.owner_instance_id != safe_owner
                    )
                    if reclaimable:
                        conn.execute(
                            "DELETE FROM idempotency_records WHERE key_hash = ?",
                            (safe_key_hash,),
                        )
                        row = None
                conn.execute(
                    """
                    DELETE FROM idempotency_records
                    WHERE expires_at <= ?
                      AND (state = 'completed' OR owner_instance_id != ?)
                      AND key_hash != ?
                    """,
                    (now, safe_owner, safe_key_hash),
                )
                if row is None:
                    count = int(
                        conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
                    )
                    if count >= max_records:
                        conn.commit()
                        return IdempotencyClaim("unavailable")
                    conn.execute(
                        """
                        INSERT INTO idempotency_records (
                            key_hash,
                            request_hash,
                            state,
                            owner_instance_id,
                            response_status,
                            response_json,
                            created_at,
                            updated_at,
                            expires_at
                        ) VALUES (?, ?, 'in_progress', ?, NULL, NULL, ?, ?, ?)
                        """,
                        (
                            safe_key_hash,
                            safe_request_hash,
                            safe_owner,
                            now,
                            now,
                            safe_expiry,
                        ),
                    )
                    conn.commit()
                    return IdempotencyClaim("claimed")

                result = _idempotency_claim_from_row(
                    row,
                    request_hash=safe_request_hash,
                    owner_instance_id=safe_owner,
                )
                conn.commit()
                return result
            except (OSError, sqlite3.Error, ValueError, TypeError):
                conn.rollback()
                return IdempotencyClaim("unavailable")

    def lookup_idempotency(
        self,
        *,
        key_hash: str,
        request_hash: str,
        owner_instance_id: str,
    ) -> IdempotencyClaim | None:
        safe_key_hash = _validate_idempotency_hash(key_hash, "key hash")
        safe_request_hash = _validate_idempotency_hash(request_hash, "request hash")
        safe_owner = _validate_idempotency_owner(owner_instance_id)
        current_time = datetime.now(UTC)

        try:
            conn = self.connect()
        except (OSError, sqlite3.Error):
            return IdempotencyClaim("unavailable")
        with closing(conn):
            try:
                row = conn.execute(
                    "SELECT * FROM idempotency_records WHERE key_hash = ?",
                    (safe_key_hash,),
                ).fetchone()
                if row is None:
                    return None
                validated = _validate_idempotency_row(row)
                if validated.expires_at <= current_time and (
                    validated.state == "completed" or validated.owner_instance_id != safe_owner
                ):
                    return None
                return _idempotency_claim_from_row(
                    row,
                    request_hash=safe_request_hash,
                    owner_instance_id=safe_owner,
                )
            except (OSError, sqlite3.Error, ValueError, TypeError):
                return IdempotencyClaim("unavailable")

    def complete_idempotency(
        self,
        *,
        key_hash: str,
        request_hash: str,
        owner_instance_id: str,
        response_status: int,
        response_json: str,
        completed_at: datetime,
        expires_at: datetime,
    ) -> None:
        safe_key_hash = _validate_idempotency_hash(key_hash, "key hash")
        safe_request_hash = _validate_idempotency_hash(request_hash, "request hash")
        safe_owner = _validate_idempotency_owner(owner_instance_id)
        safe_status = _validate_idempotency_status(response_status)
        safe_json = _validate_idempotency_response_json(response_json)
        safe_completed = _validate_idempotency_timestamp(completed_at, "completion timestamp")
        safe_expiry = _validate_idempotency_timestamp(expires_at, "expiry timestamp")
        if safe_expiry < safe_completed:
            raise ValueError("idempotency expiry timestamp is invalid")
        completed_time = datetime.fromisoformat(safe_completed)

        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM idempotency_records WHERE key_hash = ?",
                    (safe_key_hash,),
                ).fetchone()
                if row is None:
                    raise RuntimeError("idempotency completion failed")
                validated = _validate_idempotency_row(row)
                if (
                    validated.request_hash != safe_request_hash
                    or validated.owner_instance_id != safe_owner
                    or validated.state != "in_progress"
                ):
                    raise RuntimeError("idempotency completion failed")
                if completed_time < validated.created_at:
                    raise ValueError("idempotency completion timestamp is invalid")
                cursor = conn.execute(
                    """
                    UPDATE idempotency_records
                    SET state = 'completed',
                        response_status = ?,
                        response_json = ?,
                        updated_at = ?,
                        expires_at = ?
                    WHERE key_hash = ?
                      AND request_hash = ?
                      AND owner_instance_id = ?
                      AND state = 'in_progress'
                    """,
                    (
                        safe_status,
                        safe_json,
                        safe_completed,
                        safe_expiry,
                        safe_key_hash,
                        safe_request_hash,
                        safe_owner,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("idempotency completion failed")
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

    def begin_lifecycle_intent(
        self,
        bot_id: str,
        *,
        action: str,
        operation_id: str,
        source: str,
        request_id: str | None = None,
        reason: str = "",
    ) -> BotRecord:
        self._validate_intent_action(action)
        desired_state = DesiredState.stopped if action == "stop" else DesiredState.running
        event = LifecycleEventInput(
            bot_id=bot_id,
            operation_id=operation_id,
            source=source,
            action=f"bot.{action}.intent",
            outcome="pending",
            request_id=request_id,
            reason=reason,
            details={"action": action, "desired_state": desired_state.value},
        )
        self._validate_event_target(bot_id, event)
        now = datetime.now(UTC)
        now_text = now.isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                if prior_row["pending_operation_id"] is not None:
                    raise RuntimeError("bot already has a pending lifecycle intent")
                desired_revision = int(prior_row["desired_revision"]) + 1
                cursor = conn.execute(
                    """
                    UPDATE bots
                    SET desired_state = ?,
                        desired_revision = ?,
                        desired_updated_at = ?,
                        pending_operation_id = ?,
                        pending_action = ?,
                        pending_since = ?,
                        updated_at = ?
                    WHERE bot_id = ? AND pending_operation_id IS NULL
                    """,
                    (
                        desired_state.value,
                        desired_revision,
                        now_text,
                        operation_id,
                        action,
                        now_text,
                        now_text,
                        bot_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("lifecycle intent could not be started")
                event = LifecycleEventInput(
                    bot_id=bot_id,
                    operation_id=operation_id,
                    source=source,
                    action=f"bot.{action}.intent",
                    outcome="pending",
                    request_id=request_id,
                    reason=reason,
                    details={
                        "action": action,
                        "desired_state": desired_state.value,
                        "desired_revision": desired_revision,
                    },
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=str(prior_row["status"]),
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored_event = self._materialize_lifecycle_event(conn, event_id)
                record = self._record_in_transaction(conn, bot_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored_event)
        return record

    def complete_lifecycle_intent(
        self,
        bot_id: str,
        *,
        action: str,
        operation_id: str,
        desired_revision: int,
        status: BotStatus,
        pid: int | None,
        source: str,
        outcome: Literal["success", "failure"] = "success",
        request_id: str | None = None,
        reason: str = "",
        error_code: str | None = None,
        error_message: str | None = None,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
    ) -> BotRecord:
        self._validate_intent_action(action)
        self._validate_intent_revision(desired_revision)
        self._validate_intent_correlation(bot_id, operation_id, source, request_id)
        self._validate_intent_completion(
            action,
            outcome=outcome,
            status=status,
            pid=pid,
            error_code=error_code,
            error_message=error_message,
        )
        desired_state = DesiredState.stopped if action == "stop" else DesiredState.running
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._require_matching_intent(
                    prior_row,
                    action,
                    operation_id,
                    desired_revision,
                )
                self._update_lifecycle_row(
                    conn,
                    bot_id,
                    status,
                    pid,
                    started_at=started_at,
                    ready_at=ready_at,
                    stopped_at=stopped_at,
                    last_exit_code=last_exit_code,
                    last_error=last_error,
                    last_transition_reason=last_transition_reason,
                    reset_restart=reset_restart,
                    clear_ready_at=clear_ready_at,
                    clear_stopped_at=clear_stopped_at,
                    now=now,
                )
                cursor = conn.execute(
                    """
                    UPDATE bots
                    SET pending_operation_id = NULL,
                        pending_action = NULL,
                        pending_since = NULL
                    WHERE bot_id = ?
                      AND pending_operation_id = ?
                      AND pending_action = ?
                      AND desired_revision = ?
                      AND desired_state = ?
                    """,
                    (bot_id, operation_id, action, desired_revision, desired_state.value),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("pending lifecycle intent does not match")
                event = LifecycleEventInput(
                    bot_id=bot_id,
                    operation_id=operation_id,
                    source=source,
                    action=f"bot.{action}.complete",
                    outcome=outcome,
                    request_id=request_id,
                    reason=reason,
                    error_code=error_code,
                    error_message=error_message,
                    details={
                        "action": action,
                        "desired_revision": desired_revision,
                    },
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=status.value,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored_event = self._materialize_lifecycle_event(conn, event_id)
                record = self._record_in_transaction(conn, bot_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored_event)
        return record

    def clear_stale_intent(
        self,
        bot_id: str,
        *,
        action: str,
        operation_id: str,
        desired_revision: int,
        source: str,
        reason: str,
        request_id: str | None = None,
    ) -> BotRecord:
        self._validate_intent_action(action)
        self._validate_intent_revision(desired_revision)
        self._validate_intent_correlation(bot_id, operation_id, source, request_id)
        desired_state = DesiredState.stopped if action == "stop" else DesiredState.running
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._require_matching_intent(
                    prior_row,
                    action,
                    operation_id,
                    desired_revision,
                )
                cursor = conn.execute(
                    """
                    UPDATE bots
                    SET pending_operation_id = NULL,
                        pending_action = NULL,
                        pending_since = NULL,
                        updated_at = ?
                    WHERE bot_id = ?
                      AND pending_operation_id = ?
                      AND pending_action = ?
                      AND desired_revision = ?
                      AND desired_state = ?
                    """,
                    (
                        now,
                        bot_id,
                        operation_id,
                        action,
                        desired_revision,
                        desired_state.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("pending lifecycle intent does not match")
                event = LifecycleEventInput(
                    bot_id=bot_id,
                    operation_id=operation_id,
                    source=source,
                    action=f"bot.{action}.intent.clear",
                    outcome="cleared",
                    request_id=request_id,
                    reason=reason,
                    details={
                        "action": action,
                        "desired_revision": desired_revision,
                    },
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=str(prior_row["status"]),
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored_event = self._materialize_lifecycle_event(conn, event_id)
                record = self._record_in_transaction(conn, bot_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored_event)
        return record

    def _validate_intent_action(self, action: str) -> None:
        if type(action) is not str or action not in LIFECYCLE_INTENT_ACTIONS:
            raise ValueError("invalid lifecycle intent action")

    def _validate_intent_completion(
        self,
        action: str,
        *,
        outcome: Literal["success", "failure"],
        status: BotStatus,
        pid: int | None,
        error_code: str | None,
        error_message: str | None,
    ) -> None:
        if outcome not in {"success", "failure"}:
            raise ValueError("invalid lifecycle intent outcome")
        if not isinstance(status, BotStatus):
            raise TypeError("lifecycle intent status must be a BotStatus")
        if pid is not None and (type(pid) is not int or pid <= 0):
            raise ValueError("lifecycle intent terminal state has an invalid PID")
        if error_code is not None and (
            type(error_code) is not str or LIFECYCLE_ERROR_CODE_RE.fullmatch(error_code) is None
        ):
            raise ValueError("invalid lifecycle intent error code")
        if error_message is not None and type(error_message) is not str:
            raise TypeError("lifecycle intent error message must be a string")
        if outcome == "success":
            if error_code is not None or error_message is not None:
                raise ValueError("successful lifecycle intent cannot include error metadata")
            if action == "stop":
                compatible = status is BotStatus.stopped and pid is None
            else:
                compatible = status in {BotStatus.starting, BotStatus.running} and pid is not None
        else:
            compatible = status in {BotStatus.failed, BotStatus.unknown, BotStatus.stopped}
            if status in {BotStatus.failed, BotStatus.stopped} and pid is not None:
                compatible = False
        if not compatible:
            raise ValueError("lifecycle intent terminal state is incompatible with action outcome")

    def _validate_intent_revision(self, desired_revision: int) -> None:
        if type(desired_revision) is not int or desired_revision < 1:
            raise ValueError("desired revision must be a positive integer")

    def _validate_intent_correlation(
        self,
        bot_id: str,
        operation_id: str,
        source: str,
        request_id: str | None,
    ) -> None:
        event = LifecycleEventInput(
            bot_id=bot_id,
            operation_id=operation_id,
            source=source,
            action="lifecycle.intent.validate",
            outcome="validation",
            request_id=request_id,
        )
        self._validate_event_target(bot_id, event)

    def _require_matching_intent(
        self,
        row: sqlite3.Row,
        action: str,
        operation_id: str,
        desired_revision: int,
    ) -> None:
        desired_state = (
            DesiredState.stopped.value if action == "stop" else DesiredState.running.value
        )
        if (
            row["pending_operation_id"] != operation_id
            or int(row["desired_revision"]) != desired_revision
            or row["pending_action"] != action
            or row["desired_state"] != desired_state
        ):
            raise RuntimeError("pending lifecycle intent does not match")

    def _record_in_transaction(self, conn: sqlite3.Connection, bot_id: str) -> BotRecord:
        row = conn.execute("SELECT * FROM bots WHERE bot_id = ?", (bot_id,)).fetchone()
        if row is None:
            raise sqlite3.IntegrityError("updated bot projection is missing")
        return self._row_to_record(row)

    def audit_log_path(self) -> Path:
        return self.database_path.parent / "logs" / "audit.jsonl"

    def append_audit_event(self, event: str, **fields: object) -> None:
        try:
            safe_fields = sanitize_details(fields)
            if type(safe_fields) is not dict:
                return
            timestamp = datetime.now(UTC).isoformat()
            safe_event = sanitize_text(event)
            payload = {
                "ts": timestamp,
                "event": safe_event,
                **safe_fields,
            }
            line = (json.dumps(payload, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
            if len(line) > MAX_SANITIZED_JSON_BYTES:
                line = (
                    json.dumps(
                        {
                            "ts": timestamp,
                            "event": safe_event,
                            "truncated": True,
                        },
                        sort_keys=True,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8")
            append_private_bytes(nofollow_absolute_path(self.audit_log_path()), line)
        except Exception:
            return

    def upsert_bot(self, record: BotRecord) -> None:
        with closing(self.connect()) as conn:
            self._upsert_bot_row(conn, record)
            conn.commit()

    def _upsert_bot_row(self, conn: sqlite3.Connection, record: BotRecord) -> None:
        conn.execute(
            """
                INSERT INTO bots (
                    bot_id,
                    template_id,
                    display_name,
                    profile_path,
                    status,
                    pid,
                    restart_policy,
                    restart_backoff_seconds,
                    restart_max_attempts,
                    restart_attempts,
                    next_restart_at,
                    started_at,
                    ready_at,
                    stopped_at,
                    last_exit_code,
                    last_error,
                    last_transition_reason,
                    desired_state,
                    desired_revision,
                    desired_updated_at,
                    pending_operation_id,
                    pending_action,
                    pending_since,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bot_id) DO UPDATE SET
                    template_id = excluded.template_id,
                    display_name = excluded.display_name,
                    profile_path = excluded.profile_path,
                    status = excluded.status,
                    pid = excluded.pid,
                    restart_policy = excluded.restart_policy,
                    restart_backoff_seconds = excluded.restart_backoff_seconds,
                    restart_max_attempts = excluded.restart_max_attempts,
                    restart_attempts = excluded.restart_attempts,
                    next_restart_at = excluded.next_restart_at,
                    started_at = excluded.started_at,
                    ready_at = excluded.ready_at,
                    stopped_at = excluded.stopped_at,
                    last_exit_code = excluded.last_exit_code,
                    last_error = excluded.last_error,
                    last_transition_reason = excluded.last_transition_reason,
                    desired_state = excluded.desired_state,
                    desired_revision = excluded.desired_revision,
                    desired_updated_at = excluded.desired_updated_at,
                    pending_operation_id = excluded.pending_operation_id,
                    pending_action = excluded.pending_action,
                    pending_since = excluded.pending_since,
                    updated_at = excluded.updated_at
            """,
            (
                record.bot_id,
                record.template_id,
                record.display_name,
                record.profile_path,
                record.status.value,
                record.pid,
                record.restart_policy.value,
                record.restart_backoff_seconds,
                record.restart_max_attempts,
                record.restart_attempts,
                record.next_restart_at.isoformat() if record.next_restart_at else None,
                record.started_at.isoformat() if record.started_at else None,
                record.ready_at.isoformat() if record.ready_at else None,
                record.stopped_at.isoformat() if record.stopped_at else None,
                record.last_exit_code,
                _sanitize_optional_persisted_text(record.last_error),
                _sanitize_optional_persisted_text(record.last_transition_reason),
                record.desired_state.value,
                record.desired_revision,
                record.desired_updated_at.isoformat() if record.desired_updated_at else None,
                record.pending_operation_id,
                record.pending_action,
                record.pending_since.isoformat() if record.pending_since else None,
                record.created_at.isoformat(),
                record.updated_at.isoformat(),
            ),
        )

    def upsert_bot_with_event(
        self,
        record: BotRecord,
        *,
        event: LifecycleEventInput,
    ) -> LifecycleEvent:
        self._validate_event_target(record.bot_id, event)
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (record.bot_id,)
                ).fetchone()
                self._upsert_bot_row(conn, record)
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]) if prior_row else None,
                    status_after=record.status.value,
                    pid_before=int(prior_row["pid"]) if prior_row and prior_row["pid"] else None,
                    pid_after=record.pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, record.bot_id),
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return stored

    def get_bot(self, bot_id: str) -> BotRecord | None:
        with closing(self.connect()) as conn:
            row = conn.execute("SELECT * FROM bots WHERE bot_id = ?", (bot_id,)).fetchone()
        return self._row_to_record(row) if row else None

    def list_bots(self) -> list[BotRecord]:
        with closing(self.connect()) as conn:
            rows = conn.execute("SELECT * FROM bots ORDER BY bot_id").fetchall()
        return [self._row_to_record(row) for row in rows]

    def update_status(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        reset_restart: bool = False,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            if reset_restart:
                conn.execute(
                    """
                    UPDATE bots
                    SET status = ?,
                        pid = ?,
                        restart_attempts = 0,
                        next_restart_at = NULL,
                        updated_at = ?
                    WHERE bot_id = ?
                    """,
                    (status.value, pid, now, bot_id),
                )
            else:
                conn.execute(
                    "UPDATE bots SET status = ?, pid = ?, updated_at = ? WHERE bot_id = ?",
                    (status.value, pid, now, bot_id),
                )
            conn.commit()

    def update_lifecycle_state(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            self._update_lifecycle_row(
                conn,
                bot_id,
                status,
                pid,
                started_at=started_at,
                ready_at=ready_at,
                stopped_at=stopped_at,
                last_exit_code=last_exit_code,
                last_error=last_error,
                last_transition_reason=last_transition_reason,
                reset_restart=reset_restart,
                clear_ready_at=clear_ready_at,
                clear_stopped_at=clear_stopped_at,
                now=now,
            )
            conn.commit()

    def _update_lifecycle_row(
        self,
        conn: sqlite3.Connection,
        bot_id: str,
        status: BotStatus,
        pid: int | None,
        *,
        started_at: datetime | None,
        ready_at: datetime | None,
        stopped_at: datetime | None,
        last_exit_code: int | None,
        last_error: str | None,
        last_transition_reason: str | None,
        reset_restart: bool,
        clear_ready_at: bool,
        clear_stopped_at: bool,
        now: str,
    ) -> None:
        cursor = conn.execute(
            """
            UPDATE bots
            SET status = ?,
                pid = ?,
                started_at = COALESCE(?, started_at),
                ready_at = CASE WHEN ? THEN NULL ELSE COALESCE(?, ready_at) END,
                stopped_at = CASE WHEN ? THEN NULL ELSE COALESCE(?, stopped_at) END,
                last_exit_code = ?,
                last_error = ?,
                last_transition_reason = COALESCE(?, last_transition_reason),
                updated_at = ?,
                restart_attempts = CASE WHEN ? THEN 0 ELSE restart_attempts END,
                next_restart_at = CASE WHEN ? THEN NULL ELSE next_restart_at END
            WHERE bot_id = ?
            """,
            (
                status.value,
                pid,
                started_at.isoformat() if started_at else None,
                int(clear_ready_at),
                ready_at.isoformat() if ready_at else None,
                int(clear_stopped_at),
                stopped_at.isoformat() if stopped_at else None,
                last_exit_code,
                _sanitize_optional_persisted_text(last_error),
                _sanitize_optional_persisted_text(last_transition_reason),
                now,
                int(reset_restart),
                int(reset_restart),
                bot_id,
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"unknown bot: {bot_id}")

    def update_lifecycle_with_event(
        self,
        bot_id: str,
        status: BotStatus,
        pid: int | None = None,
        *,
        event: LifecycleEventInput,
        started_at: datetime | None = None,
        ready_at: datetime | None = None,
        stopped_at: datetime | None = None,
        last_exit_code: int | None = None,
        last_error: str | None = None,
        last_transition_reason: str | None = None,
        reset_restart: bool = False,
        clear_ready_at: bool = False,
        clear_stopped_at: bool = False,
    ) -> LifecycleEvent:
        self._validate_event_target(bot_id, event)
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._update_lifecycle_row(
                    conn,
                    bot_id,
                    status,
                    pid,
                    started_at=started_at,
                    ready_at=ready_at,
                    stopped_at=stopped_at,
                    last_exit_code=last_exit_code,
                    last_error=last_error,
                    last_transition_reason=last_transition_reason,
                    reset_restart=reset_restart,
                    clear_ready_at=clear_ready_at,
                    clear_stopped_at=clear_stopped_at,
                    now=now,
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=status.value,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return stored

    def update_restart_state(
        self,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            self._update_restart_row(
                conn,
                bot_id,
                status=status,
                pid=pid,
                restart_attempts=restart_attempts,
                next_restart_at=next_restart_at,
                now=now,
            )
            conn.commit()

    def _update_restart_row(
        self,
        conn: sqlite3.Connection,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
        now: str,
    ) -> None:
        cursor = conn.execute(
            """
            UPDATE bots
            SET status = ?,
                pid = ?,
                restart_attempts = ?,
                next_restart_at = ?,
                updated_at = ?
            WHERE bot_id = ?
            """,
            (
                status.value,
                pid,
                restart_attempts,
                next_restart_at.isoformat() if next_restart_at else None,
                now,
                bot_id,
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"unknown bot: {bot_id}")

    def update_restart_with_event(
        self,
        bot_id: str,
        *,
        status: BotStatus,
        pid: int | None,
        restart_attempts: int,
        next_restart_at: datetime | None,
        event: LifecycleEventInput,
    ) -> LifecycleEvent:
        self._validate_event_target(bot_id, event)
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                self._update_restart_row(
                    conn,
                    bot_id,
                    status=status,
                    pid=pid,
                    restart_attempts=restart_attempts,
                    next_restart_at=next_restart_at,
                    now=now,
                )
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=status.value,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=pid,
                )
                conn.execute(
                    "UPDATE bots SET last_event_id = ? WHERE bot_id = ?",
                    (event_id, bot_id),
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return stored

    def delete_bot(self, bot_id: str) -> bool:
        with closing(self.connect()) as conn:
            cursor = conn.execute("DELETE FROM bots WHERE bot_id = ?", (bot_id,))
            conn.commit()
        return cursor.rowcount > 0

    def delete_bot_with_event(
        self,
        bot_id: str,
        *,
        event: LifecycleEventInput,
    ) -> bool:
        self._validate_event_target(bot_id, event)
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior_row = conn.execute(
                    "SELECT * FROM bots WHERE bot_id = ?", (bot_id,)
                ).fetchone()
                if prior_row is None:
                    raise KeyError(f"unknown bot: {bot_id}")
                cursor = conn.execute("DELETE FROM bots WHERE bot_id = ?", (bot_id,))
                if cursor.rowcount != 1:
                    raise KeyError(f"unknown bot: {bot_id}")
                event_id = self._insert_lifecycle_event(
                    conn,
                    event,
                    status_before=str(prior_row["status"]),
                    status_after=None,
                    pid_before=(int(prior_row["pid"]) if prior_row["pid"] is not None else None),
                    pid_after=None,
                )
                stored = self._materialize_lifecycle_event(conn, event_id)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
        self._append_lifecycle_audit_fail_open(stored)
        return True

    def _validate_event_target(self, bot_id: str, event: LifecycleEventInput) -> None:
        if event.bot_id != bot_id:
            raise ValueError("lifecycle event bot_id must match the projection target")
        if LIFECYCLE_ID_RE.fullmatch(event.operation_id) is None:
            raise ValueError("lifecycle operation_id must be generated UUID hex")
        if event.source not in LIFECYCLE_SOURCES:
            raise ValueError("invalid lifecycle event source")
        if event.source == "api":
            if event.request_id is None or LIFECYCLE_ID_RE.fullmatch(event.request_id) is None:
                raise ValueError("API lifecycle events require a generated request ID")
        elif event.request_id is not None:
            raise ValueError("only API lifecycle events may carry a request ID")

    def _insert_lifecycle_event(
        self,
        conn: sqlite3.Connection,
        event: LifecycleEventInput,
        *,
        status_before: str | None,
        status_after: str | None,
        pid_before: int | None,
        pid_after: int | None,
    ) -> int:
        cursor = conn.execute(
            """
            INSERT INTO lifecycle_events (
                bot_id,
                operation_id,
                request_id,
                occurred_at,
                source,
                action,
                outcome,
                status_before,
                status_after,
                pid_before,
                pid_after,
                reason,
                error_code,
                error_message,
                details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.bot_id,
                event.operation_id,
                event.request_id,
                datetime.now(UTC).isoformat(),
                event.source,
                event.action,
                event.outcome,
                status_before,
                status_after,
                pid_before,
                pid_after,
                event.reason,
                event.error_code,
                event.error_message,
                serialize_lifecycle_details(event.details),
            ),
        )
        if cursor.lastrowid is None:
            raise sqlite3.IntegrityError("lifecycle event insert returned no event id")
        return int(cursor.lastrowid)

    def _materialize_lifecycle_event(
        self,
        conn: sqlite3.Connection,
        event_id: int,
    ) -> LifecycleEvent:
        row = conn.execute(
            "SELECT * FROM lifecycle_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise sqlite3.IntegrityError("inserted lifecycle event is missing")
        return self._row_to_lifecycle_event(row)

    def _append_lifecycle_audit_fail_open(self, event: LifecycleEvent) -> None:
        try:
            self._append_lifecycle_audit(event)
        except Exception:
            return

    def _append_lifecycle_audit(self, event: LifecycleEvent) -> None:
        self.append_audit_event(
            event.action,
            bot_id=event.bot_id,
            operation_id=event.operation_id,
            request_id=event.request_id,
            source=event.source,
            outcome=event.outcome,
            status_before=event.status_before,
            status_after=event.status_after,
            pid_before=event.pid_before,
            pid_after=event.pid_after,
            reason=event.reason,
            error_code=event.error_code,
            error_message=event.error_message,
            details=event.details,
        )

    def list_lifecycle_events(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> list[LifecycleEvent]:
        self._validate_history_page(bot_id, limit, before)
        with closing(self.connect()) as conn:
            rows = self._list_lifecycle_event_rows(conn, bot_id, limit, before)
        return [self._row_to_lifecycle_event(row) for row in rows]

    def history_payload(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> dict[str, object]:
        self._validate_history_page(bot_id, limit, before)
        with closing(self.connect()) as conn:
            rows = self._list_lifecycle_event_rows(conn, bot_id, limit + 1, before)
            if not rows:
                bot_is_known = (
                    conn.execute(
                        """
                        SELECT 1 FROM bots WHERE bot_id = ?
                        UNION ALL
                        SELECT 1 FROM lifecycle_events WHERE bot_id = ?
                        LIMIT 1
                        """,
                        (bot_id, bot_id),
                    ).fetchone()
                    is not None
                )
                if not bot_is_known:
                    raise KeyError(f"unknown bot: {bot_id}")
        has_more = len(rows) > limit
        events = [self._row_to_lifecycle_event(row) for row in rows[:limit]]
        return {
            "bot_id": bot_id,
            "events": [event.to_dict() for event in events],
            "next_before": events[-1].event_id if has_more else None,
        }

    def _validate_history_page(
        self,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> None:
        if not isinstance(bot_id, str):
            raise TypeError("bot_id must be a string")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if before is not None:
            if isinstance(before, bool) or not isinstance(before, int):
                raise TypeError("before must be an integer or null")
            if before < 1:
                raise ValueError("before must be positive")

    def _list_lifecycle_event_rows(
        self,
        conn: sqlite3.Connection,
        bot_id: str,
        limit: int,
        before: int | None,
    ) -> list[sqlite3.Row]:
        if before is None:
            return conn.execute(
                """
                SELECT * FROM lifecycle_events
                WHERE bot_id = ?
                ORDER BY event_id DESC
                LIMIT ?
                """,
                (bot_id, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT * FROM lifecycle_events
            WHERE bot_id = ? AND event_id < ?
            ORDER BY event_id DESC
            LIMIT ?
            """,
            (bot_id, before, limit),
        ).fetchall()

    def _row_to_lifecycle_event(self, row: sqlite3.Row) -> LifecycleEvent:
        return LifecycleEvent(
            event_id=int(row["event_id"]),
            bot_id=str(row["bot_id"]),
            operation_id=str(row["operation_id"]),
            request_id=str(row["request_id"]) if row["request_id"] is not None else None,
            occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
            source=str(row["source"]),
            action=str(row["action"]),
            outcome=str(row["outcome"]),
            status_before=(str(row["status_before"]) if row["status_before"] is not None else None),
            status_after=(str(row["status_after"]) if row["status_after"] is not None else None),
            pid_before=int(row["pid_before"]) if row["pid_before"] is not None else None,
            pid_after=int(row["pid_after"]) if row["pid_after"] is not None else None,
            reason=str(row["reason"]),
            error_code=str(row["error_code"]) if row["error_code"] is not None else None,
            error_message=(str(row["error_message"]) if row["error_message"] is not None else None),
            details=deserialize_lifecycle_details(str(row["details_json"])),
        )

    def _row_to_record(self, row: sqlite3.Row) -> BotRecord:
        next_restart_at = row["next_restart_at"]
        started_at = row["started_at"]
        ready_at = row["ready_at"]
        stopped_at = row["stopped_at"]
        desired_updated_at = row["desired_updated_at"]
        pending_since = row["pending_since"]
        return BotRecord(
            bot_id=row["bot_id"],
            template_id=row["template_id"],
            display_name=row["display_name"],
            profile_path=row["profile_path"],
            status=BotStatus(row["status"]),
            pid=row["pid"],
            restart_policy=RestartPolicy(row["restart_policy"]),
            restart_backoff_seconds=float(row["restart_backoff_seconds"]),
            restart_max_attempts=int(row["restart_max_attempts"]),
            restart_attempts=int(row["restart_attempts"]),
            next_restart_at=datetime.fromisoformat(next_restart_at) if next_restart_at else None,
            started_at=datetime.fromisoformat(started_at) if started_at else None,
            ready_at=datetime.fromisoformat(ready_at) if ready_at else None,
            stopped_at=datetime.fromisoformat(stopped_at) if stopped_at else None,
            last_exit_code=row["last_exit_code"],
            last_error=row["last_error"],
            last_transition_reason=row["last_transition_reason"],
            desired_state=DesiredState(row["desired_state"]),
            desired_revision=int(row["desired_revision"]),
            desired_updated_at=(
                datetime.fromisoformat(desired_updated_at) if desired_updated_at else None
            ),
            pending_operation_id=row["pending_operation_id"],
            pending_action=row["pending_action"],
            pending_since=datetime.fromisoformat(pending_since) if pending_since else None,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
