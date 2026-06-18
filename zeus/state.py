from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from zeus.models import BotRecord, BotStatus, RestartPolicy


class StateStore:
    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)

    def connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        with closing(self.connect()) as conn:
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
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._ensure_schema(conn)
            conn.commit()

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
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

    def upsert_bot(self, record: BotRecord) -> None:
        with closing(self.connect()) as conn:
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
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                ),
            )
            conn.commit()

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
            conn.execute(
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
            conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> BotRecord:
        next_restart_at = row["next_restart_at"]
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
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
