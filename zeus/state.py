from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from zeus.models import BotRecord, BotStatus


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
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

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
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bot_id) DO UPDATE SET
                    template_id = excluded.template_id,
                    display_name = excluded.display_name,
                    profile_path = excluded.profile_path,
                    status = excluded.status,
                    pid = excluded.pid,
                    updated_at = excluded.updated_at
                """,
                (
                    record.bot_id,
                    record.template_id,
                    record.display_name,
                    record.profile_path,
                    record.status.value,
                    record.pid,
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

    def update_status(self, bot_id: str, status: BotStatus, pid: int | None = None) -> None:
        now = datetime.now(UTC).isoformat()
        with closing(self.connect()) as conn:
            conn.execute(
                "UPDATE bots SET status = ?, pid = ?, updated_at = ? WHERE bot_id = ?",
                (status.value, pid, now, bot_id),
            )
            conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> BotRecord:
        return BotRecord(
            bot_id=row["bot_id"],
            template_id=row["template_id"],
            display_name=row["display_name"],
            profile_path=row["profile_path"],
            status=BotStatus(row["status"]),
            pid=row["pid"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
