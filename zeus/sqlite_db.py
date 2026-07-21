from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from zeus.config import SQLiteSynchronous
from zeus.schema import _assert_schema_compatible, _preflight_schema_compatibility

_SYNCHRONOUS_PRAGMA = {
    SQLiteSynchronous.NORMAL: "PRAGMA synchronous=NORMAL",
    SQLiteSynchronous.FULL: "PRAGMA synchronous=FULL",
}


class SQLiteDatabase:
    def __init__(
        self,
        database_path: Path | str,
        *,
        synchronous: SQLiteSynchronous | str = SQLiteSynchronous.NORMAL,
    ) -> None:
        self.database_path = Path(database_path)
        self.synchronous = SQLiteSynchronous(synchronous)

    def connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        _preflight_schema_compatibility(self.database_path)
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        try:
            _assert_schema_compatible(conn)
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_SYNCHRONOUS_PRAGMA[self.synchronous])
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except Exception:
            conn.close()
            raise

    @contextmanager
    def immediate(self) -> Iterator[sqlite3.Connection]:
        with closing(self.connect()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
