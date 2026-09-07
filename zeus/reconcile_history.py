from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from zeus.reconcile_store import (
    RECONCILE_COUNTER_COLUMNS,
    _parse_reconcile_timestamp,
    _validate_reconcile_run_id,
    _validate_stored_boolean_flag,
    _validate_stored_nonnegative_integer,
    _validate_stored_optional_positive_integer,
)
from zeus.reconciliation import (
    MAX_RECONCILE_TEXT_LENGTH,
    BotReconcileResult,
    ReconcileOutcome,
    ReconcileRunStart,
)
from zeus.schema import _assert_schema_current
from zeus.sqlite_db import StateReadinessError

RUN_OUTCOMES = frozenset({"running", "succeeded", "completed_with_errors", "interrupted"})
MAX_PAGE_SIZE = 100
MAX_CURSOR_LENGTH = 2048
_MAX_SQLITE_INTEGER = 2**63 - 1


class _InvalidCursor(ValueError):
    pass


@dataclass(frozen=True)
class _RunHeader:
    start: ReconcileRunStart
    finished_at: datetime | None
    outcome: str
    total: int
    counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.start.run_id,
            "scope": self.start.scope,
            "requested_bot_id": self.start.requested_bot_id,
            "source": self.start.source,
            "force": self.start.force,
            "reset_restart": self.start.reset_restart,
            "started_at": self.start.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "outcome": self.outcome,
            "total": self.total,
            "counts": self.counts,
        }


def _text(value: object, *, maximum: int = 128, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value and not empty):
        raise ValueError("stored reconciliation text is invalid")
    return value


def _optional_text(value: object, *, maximum: int = 128) -> str | None:
    return None if value is None else _text(value, maximum=maximum)


def _header(row: sqlite3.Row) -> _RunHeader:
    start = ReconcileRunStart(
        run_id=_text(row["run_id"]),
        scope=_text(row["scope"]),
        requested_bot_id=_optional_text(row["requested_bot_id"]),
        source=_text(row["source"]),
        force=_validate_stored_boolean_flag(row["force"], "force flag"),
        reset_restart=_validate_stored_boolean_flag(row["reset_restart"], "reset-restart flag"),
        started_at=_parse_reconcile_timestamp(row["started_at"], "run start timestamp"),
    )
    finished_at = (
        _parse_reconcile_timestamp(row["finished_at"], "run finish timestamp")
        if row["finished_at"] is not None
        else None
    )
    outcome = _text(row["outcome"])
    if outcome not in RUN_OUTCOMES or (outcome == "running") != (finished_at is None):
        raise ValueError("stored reconciliation outcome is invalid")
    if finished_at is not None and finished_at < start.started_at:
        raise ValueError("stored reconciliation interval is invalid")
    total = _validate_stored_nonnegative_integer(row["total"], "total")
    counts = {
        outcome.value: _validate_stored_nonnegative_integer(row[column], "outcome counter")
        for outcome, column in RECONCILE_COUNTER_COLUMNS.items()
    }
    if sum(counts.values()) != total or (start.scope == "bot" and total > 1):
        raise ValueError("stored reconciliation counters are inconsistent")
    failures = counts[ReconcileOutcome.error.value] + counts[ReconcileOutcome.action_required.value]
    if (outcome == "succeeded" and failures) or (
        outcome == "completed_with_errors" and not failures
    ):
        raise ValueError("stored reconciliation outcome disagrees with counters")
    return _RunHeader(start, finished_at, outcome, total, counts)


def _result(row: sqlite3.Row, header: _RunHeader, ordinal: int) -> dict[str, object]:
    if _validate_stored_nonnegative_integer(row["ordinal"], "ordinal") != ordinal:
        raise ValueError("stored reconciliation ordinals are not contiguous")
    if ordinal >= header.total:
        raise ValueError("stored reconciliation result exceeds total")
    bot_id = _text(row["bot_id"])
    event_id = _validate_stored_optional_positive_integer(row["event_id"], "event id")
    if event_id is not None and row["linked_event_bot_id"] != bot_id:
        raise ValueError("stored reconciliation event does not match result")
    result = BotReconcileResult(
        bot_id=bot_id,
        outcome=ReconcileOutcome(_text(row["outcome"])),
        desired_state=_optional_text(row["desired_state"]),
        observed_status=_optional_text(row["observed_status"]),
        pid=_validate_stored_optional_positive_integer(row["pid"], "pid"),
        action=_text(row["action"], maximum=MAX_RECONCILE_TEXT_LENGTH, empty=True),
        message=_text(row["message"], maximum=MAX_RECONCILE_TEXT_LENGTH, empty=True),
        error_code=_optional_text(row["error_code"], maximum=MAX_RECONCILE_TEXT_LENGTH),
        event_id=event_id,
        started_at=_parse_reconcile_timestamp(row["started_at"], "result start timestamp"),
        finished_at=_parse_reconcile_timestamp(row["finished_at"], "result finish timestamp"),
    )
    if header.start.scope == "bot" and result.bot_id != header.start.requested_bot_id:
        raise ValueError("stored reconciliation result is outside run scope")
    if result.started_at < header.start.started_at or (
        header.finished_at is not None and result.finished_at > header.finished_at
    ):
        raise ValueError("stored reconciliation result is outside run interval")
    return {**result.to_dict(), "ordinal": ordinal}


def _limit(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_PAGE_SIZE:
        raise ValueError("limit must be an integer between 1 and 100")
    return value


def _identifier(value: str, label: str) -> str:
    try:
        value = _validate_reconcile_run_id(value)
        value.encode("utf-8")
        return value
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a valid reconciliation identifier") from None


def _encode_cursor(started_at: str, run_id: str) -> str:
    payload = json.dumps([started_at, run_id], separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(value: str | None) -> tuple[str, str] | None:
    if value is None:
        return None
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_CURSOR_LENGTH:
            raise ValueError
        if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise ValueError
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        payload = json.loads(raw)
        if not isinstance(payload, list) or len(payload) != 2:
            raise ValueError
        timestamp = _parse_reconcile_timestamp(payload[0], "cursor timestamp").isoformat()
        run_id = _validate_reconcile_run_id(payload[1])
        if _encode_cursor(timestamp, run_id) != value:
            raise ValueError
        return timestamp, run_id
    except (ValueError, TypeError, binascii.Error, UnicodeError, RecursionError, OverflowError):
        raise _InvalidCursor("before cursor is invalid") from None


class ReconcileHistoryReader:
    """Read bounded history pages without migration or lifecycle side effects."""

    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        try:
            uri = self.database_path.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                try:
                    _assert_schema_current(conn)
                    yield conn
                finally:
                    conn.rollback()
        except _InvalidCursor:
            raise
        except (
            sqlite3.Error,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            IndexError,
            OverflowError,
        ) as exc:
            raise StateReadinessError("reconciliation history is unavailable") from exc

    def list_runs(
        self,
        *,
        limit: int = 50,
        before: str | None = None,
        outcome: str | None = None,
        bot_id: str | None = None,
    ) -> dict[str, object]:
        limit = _limit(limit)
        cursor = _decode_cursor(before)
        if outcome is not None and (not isinstance(outcome, str) or outcome not in RUN_OUTCOMES):
            raise ValueError("outcome must be a recognized reconciliation run outcome")
        if bot_id is not None:
            _identifier(bot_id, "bot_id")
        clauses: list[str] = []
        parameters: list[object] = []
        with self._read() as conn:
            if cursor is not None:
                clauses.append("(runs.started_at, runs.run_id) < (?, ?)")
                parameters.extend(cursor)
            if outcome is not None:
                clauses.append("runs.outcome = ?")
                parameters.append(outcome)
            if bot_id is not None:
                clauses.append(
                    "(runs.requested_bot_id = ? OR EXISTS ("
                    "SELECT 1 FROM reconcile_results AS membership "
                    "WHERE membership.run_id = runs.run_id AND membership.bot_id = ?))"
                )
                parameters.extend((bot_id, bot_id))
            where = " AND ".join(clauses) if clauses else "1"
            # Predicates are fixed above; all caller-provided values are bound.
            rows = conn.execute(
                "SELECT runs.* FROM reconcile_runs AS runs "  # nosec B608
                f"WHERE {where} ORDER BY runs.started_at DESC, runs.run_id DESC LIMIT ?",
                (*parameters, limit + 1),
            ).fetchall()
            headers = [_header(row).to_dict() for row in rows]
            return {
                "runs": headers[:limit],
                "next_before": (
                    _encode_cursor(rows[limit - 1]["started_at"], rows[limit - 1]["run_id"])
                    if len(rows) > limit
                    else None
                ),
            }

    def get_run(
        self, run_id: str, *, limit: int = 50, after: int | None = None
    ) -> dict[str, object] | None:
        _identifier(run_id, "run_id")
        limit = _limit(limit)
        if after is not None and (type(after) is not int or not 0 <= after <= _MAX_SQLITE_INTEGER):
            raise ValueError("after must be a non-negative integer within SQLite's integer range")
        first_ordinal = 0 if after is None else after + 1
        with self._read() as conn:
            row = conn.execute(
                "SELECT * FROM reconcile_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                return None
            header = _header(row)
            rows = conn.execute(
                """
                SELECT results.*, events.bot_id AS linked_event_bot_id
                FROM reconcile_results AS results
                LEFT JOIN lifecycle_events AS events ON events.event_id = results.event_id
                WHERE results.run_id = ? AND results.ordinal > ?
                ORDER BY results.ordinal LIMIT ?
                """,
                (run_id, -1 if after is None else after, limit + 1),
            ).fetchall()
            results = [
                _result(item, header, first_ordinal + index) for index, item in enumerate(rows)
            ]
            counts = {outcome.value: 0 for outcome in ReconcileOutcome}
            for result in results:
                counts[str(result["outcome"])] += 1
            if any(count > header.counts[outcome] for outcome, count in counts.items()):
                raise ValueError("stored reconciliation result counters are inconsistent")
            if len(rows) <= limit and first_ordinal + len(rows) < header.total:
                raise ValueError("stored reconciliation result history is incomplete")
            return {
                "run": header.to_dict(),
                "results": results[:limit],
                "next_after": first_ordinal + limit - 1 if len(rows) > limit else None,
            }
