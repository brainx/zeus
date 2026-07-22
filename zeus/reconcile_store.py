from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime

from zeus.reconciliation import (
    BotReconcileResult,
    PersistedReconcileRun,
    ReconcileOutcome,
    ReconcileRunStart,
    ReconcileRunSummary,
)
from zeus.sqlite_db import SQLiteDatabase

RECONCILE_COUNTER_COLUMNS = {
    ReconcileOutcome.healthy: "healthy_count",
    ReconcileOutcome.changed: "changed_count",
    ReconcileOutcome.pending: "pending_count",
    ReconcileOutcome.action_required: "action_required_count",
    ReconcileOutcome.error: "error_count",
    ReconcileOutcome.skipped: "skipped_count",
}


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


class ReconcileStore:
    def __init__(self, database: SQLiteDatabase) -> None:
        self._database = database

    def begin_reconcile_run(self, run: ReconcileRunStart) -> None:
        if not isinstance(run, ReconcileRunStart):
            raise TypeError("run must be a ReconcileRunStart")
        with closing(self._database.connect()) as conn:
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
        with closing(self._database.connect()) as conn:
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
        with closing(self._database.connect()) as conn:
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
        with closing(self._database.connect()) as conn:
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
        with closing(self._database.connect()) as conn:
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
