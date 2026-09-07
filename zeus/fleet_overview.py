from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeus.models import BotStatus, DesiredState, RestartPolicy, validate_id
from zeus.reconciliation import ReconcileOutcome
from zeus.sanitization import sanitize_text
from zeus.schema import _assert_schema_current
from zeus.sqlite_db import StateReadinessError

_FRESHNESS_SOURCE = "persisted_reconciliation"
_OVERVIEW_SQL = """
WITH overview AS (
    SELECT b.bot_id, substr(b.display_name, 1, 256) AS display_name,
           b.desired_state, b.status AS stored_status, b.pid,
           b.restart_policy, b.restart_attempts, b.restart_max_attempts,
           b.next_restart_at, b.pending_action, b.created_at, b.updated_at,
           r.run_id, r.outcome AS observation_outcome,
           r.observed_status, r.pid AS observed_pid,
           substr(r.message, 1, 2048) AS observation_reason,
           r.finished_at AS observed_at,
           (
               r.run_id IS NULL
               OR r.finished_at > :now OR r.finished_at < :cutoff
               OR b.pending_action IS NOT NULL
               OR b.desired_state != b.status
               OR b.status IN ('failed', 'unknown')
               OR r.outcome IN ('action_required', 'error', 'pending', 'skipped')
               OR (
                   b.restart_policy = 'on-failure' AND b.desired_state = 'running'
                   AND MAX(0, b.restart_attempts - (b.next_restart_at IS NOT NULL))
                       >= b.restart_max_attempts
               )
           ) AS needs_attention
    FROM bots AS b
    LEFT JOIN reconcile_results AS r ON r.rowid = (
        SELECT candidate.rowid FROM reconcile_results AS candidate
        WHERE candidate.bot_id = b.bot_id
            AND candidate.finished_at >= b.created_at
            AND candidate.started_at >= b.created_at
        ORDER BY candidate.finished_at DESC, candidate.run_id DESC
        LIMIT 1
    )
    WHERE b.bot_id > :after
)
SELECT * FROM overview
WHERE :attention_only = 0 OR needs_attention
ORDER BY bot_id
LIMIT :row_limit
"""


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("stored overview timestamp is invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("stored overview timestamp is invalid")
    normalized = parsed.astimezone(UTC)
    # Stored timestamps participate in ordered SQL comparisons.
    if normalized.isoformat() != value:
        raise ValueError("stored overview timestamp is not normalized")
    return normalized


def _nonnegative_integer(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("stored overview counter is invalid")
    return value


def _optional_pid(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise ValueError("stored overview PID is invalid")
    return value


class FleetOverviewReader:
    """Read persisted fleet evidence without probing or changing gateway state."""

    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)

    def overview(
        self,
        *,
        limit: int = 50,
        after: str | None = None,
        attention_only: bool = False,
        stale_after_seconds: float = 120,
        now: datetime | None = None,
    ) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if after is not None:
            validate_id(after, "after")
        if type(attention_only) is not bool:
            raise ValueError("attention_only must be a boolean")
        if type(stale_after_seconds) not in {int, float} or not 0 <= stale_after_seconds <= 86_400:
            raise ValueError("stale_after_seconds must be between 0 and 86400")
        observed_now = datetime.now(UTC) if now is None else now
        if (
            not isinstance(observed_now, datetime)
            or observed_now.tzinfo is None
            or observed_now.utcoffset() is None
        ):
            raise ValueError("now must be a timezone-aware datetime")
        observed_now = observed_now.astimezone(UTC)
        cutoff = observed_now - timedelta(seconds=stale_after_seconds)
        try:
            uri = f"{self.database_path.resolve().as_uri()}?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                _assert_schema_current(conn)
                rows = conn.execute(
                    _OVERVIEW_SQL,
                    {
                        "after": after or "",
                        "now": observed_now.isoformat(),
                        "cutoff": cutoff.isoformat(),
                        "attention_only": int(attention_only),
                        "row_limit": limit + 1,
                    },
                ).fetchall()
                items = [
                    self._item(row, now=observed_now, stale_after_seconds=stale_after_seconds)
                    for row in rows[:limit]
                ]
        except (sqlite3.Error, OSError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
            raise StateReadinessError("fleet overview is unavailable") from exc
        return {
            "items": items,
            "next_after": items[-1]["bot_id"] if len(rows) > limit else None,
            "limit": limit,
            "attention_only": attention_only,
            "generated_at": observed_now.isoformat(),
            "stale_after_seconds": stale_after_seconds,
            "freshness_source": _FRESHNESS_SOURCE,
            "live_probe": False,
        }

    def _item(
        self, row: sqlite3.Row, *, now: datetime, stale_after_seconds: float
    ) -> dict[str, object]:
        bot_id = validate_id(row["bot_id"], "stored bot_id")
        desired = DesiredState(row["desired_state"])
        status = BotStatus(row["stored_status"])
        policy = RestartPolicy(row["restart_policy"])
        attempts = _nonnegative_integer(row["restart_attempts"])
        maximum = _nonnegative_integer(row["restart_max_attempts"])
        next_restart = row["next_restart_at"]
        if next_restart is not None:
            next_restart = _timestamp(next_restart).isoformat()
        pending = row["pending_action"]
        if pending not in {None, "start", "stop", "restart"}:
            raise ValueError("stored pending action is invalid")
        created_at = _timestamp(row["created_at"])
        updated_at = _timestamp(row["updated_at"])
        reasons: list[str] = []
        observation: dict[str, object] | None = None
        freshness = "unknown"
        if row["run_id"] is None:
            reasons.append("no_reconciliation_observation")
        else:
            observed_at = _timestamp(row["observed_at"])
            age = (now - observed_at).total_seconds()
            outcome = ReconcileOutcome(row["observation_outcome"])
            observed_status = row["observed_status"]
            if observed_status is not None:
                observed_status = BotStatus(observed_status).value
            observation = {
                "run_id": sanitize_text(row["run_id"], max_length=128),
                "observed_at": observed_at.isoformat(),
                "age_seconds": max(0.0, age),
                "outcome": outcome.value,
                "reason": sanitize_text(row["observation_reason"]),
                "observed_status": observed_status,
                "pid": _optional_pid(row["observed_pid"]),
            }
            if age < 0:
                freshness = "clock_skew"
                reasons.append("observation_clock_skew")
            elif age > stale_after_seconds:
                freshness = "stale"
                reasons.append("stale_observation")
            else:
                freshness = "fresh"
            if outcome in {
                ReconcileOutcome.action_required,
                ReconcileOutcome.error,
                ReconcileOutcome.pending,
                ReconcileOutcome.skipped,
            }:
                reasons.append(f"reconcile_{outcome.value}")
        if pending is not None:
            reasons.append("pending_intent")
        if desired.value != status.value:
            reasons.append("desired_state_mismatch")
        if status in {BotStatus.failed, BotStatus.unknown}:
            reasons.append(f"stored_{status.value}")
        completed_attempts = max(0, attempts - int(next_restart is not None))
        budget_exhausted = completed_attempts >= maximum
        if (
            policy is RestartPolicy.on_failure
            and desired is DesiredState.running
            and budget_exhausted
        ):
            reasons.append("restart_budget_exhausted")
        return {
            "bot_id": bot_id,
            "display_name": sanitize_text(row["display_name"], max_length=256),
            "desired_state": desired.value,
            "stored_status": status.value,
            "pid": _optional_pid(row["pid"]),
            "restart_policy": policy.value,
            "restart_attempts": attempts,
            "restart_max_attempts": maximum,
            "restart_budget_remaining": max(0, maximum - completed_attempts),
            "next_restart_at": next_restart,
            "pending_action": pending,
            "created_at": created_at.isoformat(),
            "stored_state_updated_at": updated_at.isoformat(),
            "observation": observation,
            "freshness": freshness,
            "freshness_source": _FRESHNESS_SOURCE,
            "needs_attention": bool(reasons),
            "attention_reasons": reasons,
        }
