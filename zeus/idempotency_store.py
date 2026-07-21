from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime

from zeus.idempotency import IdempotencyClaim
from zeus.sqlite_db import SQLiteDatabase

IDEMPOTENCY_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
IDEMPOTENCY_OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
MAX_IDEMPOTENCY_RESPONSE_BYTES = 1_000_000


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


class IdempotencyStore:
    def __init__(self, database: SQLiteDatabase) -> None:
        self._database = database

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
            conn = self._database.connect()
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
            conn = self._database.connect()
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

        with closing(self._database.connect()) as conn:
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
