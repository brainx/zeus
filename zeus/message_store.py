from __future__ import annotations

import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeus.models import validate_id
from zeus.schema import _assert_schema_current

MAX_MESSAGE_RECEIPTS = 10_000
ATTEMPT_LEASE_SECONDS = 30
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{32}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_ENDPOINT = re.compile(r"http://(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})/health\Z")
_RUN_STATES = frozenset(
    {
        "queued",
        "running",
        "waiting_for_approval",
        "stopping",
        "completed",
        "failed",
        "cancelled",
        "interrupted",
    }
)
_TERMINAL = frozenset({"completed", "failed", "cancelled", "interrupted"})
_DISPATCH_STATES = frozenset({"prepared", "unknown", "accepted", "rejected"})
_ERROR_CODES = frozenset(
    {
        "runtime_changed",
        "interrupted",
        "health_unavailable",
        "invalid_endpoint",
        "credentials_unavailable",
        "authentication_failed",
        "unsupported_runtime",
        "invalid_health",
        "pid_mismatch",
        "timeout",
        "invalid_request",
        "not_found",
        "conflict",
        "rate_limited",
        "gateway_unavailable",
        "invalid_response",
        "response_too_large",
    }
)
_LIST_QUERIES = {
    (False, False): "SELECT * FROM message_receipts "
    "ORDER BY created_at DESC, message_id DESC LIMIT ?",
    (True, False): "SELECT * FROM message_receipts WHERE target_bot_id = ? "
    "ORDER BY created_at DESC, message_id DESC LIMIT ?",
    (False, True): "SELECT * FROM message_receipts WHERE (created_at, message_id) < (?, ?) "
    "ORDER BY created_at DESC, message_id DESC LIMIT ?",
    (True, True): "SELECT * FROM message_receipts WHERE target_bot_id = ? "
    "AND (created_at, message_id) < (?, ?) ORDER BY created_at DESC, message_id DESC LIMIT ?",
}


class MessageStoreError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"message receipt operation failed: {code}")


@dataclass(frozen=True)
class MessageReceipt:
    message_id: str
    request_key_hash: str | None
    target_bot_id: str
    target_created_at: datetime
    target_fingerprint: str
    endpoint: str
    credential_fingerprint: str
    request_hash: str
    upstream_key: str
    dispatch_state: str
    run_id: str | None
    run_status: str | None
    created_at: datetime
    updated_at: datetime
    retry_before: datetime
    last_checked_at: datetime | None
    cancel_requested_at: datetime | None
    released_at: datetime | None
    lease_until: datetime | None
    error_code: str | None
    version: int


def _identifier(value: str, *, hashed: bool = False) -> str:
    if not isinstance(value, str) or (_HASH if hashed else _UUID).fullmatch(value) is None:
        raise ValueError("message receipt identifier is invalid")
    return value


def _time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("message receipt timestamp must be timezone-aware")
    try:
        return value.astimezone(UTC)
    except OverflowError:
        raise ValueError("message receipt timestamp is invalid") from None


def _stored_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("stored message receipt timestamp is invalid")
    parsed = _time(datetime.fromisoformat(value))
    if parsed.isoformat() != value:
        raise ValueError("stored message receipt timestamp is not normalized")
    return parsed


def _endpoint(value: str) -> str:
    matched = _ENDPOINT.fullmatch(value) if isinstance(value, str) else None
    if matched is None or not 1 <= int(matched.group(1)) <= 65535:
        raise ValueError("message receipt endpoint is invalid")
    return value


def _version(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ValueError("message receipt version is invalid")
    return value


def _validate_result(
    state: str, run_id: str | None, run_status: str | None, error: str | None
) -> None:
    if state not in _DISPATCH_STATES or (error is not None and error not in _ERROR_CODES):
        raise ValueError("message receipt result is invalid")
    if state == "accepted":
        if (
            not isinstance(run_id, str)
            or _RUN_ID.fullmatch(run_id) is None
            or run_status not in _RUN_STATES
        ):
            raise ValueError("message receipt run is invalid")
    elif run_id is not None or run_status is not None:
        raise ValueError("message receipt cannot have a run before acceptance")


def _receipt(row: sqlite3.Row, *, observe: bool = False) -> MessageReceipt:
    try:
        for name in ("message_id", "upstream_key"):
            _identifier(row[name])
        for name in ("target_fingerprint", "credential_fingerprint", "request_hash"):
            _identifier(row[name], hashed=True)
        if row["request_key_hash"] is not None:
            _identifier(row["request_key_hash"], hashed=True)
        validate_id(row["target_bot_id"], "bot_id")
        _endpoint(row["endpoint"])
        _validate_result(row["dispatch_state"], row["run_id"], row["run_status"], row["error_code"])
        times = {
            name: _stored_time(row[name])
            for name in ("target_created_at", "created_at", "updated_at", "retry_before")
        }
        optional = {
            name: _stored_time(row[name]) if row[name] is not None else None
            for name in ("last_checked_at", "cancel_requested_at", "released_at", "lease_until")
        }
        if not times["target_created_at"] <= times["created_at"] <= times[
            "updated_at"
        ] or not timedelta(0) < times["retry_before"] - times["created_at"] <= timedelta(days=1):
            raise ValueError("message receipt times are inconsistent")
        for name in ("last_checked_at", "cancel_requested_at", "released_at"):
            stamp = optional[name]
            if stamp is not None and not times["created_at"] <= stamp <= times["updated_at"]:
                raise ValueError("message receipt observation time is inconsistent")
        if optional["released_at"] is not None and row["dispatch_state"] != "accepted":
            raise ValueError("only acknowledged message receipts can be released")
        lease = optional["lease_until"]
        if row["dispatch_state"] == "prepared":
            if lease is None or lease != times["updated_at"] + timedelta(
                seconds=ATTEMPT_LEASE_SECONDS
            ):
                raise ValueError("message receipt lease is invalid")
        elif lease is not None:
            raise ValueError("message receipt lease is invalid")
        receipt = MessageReceipt(
            message_id=row["message_id"],
            request_key_hash=row["request_key_hash"],
            target_bot_id=row["target_bot_id"],
            target_created_at=times["target_created_at"],
            target_fingerprint=row["target_fingerprint"],
            endpoint=row["endpoint"],
            credential_fingerprint=row["credential_fingerprint"],
            request_hash=row["request_hash"],
            upstream_key=row["upstream_key"],
            dispatch_state=row["dispatch_state"],
            run_id=row["run_id"],
            run_status=row["run_status"],
            created_at=times["created_at"],
            updated_at=times["updated_at"],
            retry_before=times["retry_before"],
            last_checked_at=optional["last_checked_at"],
            cancel_requested_at=optional["cancel_requested_at"],
            released_at=optional["released_at"],
            lease_until=lease,
            error_code=row["error_code"],
            version=_version(row["version"]),
        )
        return (
            replace(receipt, dispatch_state="unknown")
            if observe and receipt.dispatch_state == "prepared"
            else receipt
        )
    except (IndexError, TypeError, ValueError, OverflowError):
        raise MessageStoreError("invalid_receipt") from None


class MessageStore:
    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        try:
            uri = f"{self.database_path.resolve().as_uri()}?mode=rw"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys=ON")
                # Commit dispatch intent durably before sending any request, without
                # initializing missing state or changing its existing journal mode.
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute("PRAGMA busy_timeout=5000")
                with conn:
                    conn.execute("BEGIN IMMEDIATE")
                    _assert_schema_current(conn)
                    yield conn
        except MessageStoreError:
            raise
        except (sqlite3.Error, OSError, RuntimeError, TypeError, ValueError):
            raise MessageStoreError("state_unavailable") from None

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        try:
            uri = f"{self.database_path.resolve().as_uri()}?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                _assert_schema_current(conn)
                yield conn
        except MessageStoreError:
            raise
        except (sqlite3.Error, OSError, RuntimeError, TypeError, ValueError):
            raise MessageStoreError("state_unavailable") from None

    def get(self, message_id: str) -> MessageReceipt | None:
        _identifier(message_id)
        with self._read() as conn:
            row = conn.execute(
                "SELECT * FROM message_receipts WHERE message_id = ?", (message_id,)
            ).fetchone()
            return _receipt(row, observe=True) if row is not None else None

    def list(
        self, *, bot_id: str | None = None, limit: int = 50, before: str | None = None
    ) -> dict[str, object]:
        if bot_id is not None:
            validate_id(bot_id, "bot_id")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("message receipt limit must be between 1 and 100")
        if before is not None:
            _identifier(before)
        with self._read() as conn:
            parameters: list[str | int] = []
            if bot_id is not None:
                parameters.append(bot_id)
            if before is not None:
                cursor_row = conn.execute(
                    "SELECT * FROM message_receipts WHERE message_id = ?", (before,)
                ).fetchone()
                if cursor_row is None:
                    raise MessageStoreError("invalid_cursor")
                cursor = _receipt(cursor_row)
                if bot_id is not None and cursor.target_bot_id != bot_id:
                    raise MessageStoreError("invalid_cursor")
                parameters.extend((cursor.created_at.isoformat(), cursor.message_id))
            parameters.append(limit + 1)
            rows = conn.execute(
                _LIST_QUERIES[(bot_id is not None, before is not None)],
                parameters,
            ).fetchall()
            items = [_receipt(row, observe=True) for row in rows[:limit]]
        return {"items": items, "next_before": items[-1].message_id if len(rows) > limit else None}

    def prepare(
        self,
        *,
        bot_id: str,
        incarnation: datetime,
        target_fingerprint: str,
        endpoint: str,
        credential_fingerprint: str,
        input_fingerprint: str,
        request_key_fingerprint: str | None,
        now: datetime,
        retry_before: datetime,
    ) -> tuple[MessageReceipt, bool]:
        validate_id(bot_id, "bot_id")
        for value in (target_fingerprint, credential_fingerprint, input_fingerprint):
            _identifier(value, hashed=True)
        if request_key_fingerprint is not None:
            _identifier(request_key_fingerprint, hashed=True)
        _endpoint(endpoint)
        incarnation, now, retry_before = _time(incarnation), _time(now), _time(retry_before)
        if incarnation > now or not timedelta(
            seconds=ATTEMPT_LEASE_SECONDS
        ) < retry_before - now <= timedelta(days=1):
            raise ValueError("message receipt retry window is invalid")
        with self._write() as conn:
            if request_key_fingerprint is not None:
                row = conn.execute(
                    "SELECT * FROM message_receipts WHERE request_key_hash = ?",
                    (request_key_fingerprint,),
                ).fetchone()
                if row is not None:
                    existing = _receipt(row, observe=True)
                    if (
                        existing.target_bot_id,
                        existing.target_created_at,
                        existing.target_fingerprint,
                        existing.endpoint,
                        existing.credential_fingerprint,
                        existing.request_hash,
                    ) != (
                        bot_id,
                        incarnation,
                        target_fingerprint,
                        endpoint,
                        credential_fingerprint,
                        input_fingerprint,
                    ):
                        raise MessageStoreError("request_conflict")
                    self._check_clock(existing, now)
                    return existing, False
            blocker = conn.execute(
                "SELECT * FROM message_receipts WHERE target_bot_id = ? "
                "AND target_created_at = ? AND released_at IS NULL "
                "AND (dispatch_state IN ('prepared', 'unknown') OR "
                "(dispatch_state = 'accepted' AND run_status NOT IN "
                "('completed', 'failed', 'cancelled', 'interrupted'))) LIMIT 1",
                (bot_id, incarnation.isoformat()),
            ).fetchone()
            if blocker is not None:
                _receipt(blocker)
                raise MessageStoreError("bot_busy")
            if (
                conn.execute("SELECT count(*) FROM message_receipts").fetchone()[0]
                >= MAX_MESSAGE_RECEIPTS
            ):
                raise MessageStoreError("capacity_exceeded")
            message_id, upstream_key = uuid.uuid4().hex, uuid.uuid4().hex
            conn.execute(
                "INSERT INTO message_receipts (message_id, request_key_hash, target_bot_id, "
                "target_created_at, target_fingerprint, endpoint, credential_fingerprint, "
                "request_hash, upstream_key, dispatch_state, created_at, updated_at, "
                "retry_before, lease_until, version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, 1)",
                (
                    message_id,
                    request_key_fingerprint,
                    bot_id,
                    incarnation.isoformat(),
                    target_fingerprint,
                    endpoint,
                    credential_fingerprint,
                    input_fingerprint,
                    upstream_key,
                    now.isoformat(),
                    now.isoformat(),
                    retry_before.isoformat(),
                    (now + timedelta(seconds=ATTEMPT_LEASE_SECONDS)).isoformat(),
                ),
            )
            return self._load(conn, message_id), True

    @staticmethod
    def _load(conn: sqlite3.Connection, message_id: str) -> MessageReceipt:
        row = conn.execute(
            "SELECT * FROM message_receipts WHERE message_id = ?", (message_id,)
        ).fetchone()
        if row is None:
            raise MessageStoreError("receipt_changed")
        return _receipt(row)

    @staticmethod
    def _check_clock(receipt: MessageReceipt, now: datetime) -> None:
        if now < receipt.updated_at:
            raise MessageStoreError("clock_rollback")

    def _current(
        self, conn: sqlite3.Connection, message_id: str, expected_version: int, now: datetime
    ) -> MessageReceipt:
        receipt = self._load(conn, message_id)
        if receipt.version != expected_version:
            raise MessageStoreError("receipt_changed")
        self._check_clock(receipt, now)
        return receipt

    def claim_retry(
        self, message_id: str, *, expected_version: int, now: datetime
    ) -> MessageReceipt:
        _identifier(message_id)
        _version(expected_version)
        now = _time(now)
        with self._write() as conn:
            receipt = self._current(conn, message_id, expected_version, now)
            if receipt.dispatch_state not in {"prepared", "unknown"}:
                raise MessageStoreError("invalid_transition")
            if now >= receipt.retry_before:
                raise MessageStoreError("retry_expired")
            if receipt.lease_until is not None and now < receipt.lease_until:
                raise MessageStoreError("attempt_in_progress")
            conn.execute(
                "UPDATE message_receipts SET dispatch_state = 'prepared', "
                "updated_at = ?, lease_until = ?, "
                "version = version + 1, error_code = NULL WHERE message_id = ?",
                (
                    now.isoformat(),
                    (now + timedelta(seconds=ATTEMPT_LEASE_SECONDS)).isoformat(),
                    message_id,
                ),
            )
            return self._load(conn, message_id)

    def finish_attempt(
        self,
        message_id: str,
        *,
        expected_version: int,
        dispatch_state: str,
        run_id: str | None = None,
        run_status: str | None = None,
        error_code: str | None = None,
        now: datetime,
    ) -> MessageReceipt:
        _identifier(message_id)
        _version(expected_version)
        if dispatch_state not in {"unknown", "accepted", "rejected"}:
            raise ValueError("message dispatch result is invalid")
        _validate_result(dispatch_state, run_id, run_status, error_code)
        now = _time(now)
        with self._write() as conn:
            receipt = self._current(conn, message_id, expected_version, now)
            if receipt.dispatch_state != "prepared":
                raise MessageStoreError("invalid_transition")
            conn.execute(
                "UPDATE message_receipts SET dispatch_state = ?, run_id = ?, "
                "run_status = ?, error_code = ?, "
                "updated_at = ?, lease_until = NULL, version = version + 1 WHERE message_id = ?",
                (dispatch_state, run_id, run_status, error_code, now.isoformat(), message_id),
            )
            return self._load(conn, message_id)

    def release(self, message_id: str, *, expected_version: int, now: datetime) -> MessageReceipt:
        _identifier(message_id)
        _version(expected_version)
        now = _time(now)
        with self._write() as conn:
            receipt = self._current(conn, message_id, expected_version, now)
            if receipt.dispatch_state != "accepted":
                raise MessageStoreError("run_unacknowledged")
            if receipt.released_at is not None:
                return receipt
            if receipt.run_status in _TERMINAL:
                raise MessageStoreError("run_already_terminal")
            # Keep the acknowledgement, last observation and request-key tombstone.
            # Release is an operator decision, never evidence that execution stopped.
            conn.execute(
                "UPDATE message_receipts SET released_at = ?, updated_at = ?, "
                "version = version + 1 WHERE message_id = ?",
                (now.isoformat(), now.isoformat(), message_id),
            )
            return self._load(conn, message_id)

    def record_cancel_intent(
        self, message_id: str, *, expected_version: int, now: datetime
    ) -> MessageReceipt:
        _identifier(message_id)
        _version(expected_version)
        now = _time(now)
        with self._write() as conn:
            receipt = self._current(conn, message_id, expected_version, now)
            if receipt.dispatch_state != "accepted":
                raise MessageStoreError("invalid_transition")
            # Intent is durable before the request, but it cannot make a
            # cached run status appear to have been observed more recently.
            conn.execute(
                "UPDATE message_receipts SET updated_at = ?, "
                "cancel_requested_at = COALESCE(cancel_requested_at, ?), "
                "version = version + 1 WHERE message_id = ?",
                (now.isoformat(), now.isoformat(), message_id),
            )
            return self._load(conn, message_id)

    def update_run(
        self,
        message_id: str,
        *,
        expected_version: int,
        run_status: str,
        now: datetime,
        cancel_requested: bool = False,
    ) -> MessageReceipt:
        _identifier(message_id)
        _version(expected_version)
        if run_status not in _RUN_STATES or type(cancel_requested) is not bool:
            raise ValueError("message run observation is invalid")
        now = _time(now)
        with self._write() as conn:
            receipt = self._current(conn, message_id, expected_version, now)
            if receipt.dispatch_state != "accepted" or (
                receipt.run_status in _TERMINAL and run_status != receipt.run_status
            ):
                raise MessageStoreError("invalid_transition")
            conn.execute(
                "UPDATE message_receipts SET run_status = ?, updated_at = ?, last_checked_at = ?, "
                "cancel_requested_at = COALESCE(cancel_requested_at, ?), "
                "version = version + 1 WHERE message_id = ?",
                (
                    run_status,
                    now.isoformat(),
                    now.isoformat(),
                    now.isoformat() if cancel_requested else None,
                    message_id,
                ),
            )
            return self._load(conn, message_id)
