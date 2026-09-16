"""Persisted message evidence; callers must authorize observer access first."""

from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

from zeus.api_request import parse_query
from zeus.message_store import MessageReceipt, MessageStore, MessageStoreError

# Archived receipts remain durable, so counting them needs a work budget even
# though the response is small. Exceeding it never returns incomplete counts.
CAPACITY_READ_TIMEOUT_SECONDS = 2.0


def is_receipt_path(path: str) -> bool:
    return path == "/messages" or path.startswith("/messages/")


def _public_receipt(receipt: MessageReceipt) -> dict[str, object]:
    # Deliberately enumerate fields: storage identity, credentials, gateway
    # endpoints and retry authority must never become dashboard data.
    return {
        "message_id": receipt.message_id,
        "bot_id": receipt.target_bot_id,
        "dispatch_state": receipt.dispatch_state,
        "run_id": receipt.run_id,
        "run_status": receipt.run_status,
        "created_at": receipt.created_at.isoformat(),
        "updated_at": receipt.updated_at.isoformat(),
        "retry_before": receipt.retry_before.isoformat(),
        "last_checked_at": (
            receipt.last_checked_at.isoformat() if receipt.last_checked_at else None
        ),
        "cancel_requested_at": (
            receipt.cancel_requested_at.isoformat() if receipt.cancel_requested_at else None
        ),
        "released_at": receipt.released_at.isoformat() if receipt.released_at else None,
        "archived_at": receipt.archived_at.isoformat() if receipt.archived_at else None,
        "error_code": receipt.error_code,
    }


def _error(status: HTTPStatus, code: str, message: str) -> tuple[HTTPStatus, dict[str, Any]]:
    return status, {"error": {"code": code, "message": message, "status": status.value}}


def receipt_response(
    path: str, target: str, database_path: Path
) -> tuple[HTTPStatus, dict[str, Any]]:
    try:
        allowed = frozenset({"bot_id", "limit", "before"}) if path == "/messages" else frozenset()
        query = {name: values[0] for name, values in parse_query(target, allowed).items()}
        store = MessageStore(database_path)
        if path == "/messages":
            result = store.list(
                bot_id=query.get("bot_id"),
                limit=int(query.get("limit", "50")),
                before=query.get("before"),
            )
            return HTTPStatus.OK, {
                "items": [
                    _public_receipt(receipt)
                    for receipt in cast(list[MessageReceipt], result["items"])
                ],
                "next_before": result["next_before"],
            }
        if path == "/messages/capacity":
            return HTTPStatus.OK, store.capacity(read_timeout_seconds=CAPACITY_READ_TIMEOUT_SECONDS)
        parts = path.split("/")
        if len(parts) != 3 or parts[1] != "messages" or not parts[2]:
            raise ValueError("invalid message route")
        message_id = unquote(parts[2], errors="strict")
        receipt = store.get(message_id)
        if receipt is None:
            return _error(HTTPStatus.NOT_FOUND, "unknown_message", "unknown message receipt")
        return HTTPStatus.OK, _public_receipt(receipt)
    except ValueError:
        return _error(HTTPStatus.BAD_REQUEST, "invalid_request", "invalid message evidence request")
    except MessageStoreError as exc:
        if exc.code == "invalid_cursor":
            return _error(
                HTTPStatus.BAD_REQUEST, "invalid_cursor", "invalid message receipt cursor"
            )
        if exc.code == "read_budget_exceeded":
            return _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "message_read_budget_exceeded",
                "message evidence read budget exceeded",
            )
        return _error(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "message_store_unavailable",
            "message evidence is unavailable",
        )
