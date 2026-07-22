from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus

from zeus.errors import ZeusConflictError
from zeus.models import TemplateError
from zeus.process_lock import LockTimeoutError
from zeus.reconciliation import ReconcileLockTimeoutError


@dataclass(frozen=True)
class ApiError:
    status: HTTPStatus
    code: str
    message: str
    log_exception: bool = False


def map_api_exception(exc: Exception) -> ApiError:
    if isinstance(exc, KeyError):
        return _map_key_error(exc)
    if isinstance(exc, TemplateError):
        code = "invalid_bot_id" if str(exc).startswith("bot_id must match") else "invalid_request"
        return ApiError(HTTPStatus.BAD_REQUEST, code, str(exc))
    if isinstance(exc, ReconcileLockTimeoutError):
        return ApiError(
            HTTPStatus.CONFLICT,
            "reconcile_locked",
            "reconciliation is already in progress",
        )
    if isinstance(exc, LockTimeoutError):
        return ApiError(
            HTTPStatus.CONFLICT,
            "bot_locked",
            "bot lifecycle operation is already in progress",
        )
    if isinstance(exc, ZeusConflictError):
        return ApiError(HTTPStatus.CONFLICT, exc.code, str(exc))
    if isinstance(exc, ValueError):
        return ApiError(HTTPStatus.BAD_REQUEST, "invalid_request", str(exc))
    return ApiError(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "internal_error",
        "internal server error",
        log_exception=True,
    )


def _map_key_error(exc: KeyError) -> ApiError:
    detail = exc.args[0] if exc.args else "missing required field"
    message = str(detail)
    if message.startswith("unknown bot:"):
        return ApiError(HTTPStatus.NOT_FOUND, "unknown_bot", message)
    if message.startswith("unknown template:"):
        return ApiError(HTTPStatus.BAD_REQUEST, "unknown_template", message)
    return ApiError(
        HTTPStatus.BAD_REQUEST,
        "invalid_request",
        f"missing required field: {message}",
    )
