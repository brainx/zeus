from __future__ import annotations

import unittest
from http import HTTPStatus
from pathlib import Path

from zeus.api_errors import ApiError, map_api_exception
from zeus.errors import ZeusConflictError
from zeus.models import TemplateError
from zeus.process_lock import LockTimeoutError
from zeus.reconciliation import ReconcileLockTimeoutError


class ApiErrorMappingTests(unittest.TestCase):
    def test_maps_public_exception_contract(self) -> None:
        cases = (
            (
                "unknown_bot",
                KeyError("unknown bot: coder"),
                ApiError(HTTPStatus.NOT_FOUND, "unknown_bot", "unknown bot: coder"),
            ),
            (
                "unknown_template",
                KeyError("unknown template: missing"),
                ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "unknown_template",
                    "unknown template: missing",
                ),
            ),
            (
                "missing_field",
                KeyError("bot_id"),
                ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "missing required field: bot_id",
                ),
            ),
            (
                "invalid_bot_id",
                TemplateError("bot_id must match ^[a-z][a-z0-9-]{1,62}$"),
                ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_bot_id",
                    "bot_id must match ^[a-z][a-z0-9-]{1,62}$",
                ),
            ),
            (
                "template_error",
                TemplateError("template contract failed"),
                ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "template contract failed",
                ),
            ),
            (
                "reconcile_lock",
                ReconcileLockTimeoutError(Path("/tmp/reconcile.lock"), 0.1),
                ApiError(
                    HTTPStatus.CONFLICT,
                    "reconcile_locked",
                    "reconciliation is already in progress",
                ),
            ),
            (
                "bot_lock",
                LockTimeoutError(Path("/tmp/coder.lock"), 0.1),
                ApiError(
                    HTTPStatus.CONFLICT,
                    "bot_locked",
                    "bot lifecycle operation is already in progress",
                ),
            ),
            (
                "conflict",
                ZeusConflictError("conflicting lifecycle state"),
                ApiError(
                    HTTPStatus.CONFLICT,
                    "conflict",
                    "conflicting lifecycle state",
                ),
            ),
            (
                "value_error",
                ValueError("invalid lifecycle request"),
                ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "invalid lifecycle request",
                ),
            ),
            (
                "internal_error",
                RuntimeError("private failure detail"),
                ApiError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error",
                    log_exception=True,
                ),
            ),
        )

        for name, exception, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(expected, map_api_exception(exception))


if __name__ == "__main__":
    unittest.main()
