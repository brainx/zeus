from __future__ import annotations

from datetime import UTC, datetime


class AuditServiceError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
