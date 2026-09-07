"""Minimal operator-run client for the pinned Hermes 0.21 API.

The caller binds the captured endpoint and credential to an exact gateway
generation before and after each call. This module never retries mutations.
"""

from __future__ import annotations

import json
import math
import re
from typing import cast

from .gateway_http import GatewayHTTPError, request_json, visible_ascii

MAX_INPUT_BYTES = 64 * 1024
MAX_STATUS_RESPONSE_BYTES = 256 * 1024
RUN_STATES = frozenset(
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
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "interrupted"})
ERROR_CODES = frozenset(
    {
        "invalid_endpoint",
        "credentials_unavailable",
        "invalid_request",
        "authentication_failed",
        "not_found",
        "conflict",
        "rate_limited",
        "unsupported_runtime",
        "gateway_unavailable",
        "invalid_response",
        "response_too_large",
        "timeout",
    }
)
_RUN_ID = re.compile(r"run_[0-9a-f]{32}")
_DEFINITE_HTTP_ERRORS = {
    400: "invalid_request",
    401: "authentication_failed",
    403: "authentication_failed",
    404: "not_found",
    409: "conflict",
    422: "invalid_request",
    429: "rate_limited",
}


class HermesRunsClientError(RuntimeError):
    """Safe fixed code and whether a mutation may already have taken effect."""

    def __init__(self, code: str, *, uncertain: bool = False) -> None:
        if code not in ERROR_CODES:
            raise ValueError("invalid client error code")
        super().__init__(code)
        self.code = code
        self.uncertain = uncertain


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError
    return cast(dict[str, object], value)


def _run_id(value: object) -> str:
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        raise ValueError
    return value


def _state(value: object, allowed: frozenset[str] = RUN_STATES) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError
    return value


def _request(
    url: str,
    api_key: str,
    path: str,
    *,
    mutation: bool = False,
    body: bytes = b"",
    upstream_key: str | None = None,
    expected_status: int = 200,
    max_bytes: int = 64 * 1024,
    timeout_seconds: float,
) -> dict[str, object]:
    try:
        http_status, payload = request_json(
            url,
            api_key,
            path,
            method="POST" if mutation else "GET",
            body=body,
            idempotency_key=upstream_key,
            success_status=expected_status,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
        )
    except GatewayHTTPError as exc:
        uncertain = mutation and exc.code not in {
            "invalid_endpoint",
            "credentials_unavailable",
            "invalid_request",
        }
        raise HermesRunsClientError(exc.code, uncertain=uncertain) from None
    if http_status in _DEFINITE_HTTP_ERRORS:
        raise HermesRunsClientError(_DEFINITE_HTTP_ERRORS[http_status])
    if http_status != expected_status or payload is None:
        code = "gateway_unavailable" if http_status >= 500 else "invalid_response"
        raise HermesRunsClientError(code, uncertain=mutation)
    return payload


def capabilities(url: str, api_key: str, *, timeout_seconds: float = 2.0) -> dict[str, object]:
    """Require authenticated async runs and durable, bounded idempotency retention."""
    payload = _request(url, api_key, "/v1/capabilities", timeout_seconds=timeout_seconds)
    try:
        auth = _mapping(payload["auth"])
        features = _mapping(payload["features"])
        idempotency = _mapping(features["runs_idempotency"])
        retention = idempotency["retention_seconds"]
        if (
            payload["object"] != "hermes.api_server.capabilities"
            or payload["platform"] != "hermes-agent"
            or auth["type"] != "bearer"
            or auth["required"] is not True
            or any(
                features[name] is not True for name in ("run_submission", "run_status", "run_stop")
            )
            or idempotency["supported"] is not True
            or idempotency["durable"] is not True
            or isinstance(retention, bool)
            or not isinstance(retention, int | float)
            or not 0 < retention <= 2**63 - 1
            or not math.isfinite(retention)
        ):
            raise ValueError
        return {
            "object": "hermes.api_server.capabilities",
            "platform": "hermes-agent",
            "auth": {"type": "bearer", "required": True},
            "features": {
                "run_submission": True,
                "run_status": True,
                "run_stop": True,
                "runs_idempotency": {
                    "supported": True,
                    "durable": True,
                    "retention_seconds": retention,
                },
            },
        }
    except (KeyError, ValueError):
        raise HermesRunsClientError("unsupported_runtime") from None


def submit(
    url: str,
    api_key: str,
    input_text: str,
    upstream_key: str,
    *,
    timeout_seconds: float = 2.0,
) -> dict[str, object]:
    """Submit input only; a lost acknowledgement always remains uncertain."""
    try:
        if (
            not input_text.strip()
            or len(input_text.encode("utf-8")) > MAX_INPUT_BYTES
            or not visible_ascii(upstream_key, 1, 255)
        ):
            raise ValueError
        body = json.dumps({"input": input_text}, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    except ValueError:
        raise HermesRunsClientError("invalid_request") from None
    payload = _request(
        url,
        api_key,
        "/v1/runs",
        mutation=True,
        body=body,
        upstream_key=upstream_key,
        expected_status=202,
        timeout_seconds=timeout_seconds,
    )
    try:
        run_id = _run_id(payload["run_id"])
        replayed = payload["replayed"]
        if not isinstance(replayed, bool):
            raise ValueError
        state = _state(payload["status"], RUN_STATES if replayed else frozenset({"started"}))
        return {"run_id": run_id, "status": state, "replayed": replayed}
    except (KeyError, ValueError):
        raise HermesRunsClientError("invalid_response", uncertain=True) from None


def _validated_run_id(run_id: str) -> str:
    try:
        return _run_id(run_id)
    except ValueError:
        raise HermesRunsClientError("invalid_request") from None


def status(
    url: str,
    api_key: str,
    run_id: str,
    *,
    include_output: bool = False,
    timeout_seconds: float = 2.0,
) -> dict[str, object]:
    """Project status and, only on explicit request, bounded textual output."""
    run_id = _validated_run_id(run_id)
    payload = _request(
        url,
        api_key,
        f"/v1/runs/{run_id}",
        max_bytes=MAX_STATUS_RESPONSE_BYTES,
        timeout_seconds=timeout_seconds,
    )
    try:
        if payload["object"] != "hermes.run" or _run_id(payload["run_id"]) != run_id:
            raise ValueError
        result: dict[str, object] = {"run_id": run_id, "status": _state(payload["status"])}
        if include_output and "output" in payload:
            output = payload["output"]
            if (
                not isinstance(output, str)
                or len(output.encode("utf-8")) > MAX_STATUS_RESPONSE_BYTES
            ):
                raise ValueError
            result["output"] = output
        return result
    except (KeyError, ValueError):
        raise HermesRunsClientError("invalid_response") from None


def stop(url: str, api_key: str, run_id: str, *, timeout_seconds: float = 2.0) -> dict[str, object]:
    """Request cooperative interruption; stopping does not mean the worker exited."""
    run_id = _validated_run_id(run_id)
    payload = _request(
        url,
        api_key,
        f"/v1/runs/{run_id}/stop",
        mutation=True,
        max_bytes=MAX_STATUS_RESPONSE_BYTES,
        timeout_seconds=timeout_seconds,
    )
    try:
        if _run_id(payload["run_id"]) != run_id:
            raise ValueError
        state = _state(payload["status"], TERMINAL_STATES | {"stopping"})
        if state != "stopping" and payload["object"] != "hermes.run":
            raise ValueError
        return {"run_id": run_id, "status": state}
    except (KeyError, ValueError):
        raise HermesRunsClientError("invalid_response", uncertain=True) from None
