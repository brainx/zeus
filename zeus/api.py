from __future__ import annotations

import argparse
import contextlib
import hmac
import json
import os
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any, NoReturn
from urllib.parse import urlparse

from zeus import api_request
from zeus.api_errors import map_api_exception
from zeus.api_logging import ApiLogWriter
from zeus.api_request import (
    decode_json_object,
    normalize_api_path,
    parse_query,
)
from zeus.api_server import ThreadingHTTPServer
from zeus.api_server import serve as _serve_server
from zeus.config import Settings
from zeus.doctor import run_doctor
from zeus.idempotency import IdempotencyClaim, canonical_request_hash, hash_key
from zeus.models import (
    BotCreateRequest,
    BotStatus,
    HermesTemplate,
    RestartPolicy,
    validate_id,
)
from zeus.process_lock import LockTimeoutError
from zeus.rate_limit import TokenBucket
from zeus.reconciliation import (
    MAX_RECONCILE_TEXT_LENGTH,
    ReconcileOutcome,
)
from zeus.request_context import RequestContext, new_request_id, route_template
from zeus.state import MAX_IDEMPOTENCY_RESPONSE_BYTES, StateReadinessError, StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore

BOT_CREATE_FIELDS = frozenset(
    {
        "bot_id",
        "template_id",
        "display_name",
        "env",
        "restart_policy",
        "restart_backoff_seconds",
        "restart_max_attempts",
    }
)
MAX_JSON_DEPTH = api_request.MAX_JSON_DEPTH
MAX_QUERY_FIELDS = api_request.MAX_QUERY_FIELDS
MAX_IDEMPOTENCY_MESSAGE_JSON_BYTES = 4_096
_IDEMPOTENCY_MESSAGE_REPLACEMENT = "response message omitted because it exceeded the replay budget"
_IDEMPOTENCY_OWNER_LOCK = threading.Lock()
_IDEMPOTENCY_OWNER_PID: int | None = None
_IDEMPOTENCY_OWNER_ID: str | None = None
_MUTATION_ACTIONS = frozenset({"start", "stop", "restart", "reconcile"})


def _process_idempotency_owner_id(*, pid: int | None = None) -> str:
    current_pid = os.getpid() if pid is None else pid
    global _IDEMPOTENCY_OWNER_ID, _IDEMPOTENCY_OWNER_PID
    with _IDEMPOTENCY_OWNER_LOCK:
        if current_pid != _IDEMPOTENCY_OWNER_PID or _IDEMPOTENCY_OWNER_ID is None:
            _IDEMPOTENCY_OWNER_PID = current_pid
            _IDEMPOTENCY_OWNER_ID = new_request_id()
        return _IDEMPOTENCY_OWNER_ID


def _is_recognized_mutation_path(path: str) -> bool:
    if path in {"/bots", "/bots/reconcile"}:
        return True
    parts = path.split("/")
    return (
        len(parts) == 4
        and parts[0] == ""
        and parts[1] == "bots"
        and bool(parts[2])
        and parts[3] in _MUTATION_ACTIONS
    )


@dataclass(frozen=True)
class BufferedJsonResponse:
    status: HTTPStatus
    body: object
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _PreparedMutation:
    route: str
    query: dict[str, list[str]]
    body: object
    execute: Callable[[], BufferedJsonResponse]
    preclaim: Callable[[], BufferedJsonResponse | None] | None = None


def _fleet_reconcile_response_ceiling(
    snapshot: Iterable[tuple[str, str]],
    *,
    summary: bool = False,
) -> int:
    if summary:
        return _fleet_reconcile_summary_response_ceiling(snapshot)
    max_message = "x" * (MAX_IDEMPOTENCY_MESSAGE_JSON_BYTES - len(json.dumps("")))
    longest_status = max((status.value for status in BotStatus), key=len)
    total = len(b"[]")
    for index, (bot_id, profile_path) in enumerate(snapshot):
        item = {
            "bot_id": bot_id,
            "message": max_message,
            "pid": -(2**63),
            "profile_path": profile_path,
            "status": longest_status,
        }
        total += len(json.dumps(item, sort_keys=True).encode("utf-8"))
        if index:
            total += len(b", ")
        if total > MAX_IDEMPOTENCY_RESPONSE_BYTES:
            return MAX_IDEMPOTENCY_RESPONSE_BYTES + 1
    return total


def _fleet_reconcile_summary_response_ceiling(
    snapshot: Iterable[tuple[str, str]],
) -> int:
    longest_status = max((status.value for status in BotStatus), key=len)
    longest_outcome = max((outcome.value for outcome in ReconcileOutcome), key=len)
    max_escaped_text = "\U0010ffff" * MAX_RECONCILE_TEXT_LENGTH
    max_message_json_size = len(json.dumps(max_escaped_text).encode("utf-8"))
    bounded_message_json_size = min(
        max_message_json_size,
        MAX_IDEMPOTENCY_MESSAGE_JSON_BYTES,
    )
    if max_message_json_size > MAX_IDEMPOTENCY_MESSAGE_JSON_BYTES:
        bounded_message_json_size = max(
            bounded_message_json_size,
            len(json.dumps(_IDEMPOTENCY_MESSAGE_REPLACEMENT).encode("utf-8")),
        )
    max_bounded_message = "x" * (bounded_message_json_size - len(json.dumps("").encode("utf-8")))
    counts = {outcome.value: 0 for outcome in ReconcileOutcome}
    payload = {
        "run_id": "x" * 32,
        "scope": "fleet",
        "started_at": "9999-12-31T23:59:59.999999+00:00",
        "finished_at": "9999-12-31T23:59:59.999999+00:00",
        "outcome": "completed_with_errors",
        "ok": False,
        "counts": counts,
        "total": 0,
        "results": [],
    }
    total = len(json.dumps(payload, sort_keys=True).encode("utf-8"))
    bot_count = 0
    for index, (bot_id, _profile_path) in enumerate(snapshot):
        bot_count = index + 1
        item = {
            "bot_id": bot_id,
            "outcome": longest_outcome,
            "desired_state": "running",
            "observed_status": longest_status,
            "pid": 2**63 - 1,
            "action": max_escaped_text,
            "message": max_bounded_message,
            "error_code": max_escaped_text,
            "event_id": 2**63 - 1,
            "started_at": "9999-12-31T23:59:59.999999+00:00",
            "finished_at": "9999-12-31T23:59:59.999999+00:00",
        }
        total += len(json.dumps(item, sort_keys=True).encode("utf-8"))
        if index:
            total += len(b", ")
        if total > MAX_IDEMPOTENCY_RESPONSE_BYTES:
            return MAX_IDEMPOTENCY_RESPONSE_BYTES + 1
    numeric_growth = 7 * (len(str(bot_count)) - 1) if bot_count else 0
    total += numeric_growth
    if total > MAX_IDEMPOTENCY_RESPONSE_BYTES:
        return MAX_IDEMPOTENCY_RESPONSE_BYTES + 1
    return total


def _bound_idempotent_messages(value: object) -> tuple[object, bool]:
    if isinstance(value, list):
        bounded_items: list[object] = []
        exceeds_response_cap = False
        for item in value:
            bounded, exceeds = _bound_idempotent_messages(item)
            bounded_items.append(bounded)
            exceeds_response_cap = exceeds_response_cap or exceeds
        return bounded_items, exceeds_response_cap
    if isinstance(value, dict):
        bounded_mapping: dict[object, object] = {}
        exceeds_response_cap = False
        for key, item in value.items():
            if key == "message" and isinstance(item, str):
                encoded_size = len(json.dumps(item).encode("utf-8"))
                if encoded_size > MAX_IDEMPOTENCY_RESPONSE_BYTES:
                    exceeds_response_cap = True
                bounded_mapping[key] = (
                    item
                    if encoded_size <= MAX_IDEMPOTENCY_MESSAGE_JSON_BYTES
                    else _IDEMPOTENCY_MESSAGE_REPLACEMENT
                )
                continue
            bounded, exceeds = _bound_idempotent_messages(item)
            bounded_mapping[key] = bounded
            exceeds_response_cap = exceeds_response_cap or exceeds
        return bounded_mapping, exceeds_response_cap
    return value, False


def make_handler(settings: Settings) -> type[BaseHTTPRequestHandler]:
    settings.ensure_dirs()
    api_log_writer = ApiLogWriter(
        settings.state_dir / "logs" / "api.jsonl",
        enabled=settings.api_log_enabled,
    )
    store = StateStore(
        settings.database_path,
        synchronous=settings.sqlite_synchronous,
    )
    store.init()
    supervisor = Supervisor(
        store,
        settings.hermes_bin,
        settings.hermes_root,
        kill_after_timeout=settings.stop_kill_after_timeout,
        lock_timeout_seconds=settings.lock_timeout_seconds,
        readiness_timeout_seconds=settings.readiness_timeout_seconds,
        readiness_interval_seconds=settings.readiness_interval_seconds,
        allow_legacy_pid_markers=settings.allow_legacy_pid_markers,
    )
    idempotency_owner_instance_id = _process_idempotency_owner_id()
    auth_failure_bucket = TokenBucket(
        settings.api_auth_failure_rate_per_minute,
        settings.api_auth_failure_burst,
    )
    mutation_bucket = TokenBucket(
        settings.api_mutation_rate_per_minute,
        settings.api_mutation_burst,
    )

    class ZeusHandler(BaseHTTPRequestHandler):
        server_version = "ZeusHTTP/0.1"
        api_max_concurrent_requests = settings.api_max_concurrent_requests
        api_request_timeout_seconds = settings.api_request_timeout_seconds
        _request_context: RequestContext
        _response_status: int
        _response_error_code: str | None
        _validated_query_values: dict[str, list[str]]

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            if code == HTTPStatus.NOT_IMPLEMENTED:
                self._handle_request(self._method_not_allowed)
                return
            super().send_error(code, message, explain)

        def do_GET(self) -> None:
            self._handle_request(self._dispatch_get)

        def _dispatch_get(self) -> None:
            path = self._normalized_path()
            is_history = path.startswith("/bots/") and path.endswith("/history")
            if path == "/health":
                self._request_context.auth_outcome = "not_required"
                self._validate_query_parameters(set())
                self._json(HTTPStatus.OK, {"status": "ok"})
                return
            if is_history:
                self._require_key(read=False)
                self._validate_query_parameters({"limit", "before"})
            else:
                self._validate_query_parameters(set())
                self._require_key(read=not self._get_requires_strict_auth(path))
            if path == "/ready":
                try:
                    schema_version = store.check_readiness()
                except StateReadinessError:
                    self._json_error_response(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "not_ready",
                        "state store is not ready",
                    )
                    return
                self._json(
                    HTTPStatus.OK,
                    {"schema_version": schema_version, "status": "ready"},
                )
            elif path == "/doctor":
                self._json(HTTPStatus.OK, run_doctor(settings).to_dict())
            elif path == "/templates":
                self._json(HTTPStatus.OK, [template_to_dict(t) for t in TemplateStore().list()])
            elif path == "/bots":
                self._json(HTTPStatus.OK, [bot.to_dict() for bot in store.list_bots()])
            elif path.startswith("/bots/") and path.endswith("/status"):
                bot_id = self._bot_id_from_path(path, "status")
                payload = supervisor.status(
                    bot_id,
                    source="api",
                    request_id=self._request_context.request_id,
                ).to_dict()
                self._json(HTTPStatus.OK, payload)
            elif path.startswith("/bots/") and path.endswith("/logs"):
                bot_id = self._bot_id_from_path(path, "logs")
                logs = supervisor.logs(bot_id)
                self._json(HTTPStatus.OK, {"bot_id": bot_id, "logs": logs})
            elif is_history:
                bot_id = self._bot_id_from_path(path, "history")
                limit = self._integer_query("limit", default=50, minimum=1, maximum=1000)
                if limit is None:
                    raise AssertionError("history limit default is required")
                self._json(
                    HTTPStatus.OK,
                    store.history_payload(
                        bot_id,
                        limit=limit,
                        before=self._integer_query("before", default=None, minimum=1, maximum=None),
                    ),
                )
            elif path.startswith("/bots/") and path.endswith("/inspect"):
                bot_id = self._bot_id_from_path(path, "inspect")
                payload = supervisor.inspect(bot_id)
                self._json(HTTPStatus.OK, payload)
            else:
                self._json_error_response(HTTPStatus.NOT_FOUND, "invalid_request", "not found")

        def do_POST(self) -> None:
            self._handle_request(self._dispatch_post)

        def _dispatch_post(self) -> None:
            path = self._normalized_path()
            self._require_key(read=False)
            if not _is_recognized_mutation_path(path):
                self._json_error_response(HTTPStatus.NOT_FOUND, "invalid_request", "not found")
                return
            self._consume_mutation_capacity()
            prepared = self._prepare_mutation(path)
            if prepared is None:
                self._json_error_response(HTTPStatus.NOT_FOUND, "invalid_request", "not found")
                return

            key_values = self.headers.get_all("idempotency-key") or []
            if not key_values:
                response = prepared.execute()
                self._json(response.status, response.body, headers=response.headers)
                return

            if len(key_values) != 1:
                raise ValueError("idempotency key has an invalid format")
            key_hash = hash_key(key_values[0])
            del key_values
            request_hash = canonical_request_hash(
                "POST", prepared.route, prepared.query, prepared.body
            )
            if prepared.preclaim is not None:
                try:
                    existing = store.lookup_idempotency(
                        key_hash=key_hash,
                        request_hash=request_hash,
                        owner_instance_id=idempotency_owner_instance_id,
                    )
                except Exception as exc:
                    existing = IdempotencyClaim("unavailable")
                    api_log_writer.error(self._request_context.request_id, exc)
                if existing is not None and self._handle_idempotency_outcome(existing):
                    return
                try:
                    rejection = prepared.preclaim()
                except Exception as exc:
                    self._request_context.idempotency_outcome = "unavailable"
                    api_log_writer.error(self._request_context.request_id, exc)
                    self._json_error_response(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "idempotency_store_unavailable",
                        "idempotency store is unavailable",
                    )
                    return
                if rejection is not None:
                    if isinstance(rejection.body, dict):
                        error = rejection.body.get("error")
                        if isinstance(error, dict) and isinstance(error.get("code"), str):
                            self._response_error_code = error["code"]
                    self._json(rejection.status, rejection.body, headers=rejection.headers)
                    return
            claimed_at = datetime.now(UTC)
            expires_at = claimed_at + timedelta(seconds=settings.api_idempotency_retention_seconds)
            try:
                claim = store.claim_idempotency(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    owner_instance_id=idempotency_owner_instance_id,
                    expires_at=expires_at,
                    max_records=settings.api_idempotency_max_records,
                )
            except Exception as exc:
                self._request_context.idempotency_outcome = "unavailable"
                api_log_writer.error(self._request_context.request_id, exc)
                self._json_error_response(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "idempotency_store_unavailable",
                    "idempotency store is unavailable",
                )
                return
            if self._handle_idempotency_outcome(claim):
                return

            try:
                response = prepared.execute()
            except Exception as exc:
                response = self._buffer_error(exc)
            response, response_json = self._finalize_idempotent_response(response)
            try:
                completed_at = datetime.now(UTC)
                store.complete_idempotency(
                    key_hash=key_hash,
                    request_hash=request_hash,
                    owner_instance_id=idempotency_owner_instance_id,
                    response_status=response.status.value,
                    response_json=response_json,
                    completed_at=completed_at,
                    expires_at=completed_at
                    + timedelta(seconds=settings.api_idempotency_retention_seconds),
                )
            except Exception as exc:
                self._request_context.idempotency_outcome = "unavailable"
                api_log_writer.error(self._request_context.request_id, exc)
                self._json_error_response(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "idempotency_store_unavailable",
                    "idempotency store is unavailable",
                )
                return
            self._write_serialized_json(
                response.status.value,
                response_json,
                headers=response.headers,
            )

        def _prepare_mutation(self, path: str) -> _PreparedMutation | None:
            if path == "/bots":
                self._validate_query_parameters({"replace", "stop"})
                body = self._read_json()
                self._validate_request_fields(body, BOT_CREATE_FIELDS)
                request = BotCreateRequest(
                    bot_id=body["bot_id"],
                    template_id=body["template_id"],
                    display_name=body.get("display_name"),
                    env=self._env_from_body(body),
                    restart_policy=RestartPolicy(body.get("restart_policy", "manual")),
                    restart_backoff_seconds=self._float_from_body(
                        body, "restart_backoff_seconds", 5.0
                    ),
                    restart_max_attempts=self._int_from_body(body, "restart_max_attempts", 5),
                )
                replace_existing = self._bool_query("replace", default=False) or False
                stop_if_running = self._bool_query("stop", default=False) or False
                normalized_body = {
                    "bot_id": request.bot_id,
                    "template_id": request.template_id,
                    "display_name": request.display_name,
                    "env": request.env,
                    "restart_policy": request.restart_policy.value,
                    "restart_backoff_seconds": request.restart_backoff_seconds,
                    "restart_max_attempts": request.restart_max_attempts,
                }

                def create() -> BufferedJsonResponse:
                    template = TemplateStore().get(request.template_id)
                    record = supervisor.create_bot(
                        request,
                        template,
                        replace_existing=replace_existing,
                        stop_if_running=stop_if_running,
                        source="api",
                        request_id=self._request_context.request_id,
                    )
                    return BufferedJsonResponse(HTTPStatus.OK, record.to_dict())

                return _PreparedMutation(
                    path,
                    {
                        "replace": [str(replace_existing).lower()],
                        "stop": [str(stop_if_running).lower()],
                    },
                    normalized_body,
                    create,
                )
            if path == "/bots/reconcile":
                self._validate_query_parameters({"summary"})
                summary_requested = self._summary_query()
                self._require_empty_body()
                idempotent_snapshot: tuple[tuple[str, str], ...] | None = None

                def preclaim_reconcile_all() -> BufferedJsonResponse | None:
                    nonlocal idempotent_snapshot
                    idempotent_snapshot = tuple(
                        sorted((bot.bot_id, bot.profile_path) for bot in store.list_bots())
                    )
                    if (
                        _fleet_reconcile_response_ceiling(
                            idempotent_snapshot,
                            summary=summary_requested,
                        )
                        > MAX_IDEMPOTENCY_RESPONSE_BYTES
                    ):
                        return BufferedJsonResponse(
                            HTTPStatus.UNPROCESSABLE_ENTITY,
                            {
                                "error": {
                                    "code": "idempotency_response_too_large",
                                    "message": "fleet response exceeds replay budget",
                                    "status": HTTPStatus.UNPROCESSABLE_ENTITY.value,
                                }
                            },
                        )
                    return None

                def reconcile_all() -> BufferedJsonResponse:
                    if summary_requested and idempotent_snapshot is None:
                        summary = supervisor.reconcile_summary(
                            source="api",
                            request_id=self._request_context.request_id,
                        )
                        payload: object = summary.to_dict()
                    elif summary_requested:
                        summary = supervisor.reconcile_summary(
                            source="api",
                            request_id=self._request_context.request_id,
                            bot_snapshot=idempotent_snapshot,
                        )
                        payload = summary.to_dict()
                    elif idempotent_snapshot is None:
                        results = supervisor.reconcile(
                            source="api", request_id=self._request_context.request_id
                        )
                        payload = [result.to_dict() for result in results]
                    else:
                        results = supervisor.reconcile(
                            source="api",
                            request_id=self._request_context.request_id,
                            bot_snapshot=idempotent_snapshot,
                        )
                        payload = [result.to_dict() for result in results]
                    return BufferedJsonResponse(HTTPStatus.OK, payload)

                return _PreparedMutation(
                    path,
                    {"summary": ["1"]} if summary_requested else {},
                    None,
                    reconcile_all,
                    preclaim_reconcile_all,
                )

            parts = path.split("/")
            if (
                len(parts) != 4
                or parts[0] != ""
                or parts[1] != "bots"
                or not parts[2]
                or parts[3] not in _MUTATION_ACTIONS
            ):
                return None
            action = parts[3]
            raw_bot_id = parts[2]
            allowed_query = self._post_query_parameters(path)
            if allowed_query is None:
                return None
            self._validate_query_parameters(allowed_query)
            self._require_empty_body()
            bot_id = validate_id(raw_bot_id, "bot_id")

            if action == "start":
                wait = self._bool_query("wait", default=False) or False
                timeout = self._float_query("timeout")

                def start() -> BufferedJsonResponse:
                    payload = supervisor.start(
                        bot_id,
                        wait=wait,
                        timeout_seconds=timeout,
                        source="api",
                        request_id=self._request_context.request_id,
                    ).to_dict()
                    return BufferedJsonResponse(HTTPStatus.OK, payload)

                query = {"wait": [str(wait).lower()]}
                if timeout is not None:
                    query["timeout"] = [str(timeout)]
                return _PreparedMutation(path, query, None, start)
            if action == "stop":
                kill_after_timeout = self._bool_query("kill_after_timeout", default=None)

                def stop() -> BufferedJsonResponse:
                    payload = supervisor.stop(
                        bot_id,
                        kill_after_timeout=kill_after_timeout,
                        source="api",
                        request_id=self._request_context.request_id,
                    ).to_dict()
                    return BufferedJsonResponse(HTTPStatus.OK, payload)

                query = {
                    "kill_after_timeout": [
                        "default" if kill_after_timeout is None else str(kill_after_timeout).lower()
                    ]
                }
                return _PreparedMutation(path, query, None, stop)
            if action == "restart":
                restart_wait = self._bool_query("wait", default=False) or False
                restart_timeout = self._float_query("timeout")

                def restart() -> BufferedJsonResponse:
                    if restart_wait or restart_timeout is not None:
                        payload = supervisor.restart(
                            bot_id,
                            wait=restart_wait,
                            timeout_seconds=restart_timeout,
                            source="api",
                            request_id=self._request_context.request_id,
                        ).to_dict()
                    else:
                        payload = supervisor.restart(
                            bot_id,
                            source="api",
                            request_id=self._request_context.request_id,
                        ).to_dict()
                    return BufferedJsonResponse(HTTPStatus.OK, payload)

                query = {"wait": [str(restart_wait).lower()]}
                if restart_timeout is not None:
                    query["timeout"] = [str(restart_timeout)]
                return _PreparedMutation(path, query, None, restart)

            summary_requested = self._summary_query()

            def reconcile_one() -> BufferedJsonResponse:
                if summary_requested:
                    summary = supervisor.reconcile_summary(
                        bot_id,
                        source="api",
                        request_id=self._request_context.request_id,
                    )
                    return BufferedJsonResponse(HTTPStatus.OK, summary.to_dict())
                results = supervisor.reconcile(
                    bot_id,
                    source="api",
                    request_id=self._request_context.request_id,
                )
                return BufferedJsonResponse(HTTPStatus.OK, [result.to_dict() for result in results])

            return _PreparedMutation(
                path,
                {"summary": ["1"]} if summary_requested else {},
                None,
                reconcile_one,
            )

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            self._require_json_content_type()
            length = self._content_length(required=True)
            if length > 1_000_000:
                raise ValueError("request body too large")
            data = self.rfile.read(length) if length else b"{}"
            return decode_json_object(data)

        def _require_json_content_type(self) -> None:
            content_encoding = self.headers.get("content-encoding", "").strip().lower()
            if content_encoding and content_encoding != "identity":
                self._json_error_response(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    "content-encoding is not supported",
                )
                raise _ResponseSent
            content_type = self.headers.get("content-type", "")
            media_type = content_type.partition(";")[0].strip().lower()
            if media_type != "application/json":
                self._json_error_response(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    "content-type must be application/json",
                )
                raise _ResponseSent

        def _env_from_body(self, body: dict[str, Any]) -> dict[str, str]:
            env = body.get("env") or {}
            if not isinstance(env, dict):
                raise ValueError("env must be an object")
            result: dict[str, str] = {}
            for key, value in env.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValueError("env keys and values must be strings")
                result[key] = value
            return result

        def _float_from_body(self, body: dict[str, Any], name: str, default: float) -> float:
            value = body.get(name, default)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a number")
            return float(value)

        def _int_from_body(self, body: dict[str, Any], name: str, default: int) -> int:
            value = body.get(name, default)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            return value

        def _bot_id_from_path(self, path: str, action: str) -> str:
            parts = path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "bots" or parts[2] != action:
                raise ValueError("invalid bot route")
            return validate_id(parts[1], "bot_id")

        def _normalized_path(self) -> str:
            return normalize_api_path(self.path)

        def _query_values(self) -> dict[str, list[str]]:
            return self._validated_query_values

        def _validate_query_parameters(self, allowed: set[str]) -> None:
            self._validated_query_values = parse_query(self.path, frozenset(allowed))

        def _post_query_parameters(self, path: str) -> set[str] | None:
            if path == "/bots":
                return {"replace", "stop"}
            if path == "/bots/reconcile" or path.endswith("/reconcile"):
                return {"summary"}
            if path.endswith("/start") or path.endswith("/restart"):
                return {"wait", "timeout"}
            if path.endswith("/stop"):
                return {"kill_after_timeout"}
            return None

        def _summary_query(self) -> bool:
            values = self._query_values().get("summary")
            if not values:
                return False
            if values[0] != "1":
                raise ValueError("summary must be 1")
            return True

        def _validate_request_fields(self, body: dict[str, Any], allowed: frozenset[str]) -> None:
            unknown = sorted(set(body) - allowed)
            if unknown:
                raise ValueError(f"unknown request field: {unknown[0]}")

        def _content_length(self, *, required: bool) -> int:
            raw_length = self.headers.get("content-length")
            if raw_length is None:
                if required:
                    raise ValueError("content-length is required")
                return 0
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("content-length must be an integer") from exc
            if length < 0:
                raise ValueError("content-length must be non-negative")
            return length

        def _require_empty_body(self) -> None:
            if self._content_length(required=False) != 0:
                raise ValueError("request body is not allowed for this endpoint")

        def _bool_query(self, name: str, *, default: bool | None) -> bool | None:
            values = self._query_values().get(name)
            if not values:
                return default
            value = values[-1].strip().lower()
            if value in {"1", "true", "yes", "on"}:
                return True
            if value in {"0", "false", "no", "off", ""}:
                return False
            raise ValueError(f"{name} must be a boolean")

        def _float_query(self, name: str) -> float | None:
            values = self._query_values().get(name)
            if not values:
                return None
            try:
                value = float(values[-1])
            except ValueError as exc:
                raise ValueError(f"{name} must be a number") from exc
            if not 0.1 <= value <= 300:
                raise ValueError(f"{name} must be between 0.1 and 300")
            return value

        def _integer_query(
            self,
            name: str,
            *,
            default: int | None,
            minimum: int,
            maximum: int | None,
        ) -> int | None:
            values = self._query_values().get(name)
            if not values:
                return default
            try:
                value = int(values[-1])
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if value < minimum:
                if maximum is None:
                    raise ValueError(f"{name} must be positive")
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            if maximum is not None and value > maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            return value

        def _get_requires_strict_auth(self, path: str) -> bool:
            return path.startswith("/bots/") and (
                path.endswith("/inspect") or path.endswith("/logs") or path.endswith("/history")
            )

        def _require_key(self, *, read: bool) -> None:
            if read and settings.allow_unauth_reads:
                self._request_context.auth_outcome = "allowed_unauthenticated"
                return
            if not settings.api_key:
                self._request_context.auth_outcome = "unconfigured"
                self._json_error_response(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "missing_api_key",
                    "ZEUS_API_KEY is required for non-health endpoints",
                )
                raise _ResponseSent
            provided = self.headers.get("x-zeus-api-key")
            if not provided:
                self._request_context.auth_outcome = "missing"
                self._reject_invalid_api_key()
            if not hmac.compare_digest(provided, settings.api_key):
                self._request_context.auth_outcome = "rejected"
                self._reject_invalid_api_key()
            self._request_context.auth_outcome = "authenticated"

        def _reject_invalid_api_key(self) -> NoReturn:
            decision = auth_failure_bucket.consume()
            if decision.allowed:
                self._json_error_response(
                    HTTPStatus.UNAUTHORIZED,
                    "invalid_api_key",
                    "invalid api key",
                )
            else:
                self._json_error_response(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "auth_rate_limited",
                    "API authentication rate limit exceeded",
                    headers={"Retry-After": str(decision.retry_after_seconds)},
                )
            raise _ResponseSent

        def _consume_mutation_capacity(self) -> None:
            decision = mutation_bucket.consume()
            if decision.allowed:
                return
            self._json_error_response(
                HTTPStatus.TOO_MANY_REQUESTS,
                "mutation_rate_limited",
                "API mutation rate limit exceeded",
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )
            raise _ResponseSent

        def _json_error(self, exc: Exception) -> None:
            if isinstance(exc, _ResponseSent):
                return
            error = map_api_exception(exc)
            if error.log_exception:
                api_log_writer.error(self._request_context.request_id, exc)
            self._json_error_response(error.status, error.code, error.message)

        def _handle_idempotency_outcome(self, claim: IdempotencyClaim) -> bool:
            if claim.kind == "claimed":
                self._request_context.idempotency_outcome = "claimed"
                return False
            if claim.kind == "replay":
                self._request_context.idempotency_outcome = "replayed"
                if claim.response_status is None or claim.response_json is None:
                    raise RuntimeError("stored idempotency response is incomplete")
                if (
                    type(claim.response_status) is not int
                    or not 200 <= claim.response_status <= 599
                ):
                    self._request_context.idempotency_outcome = "unavailable"
                    self._json_error_response(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "idempotency_store_unavailable",
                        "idempotency store is unavailable",
                    )
                    return True
                self._response_error_code = self._serialized_error_code(claim.response_json)
                self._write_serialized_json(
                    claim.response_status,
                    claim.response_json,
                    headers={"idempotency-replayed": "true"},
                )
                return True
            self._request_context.idempotency_outcome = claim.kind
            if claim.kind == "conflict":
                self._json_error_response(
                    HTTPStatus.CONFLICT,
                    "idempotency_key_conflict",
                    "idempotency key was already used for a different request",
                )
                return True
            if claim.kind == "in_progress":
                self._json_error_response(
                    HTTPStatus.CONFLICT,
                    "idempotency_in_progress",
                    "idempotent request is already in progress",
                    headers={"retry-after": "1"},
                )
                return True
            if claim.kind == "indeterminate":
                self._json_error_response(
                    HTTPStatus.CONFLICT,
                    "idempotency_indeterminate",
                    "prior idempotent request outcome is indeterminate",
                )
                return True
            if claim.kind == "unavailable":
                self._json_error_response(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "idempotency_store_unavailable",
                    "idempotency store is unavailable",
                )
                return True
            raise RuntimeError("invalid idempotency claim outcome")

        def _buffer_error(self, exc: Exception) -> BufferedJsonResponse:
            error = map_api_exception(exc)
            if error.log_exception:
                api_log_writer.error(self._request_context.request_id, exc)
            self._response_error_code = error.code
            return BufferedJsonResponse(
                error.status,
                {
                    "error": {
                        "code": error.code,
                        "message": error.message,
                        "status": error.status.value,
                    }
                },
            )

        def _buffer_internal_error(self, exc: Exception) -> BufferedJsonResponse:
            api_log_writer.error(self._request_context.request_id, exc)
            self._response_error_code = "internal_error"
            return BufferedJsonResponse(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {
                    "error": {
                        "code": "internal_error",
                        "message": "internal server error",
                        "status": HTTPStatus.INTERNAL_SERVER_ERROR.value,
                    }
                },
            )

        def _json_error_response(
            self,
            status: HTTPStatus,
            code: str,
            message: str,
            *,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            self._response_error_code = code
            self._json(
                status,
                {"error": {"code": code, "message": message, "status": status.value}},
                headers=headers,
            )

        def _json(
            self,
            status: HTTPStatus,
            payload: Any,
            *,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            self._write_serialized_json(
                status.value,
                self._serialize_json(payload),
                headers=headers,
            )

        def _serialize_json(self, payload: object) -> str:
            return json.dumps(payload, sort_keys=True)

        def _serialize_idempotent_json(self, payload: object) -> str:
            return json.dumps(payload, sort_keys=True, allow_nan=False)

        def _finalize_idempotent_response(
            self, response: BufferedJsonResponse
        ) -> tuple[BufferedJsonResponse, str]:
            try:
                bounded_body, oversized_message = _bound_idempotent_messages(response.body)
            except RecursionError as exc:
                response = self._buffer_internal_error(exc)
                return response, self._serialize_idempotent_json(response.body)
            if oversized_message:
                response = self._buffer_internal_error(
                    ValueError("idempotent response exceeded the replay budget")
                )
            else:
                response = replace(response, body=bounded_body)
            try:
                response_json = self._serialize_idempotent_json(response.body)
            except (TypeError, ValueError) as exc:
                response = self._buffer_internal_error(exc)
                response_json = self._serialize_idempotent_json(response.body)
            if len(response_json.encode("utf-8")) > MAX_IDEMPOTENCY_RESPONSE_BYTES:
                response = self._buffer_internal_error(
                    ValueError("idempotent response exceeded the replay budget")
                )
                response_json = self._serialize_idempotent_json(response.body)
            if len(response_json.encode("utf-8")) > MAX_IDEMPOTENCY_RESPONSE_BYTES:
                raise RuntimeError("internal idempotency response exceeds replay budget")
            return response, response_json

        def _serialized_error_code(self, response_json: str) -> str | None:
            try:
                payload = json.loads(response_json)
                error = payload.get("error") if isinstance(payload, dict) else None
                code = error.get("code") if isinstance(error, dict) else None
                if isinstance(code, str):
                    return code
            except (TypeError, ValueError):
                pass
            return None

        def _write_serialized_json(
            self,
            status: int,
            response_json: str,
            *,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            data = response_json.encode("utf-8")
            self._response_status = status
            self.send_response(status)
            self.send_header("x-request-id", self._request_context.request_id)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.send_header("cross-origin-resource-policy", "same-origin")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def do_PUT(self) -> None:
            self._handle_request(self._method_not_allowed)

        def do_PATCH(self) -> None:
            self._handle_request(self._method_not_allowed)

        def do_DELETE(self) -> None:
            self._handle_request(self._method_not_allowed)

        def do_OPTIONS(self) -> None:
            self._handle_request(self._method_not_allowed)

        def _handle_request(self, dispatch: Callable[[], None]) -> None:
            self._request_context = RequestContext(
                request_id=new_request_id(),
                started_at=time.monotonic(),
                method=self.command if self.command in {"GET", "POST"} else "UNSUPPORTED",
            )
            self._request_context.route = _safe_route_template(self.path)
            self._response_status = HTTPStatus.INTERNAL_SERVER_ERROR.value
            self._response_error_code = None
            self._validated_query_values = {}
            try:
                dispatch()
            except Exception as exc:
                with contextlib.suppress(Exception):
                    self._json_error(exc)
            finally:
                api_log_writer.access(
                    self._request_context.finish(
                        self._response_status,
                        self._response_error_code,
                    )
                )

        def _method_not_allowed(self) -> None:
            self._request_context.auth_outcome = "not_required"
            self._json_error_response(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method not allowed",
                headers={"allow": "GET, POST"},
            )

    return ZeusHandler


class _ResponseSent(Exception):
    pass


def _safe_route_template(target: str) -> str | None:
    try:
        return route_template(urlparse(target).path)
    except (UnicodeError, ValueError):
        return None


def template_to_dict(template: HermesTemplate) -> dict[str, Any]:
    return {
        "id": template.id,
        "name": template.name,
        "description": template.description,
        "version": template.version,
        "metadata": template.metadata,
        "delegation": template.hermes.delegation.to_config(),
    }


def serve(host: str, port: int, settings: Settings | None = None) -> None:
    base_settings = settings or Settings.from_env()
    _serve_server(
        host,
        port,
        base_settings,
        handler_factory=make_handler,
        server_factory=ThreadingHTTPServer,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        settings = Settings.from_env()
    except ValueError as exc:
        print(f"Invalid Zeus configuration: {exc}", file=sys.stderr)
        return 1
    try:
        serve(
            host=args.host or settings.host,
            port=args.port if args.port is not None else settings.port,
            settings=settings,
        )
    except (LockTimeoutError, OSError, ValueError) as exc:
        print(f"Zeus API failed to start: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
