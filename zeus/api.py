from __future__ import annotations

import argparse
import hmac
import json
import os
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from zeus.config import Settings
from zeus.doctor import run_doctor
from zeus.models import BotCreateRequest, HermesTemplate, RestartPolicy, TemplateError, validate_id
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore


def make_handler(settings: Settings) -> type[BaseHTTPRequestHandler]:
    settings.ensure_dirs()
    store = StateStore(settings.database_path)
    store.init()
    supervisor = Supervisor(
        store,
        settings.hermes_bin,
        settings.hermes_root,
        kill_after_timeout=settings.stop_kill_after_timeout,
    )
    supervisor_lock = threading.RLock()

    class ZeusHandler(BaseHTTPRequestHandler):
        server_version = "ZeusHTTP/0.1"

        def do_GET(self) -> None:
            try:
                path = urlparse(self.path).path
                if path == "/health":
                    self._json(HTTPStatus.OK, {"status": "ok"})
                    return
                inspect_path = path.startswith("/bots/") and path.endswith("/inspect")
                self._require_key(read=not inspect_path)
                if path == "/doctor":
                    self._json(HTTPStatus.OK, run_doctor(settings).to_dict())
                elif path == "/templates":
                    self._json(HTTPStatus.OK, [template_to_dict(t) for t in TemplateStore().list()])
                elif path == "/bots":
                    self._json(HTTPStatus.OK, [bot.to_dict() for bot in store.list_bots()])
                elif path.startswith("/bots/") and path.endswith("/status"):
                    bot_id = self._bot_id_from_path(path, "status")
                    with supervisor_lock:
                        payload = supervisor.status(bot_id).to_dict()
                    self._json(HTTPStatus.OK, payload)
                elif path.startswith("/bots/") and path.endswith("/logs"):
                    bot_id = self._bot_id_from_path(path, "logs")
                    with supervisor_lock:
                        logs = supervisor.logs(bot_id)
                    self._json(HTTPStatus.OK, {"bot_id": bot_id, "logs": logs})
                elif inspect_path:
                    bot_id = self._bot_id_from_path(path, "inspect")
                    with supervisor_lock:
                        payload = supervisor.inspect(bot_id)
                    self._json(HTTPStatus.OK, payload)
                else:
                    self._json_error_response(HTTPStatus.NOT_FOUND, "invalid_request", "not found")
            except Exception as exc:
                self._json_error(exc)

        def do_POST(self) -> None:
            try:
                self._require_key(read=False)
                path = urlparse(self.path).path
                if path == "/bots":
                    body = self._read_json()
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
                    template = TemplateStore().get(request.template_id)
                    record = ProfileRenderer(settings.hermes_root).render(request, template)
                    store.upsert_bot(record)
                    store.append_audit_event(
                        "bot.create", bot_id=record.bot_id, template_id=record.template_id
                    )
                    self._json(HTTPStatus.OK, record.to_dict())
                elif path == "/bots/reconcile":
                    with supervisor_lock:
                        results = supervisor.reconcile()
                    self._json(HTTPStatus.OK, [result.to_dict() for result in results])
                elif path.startswith("/bots/") and path.endswith("/start"):
                    bot_id = self._bot_id_from_path(path, "start")
                    with supervisor_lock:
                        payload = supervisor.start(bot_id).to_dict()
                    self._json(HTTPStatus.OK, payload)
                elif path.startswith("/bots/") and path.endswith("/stop"):
                    bot_id = self._bot_id_from_path(path, "stop")
                    with supervisor_lock:
                        payload = supervisor.stop(bot_id).to_dict()
                    self._json(HTTPStatus.OK, payload)
                elif path.startswith("/bots/") and path.endswith("/restart"):
                    bot_id = self._bot_id_from_path(path, "restart")
                    with supervisor_lock:
                        payload = supervisor.restart(bot_id).to_dict()
                    self._json(HTTPStatus.OK, payload)
                elif path.startswith("/bots/") and path.endswith("/reconcile"):
                    bot_id = self._bot_id_from_path(path, "reconcile")
                    with supervisor_lock:
                        results = supervisor.reconcile(bot_id)
                    self._json(HTTPStatus.OK, [result.to_dict() for result in results])
                else:
                    self._json_error_response(HTTPStatus.NOT_FOUND, "invalid_request", "not found")
            except Exception as exc:
                self._json_error(exc)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            self._require_json_content_type()
            raw_length = self.headers.get("content-length") or "0"
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValueError("content-length must be an integer") from exc
            if length < 0:
                raise ValueError("content-length must be non-negative")
            if length > 1_000_000:
                raise ValueError("request body too large")
            data = self.rfile.read(length) if length else b"{}"
            parsed = json.loads(data.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("request body must be a JSON object")
            return parsed

        def _require_json_content_type(self) -> None:
            content_type = self.headers.get("content-type", "")
            if content_type and "application/json" not in content_type.lower():
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

        def _require_key(self, *, read: bool) -> None:
            if read and settings.allow_unauth_reads:
                return
            if not settings.api_key:
                self._json_error_response(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "missing_api_key",
                    "ZEUS_API_KEY is required for non-health endpoints",
                )
                raise _ResponseSent
            provided = self.headers.get("x-zeus-api-key") or ""
            if not hmac.compare_digest(provided, settings.api_key):
                self._json_error_response(
                    HTTPStatus.UNAUTHORIZED,
                    "invalid_api_key",
                    "invalid api key",
                )
                raise _ResponseSent

        def _json_error(self, exc: Exception) -> None:
            if isinstance(exc, _ResponseSent):
                return
            if isinstance(exc, KeyError):
                status, code, message = _key_error_response(exc)
                self._json_error_response(status, code, message)
            elif isinstance(exc, TemplateError):
                code = (
                    "invalid_bot_id"
                    if str(exc).startswith("bot_id must match")
                    else "invalid_request"
                )
                self._json_error_response(HTTPStatus.BAD_REQUEST, code, str(exc))
            elif isinstance(exc, ValueError):
                self._json_error_response(HTTPStatus.BAD_REQUEST, "invalid_request", str(exc))
            else:
                self._json_error_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error",
                )

        def _json_error_response(self, status: HTTPStatus, code: str, message: str) -> None:
            self._json(
                status,
                {"error": {"code": code, "message": message, "status": status.value}},
            )

        def _json(self, status: HTTPStatus, payload: Any) -> None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status.value)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.end_headers()
            self.wfile.write(data)

        def do_PUT(self) -> None:
            self._method_not_allowed()

        def do_PATCH(self) -> None:
            self._method_not_allowed()

        def do_DELETE(self) -> None:
            self._method_not_allowed()

        def _method_not_allowed(self) -> None:
            self._json_error_response(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "method not allowed",
            )

    return ZeusHandler


class _ResponseSent(Exception):
    pass


def _key_error_response(exc: KeyError) -> tuple[HTTPStatus, str, str]:
    detail = exc.args[0] if exc.args else "missing required field"
    message = str(detail)
    if message.startswith("unknown bot:"):
        return HTTPStatus.NOT_FOUND, "unknown_bot", message
    if message.startswith("unknown template:"):
        return HTTPStatus.BAD_REQUEST, "unknown_template", message
    return HTTPStatus.BAD_REQUEST, "invalid_request", f"missing required field: {message}"


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
    settings = settings or Settings.from_env()
    handler = make_handler(settings)
    settings.ensure_dirs()
    (settings.state_dir / "zeus.pid").write_text(str(os.getpid()), encoding="utf-8")
    server = ThreadingHTTPServer((host, port), handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    serve(host=args.host or settings.host, port=args.port or settings.port, settings=settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
