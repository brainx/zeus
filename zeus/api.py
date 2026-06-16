from __future__ import annotations

import argparse
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from zeus.config import Settings
from zeus.doctor import run_doctor
from zeus.models import BotCreateRequest, TemplateError, validate_id
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore


def make_handler(settings: Settings):
    settings.ensure_dirs()
    store = StateStore(settings.database_path)
    store.init()

    class ZeusHandler(BaseHTTPRequestHandler):
        server_version = "ZeusHTTP/0.1"

        def do_GET(self) -> None:
            try:
                path = urlparse(self.path).path
                if path == "/health":
                    self._json(HTTPStatus.OK, {"status": "ok"})
                elif path == "/doctor":
                    self._json(HTTPStatus.OK, run_doctor(settings).to_dict())
                elif path == "/templates":
                    self._json(HTTPStatus.OK, [template_to_dict(t) for t in TemplateStore().list()])
                elif path == "/bots":
                    self._json(HTTPStatus.OK, [bot.to_dict() for bot in store.list_bots()])
                elif path.startswith("/bots/") and path.endswith("/status"):
                    bot_id = self._bot_id_from_path(path, "status")
                    self._json(
                        HTTPStatus.OK,
                        Supervisor(store, settings.hermes_bin, settings.hermes_root)
                        .status(bot_id)
                        .to_dict(),
                    )
                elif path.startswith("/bots/") and path.endswith("/logs"):
                    bot_id = self._bot_id_from_path(path, "logs")
                    logs = Supervisor(store, settings.hermes_bin, settings.hermes_root).logs(bot_id)
                    self._json(HTTPStatus.OK, {"bot_id": bot_id, "logs": logs})
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except Exception as exc:
                self._json_error(exc)

        def do_POST(self) -> None:
            try:
                self._require_key()
                path = urlparse(self.path).path
                if path == "/bots":
                    body = self._read_json()
                    request = BotCreateRequest(
                        bot_id=body["bot_id"],
                        template_id=body["template_id"],
                        display_name=body.get("display_name"),
                        env=self._env_from_body(body),
                    )
                    template = TemplateStore().get(request.template_id)
                    record = ProfileRenderer(settings.hermes_root).render(request, template)
                    store.upsert_bot(record)
                    self._json(HTTPStatus.OK, record.to_dict())
                elif path.startswith("/bots/") and path.endswith("/start"):
                    bot_id = self._bot_id_from_path(path, "start")
                    self._json(
                        HTTPStatus.OK,
                        Supervisor(store, settings.hermes_bin, settings.hermes_root)
                        .start(bot_id)
                        .to_dict(),
                    )
                elif path.startswith("/bots/") and path.endswith("/stop"):
                    bot_id = self._bot_id_from_path(path, "stop")
                    self._json(
                        HTTPStatus.OK,
                        Supervisor(store, settings.hermes_bin, settings.hermes_root)
                        .stop(bot_id)
                        .to_dict(),
                    )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except Exception as exc:
                self._json_error(exc)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length") or "0")
            if length > 1_000_000:
                raise ValueError("request body too large")
            data = self.rfile.read(length) if length else b"{}"
            parsed = json.loads(data.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("request body must be a JSON object")
            return parsed

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

        def _bot_id_from_path(self, path: str, action: str) -> str:
            parts = path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "bots" or parts[2] != action:
                raise ValueError("invalid bot route")
            return validate_id(parts[1], "bot_id")

        def _require_key(self) -> None:
            if not settings.api_key:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": "ZEUS_API_KEY is required for mutating endpoints"},
                )
                raise _ResponseSent
            if self.headers.get("x-zeus-api-key") != settings.api_key:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid api key"})
                raise _ResponseSent

        def _json_error(self, exc: Exception) -> None:
            if isinstance(exc, _ResponseSent):
                return
            if isinstance(exc, (KeyError, TemplateError, ValueError)):
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            else:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal server error"})

        def _json(self, status: HTTPStatus, payload: Any) -> None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status.value)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.end_headers()
            self.wfile.write(data)

    return ZeusHandler


class _ResponseSent(Exception):
    pass


def template_to_dict(template) -> dict[str, Any]:
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
