from __future__ import annotations

import contextlib
import json
import os
import signal
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer as _ThreadingHTTPServer
from pathlib import Path
from typing import Any

from zeus.config import Settings, validate_api_exposure
from zeus.process_lock import BotProcessLock
from zeus.request_context import new_request_id

HandlerFactory = Callable[[Settings], type[BaseHTTPRequestHandler]]
ServerFactory = Callable[[tuple[str, int], type[BaseHTTPRequestHandler]], Any]


class ThreadingHTTPServer(_ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: Any,
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        bind_and_activate: bool = True,
    ) -> None:
        self.api_max_concurrent_requests = int(
            getattr(RequestHandlerClass, "api_max_concurrent_requests", 32)
        )
        self.api_request_timeout_seconds = float(
            getattr(RequestHandlerClass, "api_request_timeout_seconds", 10.0)
        )
        self._request_slots = threading.BoundedSemaphore(self.api_max_concurrent_requests)
        self._request_state = threading.Condition()
        self._active_requests: set[int] = set()
        self._draining = False
        self._drain_started = threading.Event()
        self._graceful_shutdown_requested = False
        self._graceful_shutdown_timeout_seconds = 0.0
        self._graceful_shutdown_thread: threading.Thread | None = None
        self._graceful_shutdown_result: bool | None = None
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def process_request(self, request: Any, client_address: Any) -> None:
        with self._request_state:
            if self._draining:
                rejection = ("server_draining", "API server is draining")
            elif not self._request_slots.acquire(blocking=False):
                rejection = ("server_busy", "API request capacity is exhausted")
            else:
                self._active_requests.add(id(request))
                rejection = None

        if rejection is not None:
            self._reject_unavailable_request(request, *rejection)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._finish_request(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            request.settimeout(self.api_request_timeout_seconds)
            super().process_request_thread(request, client_address)
        finally:
            self._finish_request(request)

    def begin_draining(self) -> None:
        with self._request_state:
            self._draining = True
        self._drain_started.set()

    def request_graceful_shutdown(self, timeout_seconds: float) -> None:
        self._graceful_shutdown_timeout_seconds = timeout_seconds
        self._graceful_shutdown_requested = True

    def wait_until_draining(self, timeout_seconds: float) -> bool:
        return self._drain_started.wait(timeout_seconds)

    def service_actions(self) -> None:
        super().service_actions()
        if not self._graceful_shutdown_requested or self._graceful_shutdown_thread is not None:
            return
        self.begin_draining()
        coordinator = threading.Thread(target=self._complete_graceful_shutdown, daemon=True)
        coordinator.start()
        self._graceful_shutdown_thread = coordinator

    def finish_graceful_shutdown(self) -> bool | None:
        coordinator = self._graceful_shutdown_thread
        if coordinator is None:
            return None
        coordinator.join()
        return self._graceful_shutdown_result

    def wait_for_drain(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        with self._request_state:
            while self._active_requests:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._request_state.wait(remaining)
            return True

    def _finish_request(self, request: Any) -> None:
        with self._request_state:
            request_id = id(request)
            if request_id not in self._active_requests:
                return
            self._active_requests.remove(request_id)
            self._request_slots.release()
            if not self._active_requests:
                self._request_state.notify_all()

    def _complete_graceful_shutdown(self) -> None:
        try:
            self._graceful_shutdown_result = self.wait_for_drain(
                self._graceful_shutdown_timeout_seconds
            )
        finally:
            self.shutdown()

    def _reject_unavailable_request(self, request: Any, code: str, message: str) -> None:
        request_id = new_request_id()
        body = json.dumps(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "status": HTTPStatus.SERVICE_UNAVAILABLE.value,
                }
            },
            sort_keys=True,
        ).encode("utf-8")
        response = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"connection: close\r\n"
            b"content-type: application/json\r\n"
            b"cache-control: no-store\r\n"
            + f"x-request-id: {request_id}\r\n".encode("ascii")
            + b"retry-after: 1\r\n"
            + f"content-length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        with contextlib.suppress(OSError):
            request.sendall(response)


def serve(
    host: str,
    port: int,
    settings: Settings,
    *,
    handler_factory: HandlerFactory,
    server_factory: ServerFactory,
) -> None:
    runtime_settings = replace(settings, host=host, port=port)
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    validate_api_exposure(
        runtime_settings.host,
        runtime_settings.api_key,
        runtime_settings.allow_unauth_reads,
    )
    runtime_settings.ensure_dirs()
    pid = os.getpid()
    pid_path = runtime_settings.state_dir / "zeus.pid"
    api_lock = BotProcessLock(
        runtime_settings.state_dir / "locks" / "api.lock",
        timeout_seconds=min(runtime_settings.lock_timeout_seconds, 1.0),
    )
    with api_lock:
        handler = handler_factory(runtime_settings)
        server = server_factory((host, port), handler)
        previous_signal_handlers: dict[signal.Signals, Any] = {}
        try:
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGTERM, signal.SIGINT):
                    previous_signal_handlers[signum] = signal.getsignal(signum)
                    signal.signal(
                        signum,
                        lambda _signum, _frame: server.request_graceful_shutdown(
                            runtime_settings.api_shutdown_drain_seconds
                        ),
                    )
            with contextlib.suppress(KeyboardInterrupt):
                _write_api_pid(pid_path, pid)
                server.serve_forever()
        finally:
            for signum, previous_handler in previous_signal_handlers.items():
                signal.signal(signum, previous_handler)
            finish_graceful_shutdown = getattr(server, "finish_graceful_shutdown", None)
            drain_result = (
                finish_graceful_shutdown() if callable(finish_graceful_shutdown) else None
            )
            if drain_result is None:
                begin_draining = getattr(server, "begin_draining", None)
                if callable(begin_draining):
                    begin_draining()
                server.server_close()
                wait_for_drain = getattr(server, "wait_for_drain", None)
                drain_result = (
                    wait_for_drain(runtime_settings.api_shutdown_drain_seconds)
                    if callable(wait_for_drain)
                    else True
                )
            else:
                server.server_close()
            if not drain_result:
                print("warning: API shutdown drain deadline expired", file=sys.stderr)
            _remove_api_pid_if_owned(pid_path, pid)


def _write_api_pid(path: Path, pid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{pid}.{time.time_ns()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{pid}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        with contextlib.suppress(OSError):
            path.chmod(0o600)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def _remove_api_pid_if_owned(path: Path, pid: int) -> None:
    try:
        recorded_pid = int(path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, OSError, ValueError):
        return
    if recorded_pid != pid:
        return
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
