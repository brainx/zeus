from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

from zeus import api

ACTIVE_REQUEST_SENTINEL_ENV = "ZEUS_TEST_ACTIVE_REQUEST_SENTINEL"


def _replace_sentinel(value: str) -> None:
    sentinel = os.environ.get(ACTIVE_REQUEST_SENTINEL_ENV)
    if not sentinel:
        return
    sentinel_path = Path(sentinel)
    temporary = sentinel_path.with_name(f".{sentinel_path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        temporary.write_text(value, encoding="ascii")
        os.replace(temporary, sentinel_path)
    finally:
        temporary.unlink(missing_ok=True)


class ActiveRequestSentinelServer(api.ThreadingHTTPServer):
    def process_request(self, request: Any, client_address: Any) -> None:
        super().process_request(request, client_address)
        source_port = client_address[1] if isinstance(client_address, tuple) else None
        if type(source_port) is int and 1 <= source_port <= 65535:
            with self._request_state:
                if id(request) in self._active_requests:
                    _replace_sentinel(f"{source_port}\n")

    def _finish_request(self, request: Any) -> None:
        super()._finish_request(request)
        with self._request_state:
            if not self._active_requests:
                _replace_sentinel("idle\n")


def main() -> int:
    with patch.object(api, "ThreadingHTTPServer", ActiveRequestSentinelServer):
        return api.main()


if __name__ == "__main__":
    raise SystemExit(main())
