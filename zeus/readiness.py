from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

MAX_READINESS_RESPONSE_BYTES = 64 * 1024


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _build_readiness_opener() -> OpenerDirector:
    return build_opener(ProxyHandler({}), _RejectRedirects())


@dataclass(frozen=True)
class ReadinessProbe:
    url: str
    expected_status: str = "ok"
    expected_platform: str = "hermes-agent"
    timeout_seconds: float = 30.0
    interval_seconds: float = 0.5


@dataclass(frozen=True)
class ReadinessResult:
    ready: bool
    message: str
    payload: dict[str, object] | None = None


def readiness_probe_from_env(
    env: Mapping[str, str],
    *,
    timeout_seconds: float,
    interval_seconds: float,
) -> ReadinessProbe | None:
    if env.get("API_SERVER_ENABLED") != "1":
        return None
    port = _validated_port(env.get("API_SERVER_PORT"))
    if port is None:
        return None
    host = _loopback_probe_host(env.get("API_SERVER_HOST", "127.0.0.1"))
    if host is None:
        return None
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return ReadinessProbe(
        url=f"http://{display_host}:{port}/health",
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
    )


def probe_once(
    url: str,
    timeout_seconds: float = 1.0,
    *,
    expected_status: str = "ok",
    expected_platform: str = "hermes-agent",
) -> ReadinessResult:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError:
        return ReadinessResult(False, "readiness URL must be loopback HTTP")
    if (
        parsed.scheme != "http"
        or hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return ReadinessResult(False, "readiness URL must be loopback HTTP")
    try:
        request = Request(url, headers={"Connection": "close"})  # nosec B310
        with _build_readiness_opener().open(request, timeout=timeout_seconds) as response:
            content_lengths = response.headers.get_all("content-length", [])
            try:
                declared_lengths = {int(value) for value in content_lengths}
            except ValueError:
                return ReadinessResult(False, "readiness response has invalid content length")
            if any(length < 0 for length in declared_lengths) or len(declared_lengths) > 1:
                return ReadinessResult(False, "readiness response has invalid content length")
            if any(length > MAX_READINESS_RESPONSE_BYTES for length in declared_lengths):
                return ReadinessResult(False, "readiness response exceeds size limit")
            # HTTPResponse.read(amt) clamps amt to its internal Content-Length. The
            # connection-close request lets an honest fixed-length response reach EOF,
            # while clearing this CPython parser field exposes any understated trailing
            # data to the same bounded MAX + 1 read. Chunk framing remains handled by
            # HTTPResponse because chunked responses already have length=None.
            response.length = None
            body = response.read(MAX_READINESS_RESPONSE_BYTES + 1)
        if len(body) > MAX_READINESS_RESPONSE_BYTES:
            return ReadinessResult(False, "readiness response exceeds size limit")
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            return ReadinessResult(False, "health payload must be a JSON object")
        if (
            payload.get("status") == expected_status
            and payload.get("platform") == expected_platform
        ):
            return ReadinessResult(True, "ready", payload)
        return ReadinessResult(False, "unexpected readiness health payload")
    except HTTPError as exc:
        exc.close()
        return ReadinessResult(False, "readiness endpoint returned an HTTP error")
    except (URLError, OSError):
        return ReadinessResult(False, "readiness probe failed")
    except HTTPException:
        return ReadinessResult(False, "readiness endpoint returned a malformed HTTP response")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return ReadinessResult(False, "readiness response is not valid JSON")


def wait_until_ready(probe: ReadinessProbe) -> ReadinessResult:
    deadline = time.monotonic() + probe.timeout_seconds
    last = ReadinessResult(False, "not probed yet")
    while time.monotonic() < deadline:
        last = probe_once(
            probe.url,
            timeout_seconds=min(5.0, max(0.2, probe.interval_seconds)),
            expected_status=probe.expected_status,
            expected_platform=probe.expected_platform,
        )
        if last.ready:
            return last
        time.sleep(probe.interval_seconds)
    return ReadinessResult(False, f"readiness timeout: {last.message}", last.payload)


def _validated_port(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        port = int(value)
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _loopback_probe_host(value: str) -> str | None:
    host = value.strip().strip("[]").lower()
    any_ipv4_host = ".".join(("0", "0", "0", "0"))
    if host in {"", any_ipv4_host}:
        return "127.0.0.1"
    if host == "::":
        return "::1"
    if host in {"127.0.0.1", "localhost", "::1"}:
        return host
    return None
