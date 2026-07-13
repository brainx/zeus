from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import urlopen


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
    parsed = urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return ReadinessResult(False, "readiness URL must be loopback HTTP")
    try:
        with urlopen(url, timeout=timeout_seconds) as response:  # nosec B310
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            return ReadinessResult(False, "health payload must be a JSON object")
        if (
            payload.get("status") == expected_status
            and payload.get("platform") == expected_platform
        ):
            return ReadinessResult(True, "ready", payload)
        return ReadinessResult(False, f"unexpected health payload: {payload!r}", payload)
    except (HTTPError, URLError, OSError, json.JSONDecodeError, ValueError) as exc:
        return ReadinessResult(False, f"{type(exc).__name__}: {exc}")


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
