from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

from zeus.envfile import parse_env_text


def load_dotenv(path: Path = Path(".env")) -> dict[str, str]:
    if not path.exists():
        return {}
    return parse_env_text(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    hermes_root: Path
    database_path: Path
    hermes_bin: str
    host: str
    port: int
    api_key: str | None
    allow_unauth_reads: bool
    api_max_concurrent_requests: int
    api_request_timeout_seconds: float
    api_shutdown_drain_seconds: float
    api_auth_failure_rate_per_minute: int
    api_auth_failure_burst: int
    api_mutation_rate_per_minute: int
    api_mutation_burst: int
    stop_kill_after_timeout: bool
    lock_timeout_seconds: float
    readiness_timeout_seconds: float
    readiness_interval_seconds: float
    allow_legacy_pid_markers: bool
    api_idempotency_retention_seconds: int
    api_idempotency_max_records: int
    api_log_enabled: bool = True

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        merged: dict[str, str] = load_dotenv()
        merged.update(dict(os.environ if env is None else env))
        state_dir = Path(merged.get("ZEUS_STATE_DIR") or ".zeus").resolve()
        port = _port_env(merged, "ZEUS_PORT", default=4311)
        return cls(
            state_dir=state_dir,
            hermes_root=state_dir / "hermes",
            database_path=state_dir / "zeus.db",
            hermes_bin=merged.get("ZEUS_HERMES_BIN", "hermes"),
            host=merged.get("ZEUS_HOST", "127.0.0.1"),
            port=port,
            api_key=merged.get("ZEUS_API_KEY") or None,
            allow_unauth_reads=merged.get("ZEUS_ALLOW_UNAUTH_READS") == "1",
            api_max_concurrent_requests=_int_env(
                merged,
                "ZEUS_API_MAX_CONCURRENT_REQUESTS",
                default=32,
                minimum=1,
                maximum=256,
            ),
            api_request_timeout_seconds=_float_env(
                merged,
                "ZEUS_API_REQUEST_TIMEOUT_SECONDS",
                default=10.0,
                minimum=0.1,
                maximum=300.0,
            ),
            api_shutdown_drain_seconds=_float_env(
                merged,
                "ZEUS_API_SHUTDOWN_DRAIN_SECONDS",
                default=20.0,
                minimum=0.0,
                maximum=300.0,
            ),
            api_auth_failure_rate_per_minute=_int_env(
                merged,
                "ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE",
                default=30,
                minimum=1,
                maximum=6000,
            ),
            api_auth_failure_burst=_int_env(
                merged,
                "ZEUS_API_AUTH_FAILURE_BURST",
                default=10,
                minimum=1,
                maximum=1000,
            ),
            api_mutation_rate_per_minute=_int_env(
                merged,
                "ZEUS_API_MUTATION_RATE_PER_MINUTE",
                default=120,
                minimum=1,
                maximum=6000,
            ),
            api_mutation_burst=_int_env(
                merged,
                "ZEUS_API_MUTATION_BURST",
                default=30,
                minimum=1,
                maximum=1000,
            ),
            stop_kill_after_timeout=merged.get("ZEUS_STOP_KILL_AFTER_TIMEOUT") == "1",
            lock_timeout_seconds=_float_env(
                merged, "ZEUS_LOCK_TIMEOUT_SECONDS", default=30.0, minimum=0.1, maximum=300.0
            ),
            readiness_timeout_seconds=_float_env(
                merged,
                "ZEUS_READINESS_TIMEOUT_SECONDS",
                default=30.0,
                minimum=0.1,
                maximum=300.0,
            ),
            readiness_interval_seconds=_float_env(
                merged,
                "ZEUS_READINESS_INTERVAL_SECONDS",
                default=0.5,
                minimum=0.05,
                maximum=60.0,
            ),
            allow_legacy_pid_markers=merged.get("ZEUS_ALLOW_LEGACY_PID_MARKERS", "1") == "1",
            api_idempotency_retention_seconds=_int_env(
                merged,
                "ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS",
                default=86_400,
                minimum=60,
                maximum=604_800,
            ),
            api_idempotency_max_records=_int_env(
                merged,
                "ZEUS_API_IDEMPOTENCY_MAX_RECORDS",
                default=10_000,
                minimum=100,
                maximum=1_000_000,
            ),
            api_log_enabled=merged.get("ZEUS_API_LOG_ENABLED", "1") == "1",
        )

    def ensure_dirs(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.hermes_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.state_dir / "logs").mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.state_dir / "locks" / "bots").mkdir(parents=True, exist_ok=True, mode=0o700)


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_api_exposure(host: str, api_key: str | None, allow_unauth_reads: bool) -> None:
    if is_loopback_host(host):
        return
    if allow_unauth_reads:
        raise ValueError("ZEUS_ALLOW_UNAUTH_READS cannot be enabled on a non-loopback API bind")
    if not api_key:
        raise ValueError("non-loopback API bind requires ZEUS_API_KEY")
    if len(api_key) < 16:
        raise ValueError("non-loopback API bind requires ZEUS_API_KEY with at least 16 characters")


def _port_env(env: Mapping[str, str], name: str, *, default: int) -> int:
    raw_value = env.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 0 <= value <= 65535:
        raise ValueError(f"{name} must be between 0 and 65535")
    return value


def _int_env(
    env: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw_value = env.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _float_env(
    env: Mapping[str, str],
    name: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw_value = env.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")
    return value
