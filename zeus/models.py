from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SECRET_NAME_RE = re.compile(r"(API[_-]?KEY|KEY|TOKEN|SECRET|PASSWORD)$", re.IGNORECASE)
ENV_PLACEHOLDER_RE = re.compile(r"^\$\{[A-Z][A-Z0-9_]{1,127}\}$")


class TemplateError(ValueError):
    pass


class BotStatus(StrEnum):
    stopped = "stopped"
    starting = "starting"
    running = "running"
    failed = "failed"
    unknown = "unknown"


class RestartPolicy(StrEnum):
    manual = "manual"
    on_failure = "on-failure"


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TemplateError(f"{name} must be a table")
    return value


def _string(value: Any, name: str, *, min_length: int = 1, max_length: int = 20_000) -> str:
    if not isinstance(value, str):
        raise TemplateError(f"{name} must be a string")
    text = value.strip()
    if len(text) < min_length or len(text) > max_length:
        raise TemplateError(f"{name} length must be between {min_length} and {max_length}")
    return text


def _int(value: Any, name: str, *, default: int, minimum: int, maximum: int | None = None) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise TemplateError(f"{name} must be an integer")
    if value < minimum:
        raise TemplateError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise TemplateError(f"{name} must be at most {maximum}")
    return value


def _bool(value: Any, name: str, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise TemplateError(f"{name} must be a boolean")
    return value


def validate_id(value: str, name: str = "id") -> str:
    if not isinstance(value, str) or not ID_RE.match(value):
        raise TemplateError(f"{name} must match ^[a-z][a-z0-9-]{{1,62}}$")
    return value


def _validate_required_env(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise TemplateError("hermes.required_env must be a list")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not ENV_RE.match(value):
            raise TemplateError(f"invalid environment variable name: {value}")
        result.append(value)
    return sorted(set(result))


def _reject_inline_secrets(value: Any, key: str = "") -> None:
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            _reject_inline_secrets(child_value, str(child_key))
    elif isinstance(value, list):
        for child_value in value:
            _reject_inline_secrets(child_value, key)
    elif (
        isinstance(value, str)
        and SECRET_NAME_RE.search(key)
        and value
        and not ENV_PLACEHOLDER_RE.match(value)
    ):
        raise TemplateError(f"secret-like field {key} must use ${{ENV_VAR}}")


@dataclass(frozen=True)
class HermesModelConfig:
    provider: str
    default: str
    base_url: str | None = None
    api_mode: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HermesModelConfig:
        api_mode = data.get("api_mode") or None
        if api_mode is not None:
            api_mode = _string(api_mode, "hermes.model.api_mode")
            if api_mode not in {"chat_completions", "responses", "anthropic"}:
                raise TemplateError(f"unsupported hermes.model.api_mode: {api_mode}")
        return cls(
            provider=_string(data.get("provider"), "hermes.model.provider"),
            default=_string(data.get("default"), "hermes.model.default"),
            base_url=data.get("base_url") or None,
            api_mode=api_mode,
        )

    def to_config(self) -> dict[str, Any]:
        data = {"provider": self.provider, "default": self.default}
        if self.base_url:
            data["base_url"] = self.base_url
        if self.api_mode:
            data["api_mode"] = self.api_mode
        return data


@dataclass(frozen=True)
class HermesTerminalConfig:
    backend: str = "docker"
    cwd: str = "."
    home_mode: str = "profile"
    timeout: int = 300
    docker_image: str | None = None
    docker_mount_cwd_to_workspace: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HermesTerminalConfig:
        backend = _string(data.get("backend", "docker"), "hermes.terminal.backend")
        if backend not in {"local", "docker", "ssh", "modal", "daytona", "singularity"}:
            raise TemplateError(f"unsupported terminal backend: {backend}")
        home_mode = _string(data.get("home_mode", "profile"), "hermes.terminal.home_mode")
        if home_mode not in {"auto", "real", "profile"}:
            raise TemplateError(f"unsupported terminal home_mode: {home_mode}")
        cwd = _string(data.get("cwd", "."), "hermes.terminal.cwd")
        if cwd.startswith("/"):
            raise TemplateError("hermes.terminal.cwd must be relative")
        return cls(
            backend=backend,
            cwd=cwd,
            home_mode=home_mode,
            timeout=_int(data.get("timeout"), "hermes.terminal.timeout", default=300, minimum=1),
            docker_image=data.get("docker_image") or None,
            docker_mount_cwd_to_workspace=_bool(
                data.get("docker_mount_cwd_to_workspace"),
                "hermes.terminal.docker_mount_cwd_to_workspace",
                default=False,
            ),
        )

    def to_config(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "backend": self.backend,
            "cwd": self.cwd,
            "home_mode": self.home_mode,
            "timeout": self.timeout,
            "docker_mount_cwd_to_workspace": self.docker_mount_cwd_to_workspace,
        }
        if self.docker_image:
            data["docker_image"] = self.docker_image
        return data


@dataclass(frozen=True)
class HermesGatewayConfig:
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HermesGatewayConfig:
        return cls(enabled=_bool(data.get("enabled"), "hermes.gateway.enabled", default=True))

    def to_config(self) -> dict[str, Any]:
        return {"enabled": self.enabled}


@dataclass(frozen=True)
class HermesDelegationConfig:
    max_iterations: int = 50
    max_concurrent_children: int = 3
    max_async_children: int = 3
    child_timeout_seconds: int = 0
    subagent_auto_approve: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HermesDelegationConfig:
        timeout = _int(
            data.get("child_timeout_seconds"),
            "hermes.delegation.child_timeout_seconds",
            default=0,
            minimum=0,
        )
        if 0 < timeout < 30:
            raise TemplateError("hermes.delegation.child_timeout_seconds must be 0 or at least 30")
        return cls(
            max_iterations=_int(
                data.get("max_iterations"),
                "hermes.delegation.max_iterations",
                default=50,
                minimum=1,
                maximum=500,
            ),
            max_concurrent_children=_int(
                data.get("max_concurrent_children"),
                "hermes.delegation.max_concurrent_children",
                default=3,
                minimum=1,
                maximum=32,
            ),
            max_async_children=_int(
                data.get("max_async_children"),
                "hermes.delegation.max_async_children",
                default=3,
                minimum=1,
                maximum=32,
            ),
            child_timeout_seconds=timeout,
            subagent_auto_approve=_bool(
                data.get("subagent_auto_approve"),
                "hermes.delegation.subagent_auto_approve",
                default=False,
            ),
        )

    def to_config(self) -> dict[str, Any]:
        return {
            "max_iterations": self.max_iterations,
            "max_concurrent_children": self.max_concurrent_children,
            "max_async_children": self.max_async_children,
            "child_timeout_seconds": self.child_timeout_seconds,
            "subagent_auto_approve": self.subagent_auto_approve,
        }


@dataclass(frozen=True)
class HermesConfig:
    model: HermesModelConfig
    terminal: HermesTerminalConfig = field(default_factory=HermesTerminalConfig)
    gateway: HermesGatewayConfig = field(default_factory=HermesGatewayConfig)
    delegation: HermesDelegationConfig = field(default_factory=HermesDelegationConfig)
    required_env: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HermesConfig:
        return cls(
            model=HermesModelConfig.from_dict(_mapping(data.get("model"), "hermes.model")),
            terminal=HermesTerminalConfig.from_dict(
                _mapping(data.get("terminal", {}), "hermes.terminal")
            ),
            gateway=HermesGatewayConfig.from_dict(
                _mapping(data.get("gateway", {}), "hermes.gateway")
            ),
            delegation=HermesDelegationConfig.from_dict(
                _mapping(data.get("delegation", {}), "hermes.delegation")
            ),
            required_env=_validate_required_env(data.get("required_env")),
            extra={
                key: value
                for key, value in data.items()
                if key not in {"model", "terminal", "gateway", "delegation", "required_env"}
            },
        )

    def to_config(self) -> dict[str, Any]:
        data = {
            "model": self.model.to_config(),
            "terminal": self.terminal.to_config(),
            "gateway": self.gateway.to_config(),
            "delegation": self.delegation.to_config(),
        }
        data.update(self.extra)
        return data


@dataclass(frozen=True)
class HermesTemplate:
    id: str
    name: str
    description: str
    version: str
    hermes: HermesConfig
    soul: str
    skills: dict[str, Any] = field(default_factory=dict)
    cron: list[dict[str, Any]] = field(default_factory=list)
    mcp: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HermesTemplate:
        _reject_inline_secrets(data)
        template_id = validate_id(_string(data.get("id"), "id"))
        version = _string(data.get("version"), "version")
        if not SEMVER_RE.match(version):
            raise TemplateError("version must be MAJOR.MINOR.PATCH")
        cron = data.get("cron", [])
        if not isinstance(cron, list):
            raise TemplateError("cron must be a list")
        return cls(
            id=template_id,
            name=_string(data.get("name"), "name", max_length=120),
            description=_string(data.get("description"), "description", max_length=500),
            version=version,
            hermes=HermesConfig.from_dict(_mapping(data.get("hermes"), "hermes")),
            soul=_string(data.get("soul"), "soul"),
            skills=dict(_mapping(data.get("skills", {}), "skills")),
            cron=[dict(_mapping(item, "cron item")) for item in cron],
            mcp=dict(_mapping(data.get("mcp", {}), "mcp")),
            metadata=dict(_mapping(data.get("metadata", {}), "metadata")),
        )


@dataclass(frozen=True)
class BotCreateRequest:
    bot_id: str
    template_id: str
    display_name: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    restart_policy: RestartPolicy = RestartPolicy.manual
    restart_backoff_seconds: float = 5.0
    restart_max_attempts: int = 5

    def __post_init__(self) -> None:
        validate_id(self.bot_id, "bot_id")
        validate_id(self.template_id, "template_id")
        try:
            policy = RestartPolicy(self.restart_policy)
        except ValueError as exc:
            raise TemplateError("restart_policy must be manual or on-failure") from exc
        if self.restart_backoff_seconds < 0 or self.restart_backoff_seconds > 3600:
            raise TemplateError("restart_backoff_seconds must be between 0 and 3600")
        if self.restart_max_attempts < 0 or self.restart_max_attempts > 100:
            raise TemplateError("restart_max_attempts must be between 0 and 100")
        object.__setattr__(self, "restart_policy", policy)
        object.__setattr__(self, "restart_backoff_seconds", float(self.restart_backoff_seconds))


@dataclass(frozen=True)
class BotRecord:
    bot_id: str
    template_id: str
    display_name: str
    profile_path: str
    status: BotStatus = BotStatus.stopped
    pid: int | None = None
    restart_policy: RestartPolicy = RestartPolicy.manual
    restart_backoff_seconds: float = 5.0
    restart_max_attempts: int = 5
    restart_attempts: int = 0
    next_restart_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bot_id": self.bot_id,
            "template_id": self.template_id,
            "display_name": self.display_name,
            "profile_path": self.profile_path,
            "status": self.status.value,
            "pid": self.pid,
            "restart_policy": self.restart_policy.value,
            "restart_backoff_seconds": self.restart_backoff_seconds,
            "restart_max_attempts": self.restart_max_attempts,
            "restart_attempts": self.restart_attempts,
            "next_restart_at": self.next_restart_at.isoformat() if self.next_restart_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True)
class BotStatusResponse:
    bot_id: str
    status: BotStatus
    pid: int | None
    profile_path: str
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "bot_id": self.bot_id,
            "status": self.status.value,
            "pid": self.pid,
            "profile_path": self.profile_path,
            "message": self.message,
        }
