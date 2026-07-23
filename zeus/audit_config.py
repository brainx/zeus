from __future__ import annotations

import json
import re
from dataclasses import fields
from pathlib import Path
from typing import NoReturn

from zeus.audit_models import (
    HARD_LIMITS,
    AuditCategory,
    AuditConfig,
    AuditLimits,
    SuggestedCommand,
)
from zeus.private_io import read_private_bytes

AUDIT_CONFIG_SCHEMA_VERSION = 1
AUDIT_CONFIG_MAX_BYTES = 1024 * 1024
DEFAULT_AUDIT_IMAGE = (
    "nikolaik/python-nodejs:python3.11-nodejs20@sha256:"
    "8f958bdc1b4a422bfafd97cab4f69836401f616ae985d4b57a53d254f5bcb038"
)

_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_IMAGE_NAME_COMPONENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
_IMAGE_REPOSITORY = (
    rf"(?:{_IMAGE_NAME_COMPONENT}/)*"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?"
)
_IMAGE_RE = re.compile(rf"^(?:sha256:[0-9a-f]{{64}}|{_IMAGE_REPOSITORY}@sha256:[0-9a-f]{{64}})$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "provider",
        "model",
        "provider_env",
        "image",
        "categories",
        "exclude_paths",
        "suggested_commands",
        "limits",
    }
)
_CONFIGURABLE_LIMITS = frozenset(
    {
        "overall_seconds",
        "terminal_command_seconds",
        "findings",
        "model_output_bytes",
        "artifact_bytes",
        "snapshot_entries",
        "snapshot_blob_bytes",
    }
)


class AuditConfigError(ValueError):
    pass


def _error(message: str) -> NoReturn:
    raise AuditConfigError(message)


def _reject_unknown_fields(value: dict[object, object], allowed: frozenset[str], name: str) -> None:
    if not all(isinstance(key, str) for key in value):
        _error(f"{name} field names must be strings")
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        _error(f"{name} contains unknown fields: {', '.join(unknown)}")


def _optional_text(value: dict[object, object], name: str) -> str | None:
    if name not in value:
        return None
    result = value[name]
    if (
        not isinstance(result, str)
        or not result
        or result != result.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in result)
    ):
        _error(f"{name} must be a non-empty text string without surrounding whitespace")
    return result


def _provider_env(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        _error("provider_env must be a list")
    if len(value) > 4:
        _error("provider_env may contain at most four names")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _ENV_NAME_RE.fullmatch(item):
            _error("provider_env contains an invalid environment variable name")
        if item in result:
            _error("provider_env names must be unique")
        result.append(item)
    return tuple(result)


def _image(value: object) -> str:
    if not isinstance(value, str) or not _IMAGE_RE.fullmatch(value):
        _error("image must be a SHA-256 digest or digest-qualified image reference")
    return value


def _categories(value: object) -> frozenset[AuditCategory]:
    if not isinstance(value, list) or not value:
        _error("categories must be a non-empty list")
    result: set[AuditCategory] = set()
    for item in value:
        if not isinstance(item, str):
            _error("categories must contain strings")
        try:
            category = AuditCategory(item)
        except ValueError:
            _error(f"unsupported audit category: {item}")
        if category in result:
            _error("categories must be unique")
        result.add(category)
    return frozenset(result)


def _relative_posix_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        _error(f"{name} must be a non-empty relative POSIX path")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        _error(f"{name} must be a confined relative POSIX path")
    components = value.split("/")
    if (
        any(component in {"", ".", ".."} for component in components)
        or any(component.casefold() == ".git" for component in components)
        or re.fullmatch(r"[A-Za-z]:", components[0])
    ):
        _error(f"{name} must be a confined relative POSIX path")
    return value


def _exclude_paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        _error("exclude_paths must be a list")
    result: list[str] = []
    for item in value:
        path = _relative_posix_path(item, "exclude_paths entry")
        if path in result:
            _error("exclude_paths entries must be unique")
        result.append(path)
    return tuple(result)


def _suggested_commands(value: object) -> tuple[SuggestedCommand, ...]:
    if not isinstance(value, dict):
        _error("suggested_commands must be an object")
    if len(value) > 64:
        _error("suggested_commands may contain at most 64 commands")
    commands: list[SuggestedCommand] = []
    for name in sorted(value):
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
        ):
            _error("suggested command names must be non-empty text strings")
        argv = value[name]
        if not isinstance(argv, list) or not argv:
            _error(f"suggested command {name} must be a non-empty argv list")
        parsed_argv: list[str] = []
        for index, argument in enumerate(argv):
            if not isinstance(argument, str) or "\x00" in argument:
                _error(f"suggested command {name} argv entries must be strings without NUL")
            if index == 0 and not argument:
                _error(f"suggested command {name} executable must not be empty")
            parsed_argv.append(argument)
        commands.append(SuggestedCommand(name=name, argv=tuple(parsed_argv)))
    return tuple(commands)


def _limits(value: object) -> AuditLimits:
    if not isinstance(value, dict):
        _error("limits must be an object")
    _reject_unknown_fields(value, _CONFIGURABLE_LIMITS, "limits")
    configured = {field.name: getattr(HARD_LIMITS, field.name) for field in fields(AuditLimits)}
    for name, limit in value.items():
        if isinstance(limit, bool) or not isinstance(limit, int):
            _error(f"limits.{name} must be an integer")
        ceiling = getattr(HARD_LIMITS, name)
        if limit < 1 or limit > ceiling:
            _error(f"limits.{name} must be between 1 and {ceiling}")
        configured[name] = limit
    return AuditLimits(**configured)


def parse_audit_config(value: object) -> AuditConfig:
    if not isinstance(value, dict):
        _error("audit configuration must be an object")
    _reject_unknown_fields(value, _TOP_LEVEL_FIELDS, "audit configuration")
    schema_version = value.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != AUDIT_CONFIG_SCHEMA_VERSION
    ):
        _error("schema_version must be exactly 1")

    return AuditConfig(
        schema_version=AUDIT_CONFIG_SCHEMA_VERSION,
        provider=_optional_text(value, "provider"),
        model=_optional_text(value, "model"),
        provider_env=_provider_env(value.get("provider_env", [])),
        image=_image(value.get("image", DEFAULT_AUDIT_IMAGE)),
        categories=_categories(
            value.get("categories", [category.value for category in AuditCategory])
        ),
        exclude_paths=_exclude_paths(value.get("exclude_paths", [])),
        suggested_commands=_suggested_commands(value.get("suggested_commands", {})),
        limits=_limits(value.get("limits", {})),
    )


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _error(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    _error(f"non-finite JSON number is not allowed: {value}")


def load_audit_config(state_dir: Path) -> AuditConfig:
    data = read_private_bytes(
        state_dir / "audit" / "config.json",
        AUDIT_CONFIG_MAX_BYTES,
        missing_ok=True,
    )
    if data is None:
        return parse_audit_config({"schema_version": AUDIT_CONFIG_SCHEMA_VERSION})
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except AuditConfigError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditConfigError("audit configuration is not valid UTF-8 JSON") from exc
    return parse_audit_config(value)
