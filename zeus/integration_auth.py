"""Named API credentials loaded once from a private, bounded configuration file."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zeus.private_io import nofollow_absolute_path, read_private_bytes

INTEGRATION_PERMISSIONS = frozenset({"observer", "diagnostics", "operator"})
MAX_INTEGRATIONS = 32
MAX_CONFIG_BYTES = 65_536
_INTEGRATION_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_KEY_ENV = re.compile(r"[A-Z_][A-Z0-9_]{0,127}\Z")


@dataclass(frozen=True)
class IntegrationCredential:
    integration_id: str
    key: str = field(repr=False)
    permissions: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.integration_id, str)
            or _INTEGRATION_ID.fullmatch(self.integration_id) is None
            or self.integration_id == "admin"
        ):
            raise ValueError("integration id must be a lowercase identifier other than admin")
        if (
            not isinstance(self.key, str)
            or not 32 <= len(self.key) <= 512
            or any(not 33 <= ord(character) <= 126 for character in self.key)
        ):
            raise ValueError(
                "integration keys must contain 32-512 non-space printable ASCII characters"
            )
        if (
            not isinstance(self.permissions, frozenset)
            or not self.permissions
            or not self.permissions <= INTEGRATION_PERMISSIONS
        ):
            raise ValueError(
                "integration permissions must contain observer, diagnostics, or operator"
            )


@dataclass(frozen=True)
class ApiPrincipal:
    integration_id: str
    permissions: frozenset[str]
    administrator: bool = False


def validate_integration_credentials(
    integrations: tuple[IntegrationCredential, ...], *, admin_key: str | None
) -> None:
    if not isinstance(integrations, tuple) or len(integrations) > MAX_INTEGRATIONS:
        raise ValueError("API integrations must be a tuple containing at most 32 credentials")
    ids: set[str] = set()
    keys: set[str] = set()
    for credential in integrations:
        if not isinstance(credential, IntegrationCredential):
            raise ValueError("API integrations must contain integration credentials")
        credential.__post_init__()
        if credential.integration_id in ids:
            raise ValueError("integration ids must be unique")
        if credential.key in keys or credential.key == admin_key:
            raise ValueError(
                "integration keys must be unique and distinct from the administrator key"
            )
        ids.add(credential.integration_id)
        keys.add(credential.key)


def authenticate_api_key(
    provided: str,
    admin_key: str | None,
    integrations: tuple[IntegrationCredential, ...],
) -> ApiPrincipal | None:
    """Match all configured credentials without accepting a caller-supplied identity."""
    if not isinstance(provided, str) or not provided or not provided.isascii():
        return None
    principal = None
    if admin_key and hmac.compare_digest(provided, admin_key):
        principal = ApiPrincipal("admin", INTEGRATION_PERMISSIONS, administrator=True)
    for credential in integrations:
        if hmac.compare_digest(provided, credential.key):
            principal = ApiPrincipal(credential.integration_id, credential.permissions)
    return principal


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("integration configuration contains duplicate JSON fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("integration configuration contains a non-JSON value")


def load_integration_credentials(
    env: Mapping[str, str], *, admin_key: str | None
) -> tuple[IntegrationCredential, ...]:
    configured_path = env.get("ZEUS_API_INTEGRATIONS_FILE")
    if not configured_path:
        return ()
    try:
        path = nofollow_absolute_path(Path(configured_path))
        raw = read_private_bytes(path, MAX_CONFIG_BYTES, tighten=False)
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (OSError, ValueError, RecursionError):
        # Parsing and filesystem exceptions can carry private paths or source content.
        raise ValueError(
            "ZEUS_API_INTEGRATIONS_FILE must be a readable private UTF-8 JSON file"
        ) from None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "integrations"}
        or type(payload["version"]) is not int
        or payload["version"] != 1
    ):
        raise ValueError("integration configuration requires version 1 and integrations only")
    entries = payload["integrations"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_INTEGRATIONS:
        raise ValueError("integration configuration must contain 1-32 integrations")
    credentials: list[IntegrationCredential] = []
    key_envs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "key_env", "permissions"}:
            raise ValueError("integration entries require id, key_env, and permissions only")
        key_env = entry["key_env"]
        if not isinstance(key_env, str) or _KEY_ENV.fullmatch(key_env) is None:
            raise ValueError("integration key_env must be an uppercase environment variable name")
        if key_env in key_envs:
            raise ValueError("integration key_env references must be unique")
        key_envs.add(key_env)
        key = env.get(key_env)
        if not key:
            raise ValueError("integration key environment variable is missing or empty")
        permissions = entry["permissions"]
        if (
            not isinstance(permissions, list)
            or not 1 <= len(permissions) <= len(INTEGRATION_PERMISSIONS)
            or any(not isinstance(permission, str) for permission in permissions)
            or len(set(permissions)) != len(permissions)
        ):
            raise ValueError(
                "integration permissions must be a nonempty list of unique permissions"
            )
        credentials.append(IntegrationCredential(entry["id"], key, frozenset(permissions)))
    result = tuple(credentials)
    validate_integration_credentials(result, admin_key=admin_key)
    return result
