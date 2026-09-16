"""Authenticated discovery and dispatch for dashboard integration reads."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from zeus import __version__
from zeus.api_authorization import ROUTE_PERMISSIONS
from zeus.api_request import parse_query
from zeus.integration_auth import ApiPrincipal
from zeus.operator_api import is_operator_path, operator_response
from zeus.schema import SCHEMA_VERSION

if TYPE_CHECKING:
    from zeus.supervisor import Supervisor


def capabilities(principal: ApiPrincipal) -> dict[str, Any]:
    """Describe the caller's access without reading storage or probing runtimes."""
    return {
        "capabilities_version": 1,
        "api_version": "v1",
        "zeus_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "integration_id": principal.integration_id,
        "administrator": principal.administrator,
        "permissions": sorted(principal.permissions),
        "endpoints": [
            {
                "method": method,
                "path": path,
                "permission": permission,
                "mutates_state": method == "POST" or path in {"/doctor", "/bots/{bot_id}/status"},
            }
            for (method, path), permission in sorted(ROUTE_PERMISSIONS.items())
            if principal.administrator
            or permission == "authenticated"
            or permission in principal.permissions
        ],
    }


def is_dashboard_path(path: str) -> bool:
    return path == "/capabilities" or is_operator_path(path)


def dashboard_response(
    path: str, target: str, principal: ApiPrincipal, supervisor: Supervisor
) -> tuple[HTTPStatus, dict[str, Any]]:
    if path == "/capabilities":
        parse_query(target, frozenset())
        return HTTPStatus.OK, capabilities(principal)
    return operator_response(path, target, supervisor)
