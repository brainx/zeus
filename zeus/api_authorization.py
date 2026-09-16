"""Endpoint permissions and authentication for server-side API integrations."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
from http import HTTPStatus

from zeus.config import Settings
from zeus.integration_auth import ApiPrincipal, authenticate_api_key
from zeus.rate_limit import TokenBucket
from zeus.request_context import RequestContext, route_template

# Scopes describe effects and sensitivity, not HTTP verbs. In particular, status
# can recover pending intent, doctor initializes state, and inventory exposes paths.
ROUTE_PERMISSIONS = {
    ("GET", "/ready"): "observer",
    ("GET", "/fleet"): "observer",
    ("GET", "/reconcile/runs"): "observer",
    ("GET", "/reconcile/runs/{run_id}"): "observer",
    ("GET", "/doctor"): "operator",
    ("GET", "/templates"): "diagnostics",
    ("GET", "/bots"): "diagnostics",
    ("GET", "/bots/{bot_id}/history"): "diagnostics",
    ("GET", "/bots/{bot_id}/logs"): "diagnostics",
    ("GET", "/bots/{bot_id}/inspect"): "diagnostics",
    ("GET", "/bots/{bot_id}/diagnostics"): "diagnostics",
    ("GET", "/bots/{bot_id}/status"): "operator",
    ("POST", "/bots"): "operator",
    ("POST", "/bots/reconcile"): "operator",
    ("POST", "/bots/{bot_id}/start"): "operator",
    ("POST", "/bots/{bot_id}/stop"): "operator",
    ("POST", "/bots/{bot_id}/restart"): "operator",
    ("POST", "/bots/{bot_id}/reconcile"): "operator",
}


@dataclass
class AuthorizationDenied(Exception):
    status: HTTPStatus
    code: str
    message: str
    retry_after: int | None = None


class ApiAuthorizer:
    def __init__(self, settings: Settings, failures: TokenBucket) -> None:
        self.settings = settings
        self.failures = failures

    def authorize(
        self,
        headers: Message,
        context: RequestContext,
        *,
        method: str,
        path: str,
        allow_unauthenticated: bool,
    ) -> ApiPrincipal | None:
        template = route_template(path)
        permission = ROUTE_PERMISSIONS.get((method, template)) if template else None
        values = headers.get_all("x-zeus-api-key") or []
        if (
            not values
            and allow_unauthenticated
            and self.settings.allow_unauth_reads
            and permission != "operator"
            and (not self.settings.api_integrations or permission == "observer")
        ):
            context.auth_outcome = "allowed_unauthenticated"
            return None
        if not self.settings.api_key and not self.settings.api_integrations:
            context.auth_outcome = "unconfigured"
            raise AuthorizationDenied(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "missing_api_key",
                "an API credential is required for non-health endpoints",
            )
        principal = (
            authenticate_api_key(values[0], self.settings.api_key, self.settings.api_integrations)
            if len(values) == 1
            else None
        )
        if principal is None:
            context.auth_outcome = "rejected" if values else "missing"
            decision = self.failures.consume()
            if decision.allowed:
                raise AuthorizationDenied(
                    HTTPStatus.UNAUTHORIZED, "invalid_api_key", "invalid api key"
                )
            raise AuthorizationDenied(
                HTTPStatus.TOO_MANY_REQUESTS,
                "auth_rate_limited",
                "API authentication rate limit exceeded",
                decision.retry_after_seconds,
            )
        context.integration_id = principal.integration_id
        if not principal.administrator and permission not in principal.permissions:
            context.auth_outcome = "forbidden"
            raise AuthorizationDenied(
                HTTPStatus.FORBIDDEN, "permission_denied", "integration permission denied"
            )
        context.auth_outcome = "authenticated"
        return principal
