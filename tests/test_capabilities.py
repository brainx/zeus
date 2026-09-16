from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.test_api import api_server, request_json
from zeus import __version__
from zeus.api_authorization import ROUTE_PERMISSIONS
from zeus.config import Settings
from zeus.dashboard_api import capabilities
from zeus.doctor import _check_api_auth
from zeus.integration_auth import ApiPrincipal, IntegrationCredential
from zeus.schema import SCHEMA_VERSION


class CapabilityTests(unittest.TestCase):
    def test_auth_readiness_recognizes_named_credentials_without_relaxing_network_guard(
        self,
    ) -> None:
        settings = replace(
            Settings.from_env({}, include_dotenv=False),
            api_integrations=(IntegrationCredential("olymp", "a" * 32, frozenset({"observer"})),),
        )
        self.assertEqual("pass", _check_api_auth(settings).status)
        self.assertEqual("fail", _check_api_auth(replace(settings, host="0.0.0.0")).status)
        self.assertEqual("warn", _check_api_auth(replace(settings, api_integrations=())).status)

    def test_discovery_lists_only_effective_access_and_status_is_a_mutation(self) -> None:
        for scope in ("observer", "diagnostics", "operator"):
            result = capabilities(ApiPrincipal("olymp", frozenset({scope})))
            self.assertEqual("olymp", result["integration_id"])
            self.assertEqual([scope], result["permissions"])
            self.assertEqual(__version__, result["zeus_version"])
            self.assertEqual(SCHEMA_VERSION, result["schema_version"])
            endpoints = result["endpoints"]
            self.assertEqual(
                {
                    (method, path)
                    for (method, path), permission in ROUTE_PERMISSIONS.items()
                    if permission in {scope, "authenticated"}
                },
                {(item["method"], item["path"]) for item in endpoints},
            )
            for item in endpoints:
                self.assertEqual(
                    item["method"] == "POST"
                    or item["path"] in {"/doctor", "/bots/{bot_id}/status"},
                    item["mutates_state"],
                )

    def test_discovery_requires_authentication_even_with_development_flag(self) -> None:
        with api_server({"ZEUS_API_KEY": "secret", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as port:
            for prefix in ("", "/v1"):
                status, body = request_json(port, "GET", prefix + "/capabilities")
                self.assertEqual(401, status)
                self.assertEqual("invalid_api_key", body["error"]["code"])
                status, body = request_json(
                    port, "GET", prefix + "/capabilities", headers={"x-zeus-api-key": "secret"}
                )
                self.assertEqual(200, status)
                self.assertTrue(body["administrator"])
                self.assertEqual("admin", body["integration_id"])
                self.assertEqual(len(ROUTE_PERMISSIONS), len(body["endpoints"]))

    def test_named_discovery_does_not_probe_storage_or_runtime_or_reveal_other_credentials(
        self,
    ) -> None:
        original = Settings.from_env
        credentials = (
            IntegrationCredential("olymp", "a" * 32, frozenset({"observer"})),
            IntegrationCredential("private-operator", "b" * 32, frozenset({"operator"})),
            IntegrationCredential("diagnostic", "c" * 32, frozenset({"diagnostics"})),
        )
        with (
            patch.object(
                Settings,
                "from_env",
                side_effect=lambda *a, **k: replace(
                    original(*a, **k), api_integrations=credentials
                ),
            ),
            api_server({"ZEUS_API_KEY": "secret"}) as port,
            patch("zeus.state.StateStore.check_readiness", side_effect=AssertionError("storage")),
            patch("zeus.supervisor.Supervisor.status", side_effect=AssertionError("status")),
            patch("zeus.supervisor.Supervisor.reconcile", side_effect=AssertionError("recovery")),
        ):
            for credential in credentials:
                headers = {"x-zeus-api-key": credential.key, "X-Integration-ID": "forged"}
                status, body = request_json(port, "GET", "/v1/capabilities", headers=headers)
                self.assertEqual(200, status)
                self.assertEqual(credential.integration_id, body["integration_id"])
                self.assertEqual(sorted(credential.permissions), body["permissions"])
                serialized = json.dumps(body)
                for other in credentials:
                    self.assertNotIn(other.key, serialized)
                    if other != credential:
                        self.assertNotIn(other.integration_id, serialized)
                self.assertNotIn("forged", serialized)
            status, _ = request_json(
                port, "GET", "/capabilities?refresh=true", headers={"x-zeus-api-key": "a" * 32}
            )
            self.assertEqual(400, status)

    def test_openapi_has_unique_operations_and_resolvable_local_references(self) -> None:
        spec = json.loads(Path("docs/openapi.json").read_text())
        operations = [operation for path in spec["paths"].values() for operation in path.values()]
        ids = [operation["operationId"] for operation in operations]
        self.assertEqual(len(ids), len(set(ids)))
        for operation in operations:
            if operation.get("security", spec["security"]):
                self.assertTrue(
                    {"400", "401", "429", "500", "503"} <= operation["responses"].keys()
                )

        def walk(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    target = spec
                    self.assertTrue(value["$ref"].startswith("#/"))
                    for key in value["$ref"][2:].split("/"):
                        target = target[key]
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(spec)
