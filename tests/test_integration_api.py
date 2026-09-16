from __future__ import annotations

import hashlib
import http.client
import json
import sqlite3
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import ExitStack, closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

from tests.test_api import api_server_with_state, request_json_with_headers, wait_for_access_rows
from zeus.idempotency import canonical_request_hash
from zeus.state import StateStore
from zeus.supervisor import Supervisor

_KEYS = {
    "observer": "observer-integration-test-" + "1" * 32,
    "diagnostics": "diagnostics-integration-test-" + "2" * 32,
    "operator": "operator-integration-test-" + "3" * 32,
    "other_operator": "other-operator-test-" + "4" * 32,
    "admin": "legacy-administrator-test-" + "5" * 32,
}
_CREATE_BODY = json.dumps({"bot_id": "coder", "template_id": "coding-bot"}).encode()
_ROUTES = (
    ("GET", "/ready", "observer"),
    ("GET", "/fleet", "observer"),
    ("GET", "/reconcile/runs", "observer"),
    ("GET", "/reconcile/runs/example", "observer"),
    ("GET", "/doctor", "operator"),
    ("GET", "/templates", "diagnostics"),
    ("GET", "/bots", "diagnostics"),
    ("GET", "/bots/coder/history", "diagnostics"),
    ("GET", "/bots/coder/logs", "diagnostics"),
    ("GET", "/bots/coder/inspect", "diagnostics"),
    ("GET", "/bots/coder/diagnostics", "diagnostics"),
    ("GET", "/bots/coder/status", "operator"),
    ("POST", "/bots", "operator"),
    ("POST", "/bots/reconcile", "operator"),
    ("POST", "/bots/coder/start", "operator"),
    ("POST", "/bots/coder/stop", "operator"),
    ("POST", "/bots/coder/restart", "operator"),
    ("POST", "/bots/coder/reconcile", "operator"),
)


def _result(sequence: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        to_dict=lambda: {"bot_id": "coder", "status": "running", "sequence": sequence}
    )


class IntegrationApiTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.request_count = 0
        self.configuration = self.root / "integrations.json"
        self.configuration.write_text(
            json.dumps(
                {
                    "version": 1,
                    "integrations": [
                        {
                            "id": identity,
                            "key_env": f"INTEGRATION_{identity.upper()}",
                            "permissions": [
                                "operator" if identity == "other_operator" else identity
                            ],
                        }
                        for identity in _KEYS
                        if identity != "admin"
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.configuration.chmod(0o600)
        self.env = {
            "ZEUS_STATE_DIR": str(self.root / "state"),
            "ZEUS_API_KEY": _KEYS["admin"],
            "ZEUS_API_INTEGRATIONS_FILE": str(self.configuration),
            "ZEUS_API_AUTH_FAILURE_BURST": "1000",
            "ZEUS_API_MUTATION_RATE_PER_MINUTE": "6000",
            "ZEUS_API_MUTATION_BURST": "1000",
            **{f"INTEGRATION_{identity.upper()}": key for identity, key in _KEYS.items()},
        }

    @contextmanager
    def server(self, **overrides: str) -> Iterator[tuple[int, Path]]:
        with (
            patch("zeus.config.load_dotenv", return_value={}),
            api_server_with_state({**self.env, **overrides}) as fixture,
        ):
            yield fixture

    def request(
        self,
        port: int,
        method: str,
        path: str,
        identity: str | None,
        *,
        body: bytes | None = None,
        key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        headers = {} if identity is None else {"x-zeus-api-key": _KEYS[identity]}
        if body is not None:
            headers["content-type"] = "application/json"
        if key is not None:
            headers["idempotency-key"] = key
        headers.update(extra_headers or {})
        response = request_json_with_headers(port, method, path, body=body, headers=headers)
        self.request_count += 1
        # The server sends responses before logging and releasing worker slots.
        # Keep the permission matrix focused on authorization, not burst capacity.
        wait_for_access_rows(self.root / "state", self.request_count)
        return response

    def test_endpoint_permissions_and_admin_compatibility_for_both_route_aliases(self) -> None:
        with ExitStack() as stack:
            effects: list[Mock] = []
            for method in ("status", "create_bot", "start", "stop", "restart"):
                effects.append(
                    stack.enter_context(patch.object(Supervisor, method, return_value=_result()))
                )
            effects.extend(
                (
                    stack.enter_context(
                        patch.object(Supervisor, "reconcile", return_value=[_result()])
                    ),
                    stack.enter_context(
                        patch.object(Supervisor, "logs", return_value="private logs")
                    ),
                    stack.enter_context(
                        patch.object(Supervisor, "inspect", return_value={"bot_id": "coder"})
                    ),
                    stack.enter_context(patch("zeus.api.run_doctor", return_value=_result())),
                    stack.enter_context(
                        patch("zeus.operator_api.diagnose_bot", return_value={"status": "degraded"})
                    ),
                    stack.enter_context(
                        patch.object(StateStore, "history_payload", return_value={"events": []})
                    ),
                    stack.enter_context(
                        patch(
                            "zeus.operator_api.ReconcileHistoryReader.get_run",
                            return_value={"run": {}},
                        )
                    ),
                )
            )
            port, _state = stack.enter_context(self.server())
            for identity in ("observer", "diagnostics", "operator", "admin"):
                for prefix in ("", "/v1"):
                    for method, path, permission in _ROUTES:
                        with self.subTest(
                            identity=identity, prefix=prefix, method=method, path=path
                        ):
                            for effect in effects:
                                effect.reset_mock()
                            status, headers, body = self.request(
                                port,
                                method,
                                prefix + path,
                                identity,
                                body=_CREATE_BODY if method == "POST" and path == "/bots" else None,
                            )
                            allowed = identity in {permission, "admin"}
                            self.assertEqual(200 if allowed else 403, status, body)
                            self.assertEqual("no-store", headers["cache-control"])
                            self.assertRegex(headers["x-request-id"], r"^[0-9a-f]{32}$")
                            if not allowed:
                                self.assertEqual("permission_denied", body["error"]["code"])
                                for effect in effects:
                                    effect.assert_not_called()

    def test_denied_get_status_and_mutations_never_execute_or_claim_idempotency(self) -> None:
        with (
            patch.object(Supervisor, "status") as status_call,
            patch.object(Supervisor, "create_bot") as create,
            patch.object(Supervisor, "start") as start,
            patch.object(Supervisor, "stop") as stop,
            patch.object(Supervisor, "restart") as restart,
            patch.object(Supervisor, "reconcile") as reconcile,
            self.server() as (port, state_dir),
        ):
            for identity in ("observer", "diagnostics"):
                for prefix in ("", "/v1"):
                    for method, path, permission in _ROUTES:
                        if permission != "operator":
                            continue
                        result, _headers, body = self.request(
                            port,
                            method,
                            prefix + path,
                            identity,
                            body=b"not JSON" if method == "POST" else None,
                            key="denied-must-not-claim" if method == "POST" else None,
                        )
                        self.assertEqual(403, result, body)
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                self.assertEqual(
                    0, connection.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
                )
        for operation in (status_call, create, start, stop, restart, reconcile):
            operation.assert_not_called()

    def test_missing_invalid_and_duplicate_key_headers_are_rejected(self) -> None:
        with self.server() as (port, _state_dir):
            for headers in ({}, {"x-zeus-api-key": "invalid"}, {"x-zeus-api-key": ""}):
                status, _response_headers, body = request_json_with_headers(
                    port, "GET", "/ready", headers=headers
                )
                self.assertEqual(401, status)
                self.assertEqual("invalid_api_key", body["error"]["code"])
            for values in (
                (_KEYS["observer"], _KEYS["observer"]),
                (_KEYS["observer"], _KEYS["admin"]),
            ):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    connection.putrequest("GET", "/ready")
                    connection.putheader("x-zeus-api-key", values[0])
                    connection.putheader("X-Zeus-Api-Key", values[1])
                    connection.endheaders()
                    response = connection.getresponse()
                    body = json.loads(response.read())
                    self.assertEqual(401, response.status)
                    self.assertEqual("invalid_api_key", body["error"]["code"])
                finally:
                    connection.close()

    def test_development_flag_cannot_bypass_named_permissions_by_omitting_credentials(self) -> None:
        with (
            patch.object(Supervisor, "status") as status_call,
            patch("zeus.api.run_doctor") as doctor,
            self.server(ZEUS_ALLOW_UNAUTH_READS="1") as (port, _state_dir),
        ):
            for prefix in ("", "/v1"):
                for path in ("/bots", "/templates", "/doctor", "/bots/coder/status"):
                    for identity, expected in (("observer", 403), (None, 401)):
                        status, _headers, body = self.request(port, "GET", prefix + path, identity)
                        self.assertEqual(expected, status, body)
                status, _headers, _body = self.request(port, "GET", prefix + "/ready", None)
                self.assertEqual(200, status)
                status, _headers, _body = self.request(port, "GET", prefix + "/ready", "operator")
                self.assertEqual(403, status)
            status_call.assert_not_called()
            doctor.assert_not_called()

    def test_legacy_development_reads_do_not_grant_anonymous_status_effects(self) -> None:
        with (
            patch.object(Supervisor, "status") as status_call,
            self.server(ZEUS_ALLOW_UNAUTH_READS="1", ZEUS_API_INTEGRATIONS_FILE="") as (
                port,
                _state,
            ),
        ):
            for prefix in ("", "/v1"):
                status, _headers, _body = self.request(port, "GET", prefix + "/bots", None)
                self.assertEqual(200, status)
                status, _headers, _body = self.request(
                    port, "GET", prefix + "/bots/coder/status", None
                )
                self.assertEqual(401, status)
            status_call.assert_not_called()

    def test_named_credentials_work_without_legacy_admin_configuration(self) -> None:
        with self.server(ZEUS_API_KEY="") as (port, _state_dir):
            self.assertEqual(200, self.request(port, "GET", "/ready", "observer")[0])
            self.assertEqual(403, self.request(port, "GET", "/bots", "observer")[0])
            self.assertEqual(401, self.request(port, "GET", "/ready", "admin")[0])

    def test_unknown_routes_fail_closed_for_named_credentials(self) -> None:
        with self.server() as (port, _state_dir):
            for method in ("GET", "POST"):
                for prefix in ("", "/v1"):
                    for identity in ("observer", "diagnostics", "operator"):
                        self.assertEqual(
                            403, self.request(port, method, prefix + "/unknown", identity)[0]
                        )
                    self.assertEqual(
                        404, self.request(port, method, prefix + "/unknown", "admin")[0]
                    )

    def test_access_logs_derive_identity_only_from_authenticated_credentials(self) -> None:
        with self.server() as (port, state_dir):
            responses = (
                self.request(
                    port,
                    "GET",
                    "/ready",
                    "observer",
                    extra_headers={"X-Zeus-Integration-ID": "forged-admin"},
                ),
                self.request(
                    port,
                    "GET",
                    "/bots",
                    "observer",
                    extra_headers={"X-Zeus-Integration-ID": "forged-admin"},
                ),
                self.request(
                    port,
                    "GET",
                    "/ready",
                    "admin",
                    extra_headers={"X-Zeus-Integration-ID": "forged-admin"},
                ),
                self.request(
                    port,
                    "GET",
                    "/ready",
                    None,
                    extra_headers={
                        "X-Zeus-Integration-ID": "forged-admin",
                        "x-zeus-api-key": "invalid",
                    },
                ),
            )
            rows = wait_for_access_rows(state_dir, len(responses))
            by_request = {row["request_id"]: row for row in rows}
            for response, identity, outcome in zip(
                responses,
                ("observer", "observer", "admin", None),
                ("authenticated", "forbidden", "authenticated", "rejected"),
                strict=True,
            ):
                row = by_request[response[1]["x-request-id"]]
                self.assertEqual(identity, row["integration_id"])
                self.assertEqual(outcome, row["auth_outcome"])
            serialized = json.dumps(rows)
            self.assertNotIn("forged-admin", serialized)
            for key in _KEYS.values():
                self.assertNotIn(key, serialized)

    def test_every_named_mutation_replays_across_route_aliases(self) -> None:
        with ExitStack() as stack:
            effects: dict[str, Mock] = {}
            for method in ("create_bot", "start", "stop", "restart"):
                effects[method] = stack.enter_context(
                    patch.object(Supervisor, method, return_value=_result())
                )
            effects["reconcile"] = stack.enter_context(
                patch.object(Supervisor, "reconcile", return_value=[_result()])
            )
            port, _state = stack.enter_context(self.server())
            for index, (method, path, _permission) in enumerate(_ROUTES):
                if method != "POST":
                    continue
                for effect in effects.values():
                    effect.reset_mock()
                body = _CREATE_BODY if path == "/bots" else None
                first = self.request(
                    port, method, path, "operator", body=body, key=f"operation-{index}"
                )
                replay = self.request(
                    port, method, "/v1" + path, "operator", body=body, key=f"operation-{index}"
                )
                self.assertEqual(200, first[0], first[2])
                self.assertEqual(first[0], replay[0])
                self.assertEqual(first[2], replay[2])
                self.assertNotIn("idempotency-replayed", first[1])
                self.assertEqual("true", replay[1].get("idempotency-replayed"))
                self.assertEqual(1, sum(effect.call_count for effect in effects.values()))

    def test_same_idempotency_key_is_independent_across_named_integrations_and_admin(self) -> None:
        with (
            patch.object(
                Supervisor, "start", side_effect=[_result(1), _result(2), _result(3)]
            ) as start,
            self.server() as (port, state_dir),
        ):
            for sequence, identity in enumerate(("operator", "other_operator", "admin"), start=1):
                first = self.request(port, "POST", "/bots/coder/start", identity, key="shared-key")
                replay = self.request(
                    port, "POST", "/v1/bots/coder/start", identity, key="shared-key"
                )
                self.assertEqual(200, first[0], first[2])
                self.assertEqual(sequence, first[2]["sequence"])
                self.assertEqual(first[2], replay[2])
                self.assertEqual("true", replay[1].get("idempotency-replayed"))
            self.assertEqual(3, start.call_count)
            with closing(sqlite3.connect(state_dir / "zeus.db")) as connection:
                hashes = [
                    row[0] for row in connection.execute("SELECT key_hash FROM idempotency_records")
                ]
            self.assertEqual(3, len(set(hashes)))
            self.assertIn(hashlib.sha256(b"shared-key").hexdigest(), hashes)

    def test_credential_rotation_preserves_replay_for_stable_integration_identity(self) -> None:
        with patch.object(Supervisor, "start", return_value=_result()) as start:
            with self.server() as (port, _state_dir):
                first = self.request(
                    port, "POST", "/bots/coder/start", "operator", key="rotate-key"
                )
            rotated = "rotated-operator-test-" + "6" * 32
            with self.server(INTEGRATION_OPERATOR=rotated) as (port, _state_dir):
                old = self.request(port, "POST", "/bots/coder/start", "operator", key="rotate-key")
                replay = self.request(
                    port,
                    "POST",
                    "/v1/bots/coder/start",
                    None,
                    key="rotate-key",
                    extra_headers={"x-zeus-api-key": rotated},
                )
            self.assertEqual(200, first[0])
            self.assertEqual(401, old[0])
            self.assertEqual(first[2], replay[2])
            self.assertEqual("true", replay[1].get("idempotency-replayed"))
            start.assert_called_once()

    def test_legacy_admin_records_replay_without_claiming_named_integration_records(self) -> None:
        with (
            patch.object(Supervisor, "start", return_value=_result(2)) as start,
            self.server() as (port, state_dir),
        ):
            store = StateStore(state_dir / "zeus.db")
            key_hash = hashlib.sha256(b"legacy-admin").hexdigest()
            request_hash = canonical_request_hash(
                "POST", "/bots/coder/start", {"wait": ["false"]}, None
            )
            now = datetime.now(UTC)
            expiry = now + timedelta(hours=1)
            store.claim_idempotency(
                key_hash=key_hash,
                request_hash=request_hash,
                owner_instance_id="old-server",
                expires_at=expiry,
            )
            store.complete_idempotency(
                key_hash=key_hash,
                request_hash=request_hash,
                owner_instance_id="old-server",
                response_status=200,
                response_json=json.dumps(_result().to_dict()),
                completed_at=datetime.now(UTC),
                expires_at=expiry,
            )
            replay = self.request(port, "POST", "/bots/coder/start", "admin", key="legacy-admin")
            self.assertEqual(200, replay[0], replay[2])
            self.assertEqual(1, replay[2]["sequence"])
            self.assertEqual("true", replay[1].get("idempotency-replayed"))
            start.assert_not_called()
            independent = self.request(
                port, "POST", "/bots/coder/start", "operator", key="legacy-admin"
            )
            self.assertEqual(200, independent[0], independent[2])
            self.assertEqual(2, independent[2]["sequence"])
            start.assert_called_once()

    def test_same_integration_conflicting_request_never_reexecutes(self) -> None:
        with (
            patch.object(Supervisor, "start", return_value=_result()) as start,
            patch.object(Supervisor, "stop") as stop,
            self.server() as (port, _state_dir),
        ):
            self.assertEqual(
                200, self.request(port, "POST", "/bots/coder/start", "operator", key="conflict")[0]
            )
            conflict = self.request(port, "POST", "/bots/coder/stop", "operator", key="conflict")
            self.assertEqual(409, conflict[0])
            self.assertEqual("idempotency_key_conflict", conflict[2]["error"]["code"])
            start.assert_called_once()
            stop.assert_not_called()

    def test_incomplete_named_mutation_is_not_reexecuted_before_or_after_server_restart(
        self,
    ) -> None:
        with patch.object(Supervisor, "start", return_value=_result()) as start:
            with self.server() as (port, _state_dir):
                with patch.object(
                    StateStore,
                    "complete_idempotency",
                    side_effect=sqlite3.DatabaseError("private failure"),
                ):
                    first = self.request(
                        port, "POST", "/bots/coder/start", "operator", key="uncertain"
                    )
                in_progress = self.request(
                    port, "POST", "/bots/coder/start", "operator", key="uncertain"
                )
                self.assertEqual(503, first[0])
                self.assertEqual("idempotency_store_unavailable", first[2]["error"]["code"])
                self.assertEqual(409, in_progress[0])
                self.assertEqual("idempotency_in_progress", in_progress[2]["error"]["code"])
            with (
                patch("zeus.api._process_idempotency_owner_id", return_value="new-server-instance"),
                self.server() as (port, _state_dir),
            ):
                indeterminate = self.request(
                    port, "POST", "/v1/bots/coder/start", "operator", key="uncertain"
                )
                self.assertEqual(409, indeterminate[0])
                self.assertEqual("idempotency_indeterminate", indeterminate[2]["error"]["code"])
                start.assert_called_once()
                independent = self.request(
                    port, "POST", "/bots/coder/start", "other_operator", key="uncertain"
                )
                self.assertEqual(200, independent[0])
                self.assertEqual(2, start.call_count)


if __name__ == "__main__":
    unittest.main()
