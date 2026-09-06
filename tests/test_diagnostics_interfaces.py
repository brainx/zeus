from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.test_api import api_server_with_state, request_json
from zeus.cli import main
from zeus.models import BotRecord
from zeus.request_context import route_template
from zeus.state import StateReadinessError, StateStore


def diagnostic_report(status: str) -> dict[str, object]:
    checks = {name: {"status": "ok"} for name in ("state_db", "session_store", "config")}
    checks["model"] = {"status": status}
    return {
        "bot_id": "coder",
        "observed_at": "2026-09-07T00:00:00+00:00",
        "status": status,
        "reason": status,
        "process": {"pid": 123, "verified": True},
        "health": {
            "status": status,
            "version": "0.21.0",
            "pid": 123,
            "gateway_state": "running",
            "active_agents": 0,
            "gateway_busy": False,
            "gateway_drainable": True,
            "readiness": {
                "status": status,
                "checks": {
                    **checks,
                    "disk": {"status": "ok", "used_percent": 20, "free_bytes": 1_000_000},
                    "gateway": {
                        "status": "ok",
                        "state": "running",
                        "connected_platforms": 1,
                        "platforms": 1,
                    },
                    "background_queues": {
                        "status": "ok",
                        "active_api_runs": 0,
                        "process_completions": 0,
                        "active_delegations": 0,
                    },
                },
            },
        },
    }


class DiagnosticsInterfaceTests(unittest.TestCase):
    def cli(self, root: Path, arguments: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(root / "state")}, clear=True),
            patch("zeus.cli._services", side_effect=AssertionError("must remain read-only")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(["bot", "diagnostics", *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_missing_state_and_invalid_id_do_not_create_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for bot_id, error in (("coder", "not_ready"), ("../unsafe", "invalid_bot_id")):
                with self.subTest(bot_id=bot_id):
                    code, stdout, _ = self.cli(root, [bot_id, "--json"])
                    self.assertEqual(1, code)
                    self.assertEqual(error, json.loads(stdout)["error"]["code"])
                    self.assertFalse((root / "state").exists())

    def test_cli_stopped_unknown_and_human_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "state" / "zeus.db")
            store.init()
            store.upsert_bot(BotRecord("coder", "coding-bot", "Coder", "unused"))
            code, stdout, _ = self.cli(root, ["coder", "--json"])
            self.assertEqual(1, code)
            self.assertEqual("not_running", json.loads(stdout)["status"])
            code, _, stderr = self.cli(root, ["missing"])
            self.assertEqual(1, code)
            self.assertIn("unknown bot", stderr)
            code, stdout, _ = self.cli(root, ["coder"])
            self.assertIn("coder\tnot_running\tnot_running", stdout)

    def test_cli_healthy_and_degraded_observations_have_distinct_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for status in ("ok", "degraded"):
                payload = diagnostic_report(status)
                with (
                    self.subTest(status=status),
                    patch("zeus.diagnostics_cli.diagnose_bot", return_value=payload),
                ):
                    code, stdout, _ = self.cli(root, ["coder"])
                self.assertEqual(0 if status == "ok" else 1, code)
                self.assertIn(f"model\t{status}", stdout)
                self.assertIn("active_agents\t0", stdout)

    def test_api_authentication_precedes_probe_and_parameter_validation(self) -> None:
        with (
            api_server_with_state({"ZEUS_API_KEY": "test-key", "ZEUS_ALLOW_UNAUTH_READS": "1"}) as (
                port,
                _,
            ),
            patch("zeus.operator_api.diagnose_bot") as diagnose,
        ):
            for prefix in ("", "/v1"):
                status, _ = request_json(port, "GET", f"{prefix}/bots/coder/diagnostics?url=bad")
                self.assertEqual(401, status)
            diagnose.assert_not_called()
        with api_server_with_state() as (port, _):
            status, body = request_json(port, "GET", "/bots/coder/diagnostics")
            self.assertEqual(503, status)
            self.assertEqual("missing_api_key", body["error"]["code"])

    def test_api_aliases_match_readonly_stopped_observation_and_openapi(self) -> None:
        spec = json.loads(Path("docs/openapi.json").read_text())
        schema = spec["components"]["schemas"]["LiveGatewayDiagnostics"]
        operation = spec["paths"]["/bots/{bot_id}/diagnostics"]["get"]
        self.assertEqual([{"ZeusApiKey": []}], operation["security"])
        headers = {"x-zeus-api-key": "test-key"}
        with api_server_with_state({"ZEUS_API_KEY": "test-key"}) as (port, state_dir):
            store = StateStore(state_dir / "zeus.db")
            store.upsert_bot(BotRecord("coder", "coding-bot", "Coder", "unused"))
            before = store.get_bot("coder")
            locks_before = set((state_dir / "locks").rglob("*"))
            for prefix in ("", "/v1"):
                status, payload = request_json(
                    port, "GET", f"{prefix}/bots/coder/diagnostics", headers=headers
                )
                self.assertEqual(200, status)
                self.assertEqual("not_running", payload["status"])
                self.assertEqual({"pid": None, "verified": False}, payload["process"])
                self.assertIsNone(payload["health"])
                self.assertEqual(set(schema["required"]), set(payload))
                self.assertEqual(before, store.get_bot("coder"))
            self.assertEqual(locks_before, set((state_dir / "locks").rglob("*")))

    def test_api_unknown_invalid_query_and_unavailable_state(self) -> None:
        headers = {"x-zeus-api-key": "test-key"}
        with api_server_with_state({"ZEUS_API_KEY": "test-key"}) as (port, _):
            status, payload = request_json(
                port, "GET", "/bots/missing/diagnostics", headers=headers
            )
            self.assertEqual(404, status)
            self.assertEqual("unknown_bot", payload["error"]["code"])
            for route in (
                "/bots/coder/diagnostics?url=http://example.com",
                "/bots/coder/diagnostics?timeout=9",
                "/bots/coder/extra/diagnostics",
                "/bots/bad%2Fid/diagnostics",
                "/bots/%FF/diagnostics",
            ):
                with (
                    self.subTest(route=route),
                    patch("zeus.hermes_diagnostics.probe_gateway_health") as probe,
                ):
                    status, _ = request_json(port, "GET", route, headers=headers)
                    self.assertEqual(400, status)
                    probe.assert_not_called()
            with patch(
                "zeus.operator_api.diagnose_bot", side_effect=StateReadinessError("private detail")
            ):
                status, payload = request_json(
                    port, "GET", "/bots/coder/diagnostics", headers=headers
                )
                self.assertEqual(503, status)
                self.assertNotIn("private detail", json.dumps(payload))

    def test_api_degraded_observation_is_a_successful_read(self) -> None:
        with (
            api_server_with_state({"ZEUS_API_KEY": "test-key"}) as (port, _),
            patch("zeus.operator_api.diagnose_bot", return_value=diagnostic_report("degraded")),
        ):
            status, payload = request_json(
                port, "GET", "/bots/coder/diagnostics", headers={"x-zeus-api-key": "test-key"}
            )
            self.assertEqual(200, status)
            self.assertEqual("degraded", payload["status"])

    def test_route_template_does_not_log_bot_identifiers(self) -> None:
        self.assertEqual(
            "/bots/{bot_id}/diagnostics", route_template("/v1/bots/private-bot/diagnostics")
        )
