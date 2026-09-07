from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from tests.test_api import api_server_with_state, request_json
from tests.test_reconcile_store import _result, _run, _summary
from zeus.cli import main
from zeus.models import BotRecord
from zeus.request_context import route_template
from zeus.state import StateStore


def seed_history(path: Path) -> StateStore:
    store = StateStore(path)
    store.init()
    for name in ("run-a", "run-b"):
        run = _run(name)
        results = [_result("one"), _result("two")]
        store.begin_reconcile_run(run)
        for result in results:
            store.append_reconcile_result(name, result)
        store.finish_reconcile_run(_summary(run, results))
    return store


class OperatorInterfaceTests(unittest.TestCase):
    def cli(self, root: Path, arguments: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(root / "state")}, clear=True),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            patch("zeus.cli._services", side_effect=AssertionError("must remain read-only")),
        ):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_missing_cli_state_is_not_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for args in (
                ["reconcile", "list"],
                ["reconcile", "show", "missing"],
                ["fleet", "status"],
            ):
                with self.subTest(args=args):
                    code, stdout, _ = self.cli(root, [*args, "--json"])
                    self.assertEqual(1, code)
                    self.assertEqual("not_ready", json.loads(stdout)["error"]["code"])
                    self.assertFalse((root / "state").exists())

    def test_cli_history_pagination_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed_history(root / "state" / "zeus.db")
            code, stdout, _ = self.cli(root, ["reconcile", "list", "--limit", "1", "--json"])
            self.assertEqual(0, code)
            first = json.loads(stdout)
            self.assertEqual("run-b", first["runs"][0]["run_id"])
            code, stdout, _ = self.cli(
                root, ["reconcile", "list", "--before", first["next_before"], "--json"]
            )
            self.assertEqual(["run-a"], [run["run_id"] for run in json.loads(stdout)["runs"]])
            code, stdout, _ = self.cli(root, ["reconcile", "show", "run-b", "--limit", "1"])
            self.assertEqual(0, code)
            self.assertIn("Next page: --after 0", stdout)
            code, stdout, _ = self.cli(
                root, ["reconcile", "show", "run-b", "--after", "0", "--json"]
            )
            self.assertEqual(1, json.loads(stdout)["results"][0]["ordinal"])
            code, stdout, _ = self.cli(root, ["reconcile", "list"])
            self.assertIn("succeeded", stdout)
            code, stdout, _ = self.cli(root, ["fleet", "status"])
            self.assertEqual(0, code)
            self.assertIn("no live probe", stdout)

    def test_cli_errors_and_empty_fleet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed_history(root / "state" / "zeus.db")
            for args in (
                ["reconcile", "list", "--limit", "101"],
                ["fleet", "status", "--stale-after-seconds", "nan"],
            ):
                code, stdout, _ = self.cli(root, [*args, "--json"])
                self.assertEqual(1, code)
                self.assertEqual("invalid_request", json.loads(stdout)["error"]["code"])
            code, stdout, _ = self.cli(root, ["reconcile", "show", "missing", "--json"])
            self.assertEqual("unknown_reconcile_run", json.loads(stdout)["error"]["code"])
            code, _, stderr = self.cli(root, ["reconcile", "show", "missing"])
            self.assertEqual(1, code)
            self.assertIn("unknown reconciliation run", stderr)
            code, stdout, _ = self.cli(root, ["fleet", "status", "--attention-only", "--json"])
            payload = json.loads(stdout)
            self.assertEqual(0, code)
            self.assertFalse(payload["live_probe"])
            self.assertTrue(payload["attention_only"])
            self.assertEqual([], payload["items"])

    def test_api_strict_auth_on_both_aliases_and_before_query_validation(self) -> None:
        with api_server_with_state(
            {"ZEUS_API_KEY": "test-key", "ZEUS_ALLOW_UNAUTH_READS": "1"}
        ) as (port, _):
            for prefix in ("", "/v1"):
                for path in ("/fleet", "/reconcile/runs", "/reconcile/runs/missing"):
                    with self.subTest(path=prefix + path):
                        code, _ = request_json(port, "GET", prefix + path + "?unexpected=1")
                        self.assertEqual(401, code)
        with api_server_with_state({"ZEUS_ALLOW_UNAUTH_READS": "1"}) as (port, _):
            self.assertEqual(503, request_json(port, "GET", "/fleet")[0])

    def test_api_history_fleet_and_unchanged_evidence(self) -> None:
        headers = {"x-zeus-api-key": "test-key"}
        with api_server_with_state({"ZEUS_API_KEY": "test-key"}) as (port, state_dir):
            path = state_dir / "zeus.db"
            seed_history(path)
            before = path.read_bytes()
            code, first = request_json(port, "GET", "/v1/reconcile/runs?limit=1", headers=headers)
            self.assertEqual(200, code)
            self.assertEqual("run-b", first["runs"][0]["run_id"])
            code, second = request_json(
                port,
                "GET",
                "/reconcile/runs?before=" + quote(first["next_before"]),
                headers=headers,
            )
            self.assertEqual(["run-a"], [run["run_id"] for run in second["runs"]])
            code, detail = request_json(
                port, "GET", "/reconcile/runs/run-b?limit=1", headers=headers
            )
            self.assertEqual(0, detail["next_after"])
            code, detail = request_json(
                port, "GET", "/reconcile/runs/run-b?after=0", headers=headers
            )
            self.assertEqual(1, detail["results"][0]["ordinal"])
            self.assertIsNone(detail["next_after"])
            code, fleet = request_json(
                port, "GET", "/fleet?attention_only=1&stale_after_seconds=30", headers=headers
            )
            self.assertEqual(200, code)
            self.assertEqual("persisted_reconciliation", fleet["freshness_source"])
            self.assertFalse(fleet["live_probe"])
            self.assertEqual(before, path.read_bytes())
            code, body = request_json(port, "GET", "/reconcile/runs/missing", headers=headers)
            self.assertEqual(404, code)
            self.assertEqual("unknown_reconcile_run", body["error"]["code"])

    def test_api_rejects_bad_queries_and_reports_unavailable_state(self) -> None:
        headers = {"x-zeus-api-key": "test-key"}
        with api_server_with_state({"ZEUS_API_KEY": "test-key"}) as (port, state_dir):
            for path in (
                "/fleet?limit=0",
                "/fleet?limit=101",
                "/fleet?limit=wat",
                "/fleet?attention_only=wat",
                "/fleet?stale_after_seconds=nan",
                "/fleet?stale_after_seconds=wat",
                "/fleet?limit=1&limit=2",
                "/fleet?unknown=1",
                "/reconcile/runs?before=bad",
                "/reconcile/runs?outcome=bad",
                "/reconcile/runs/run-a?after=-1",
                "/reconcile/runs/run-a?after=wat",
                "/reconcile/runs/",
                "/reconcile/runs/extra/part",
                "/reconcile/runs/%FF",
            ):
                with self.subTest(path=path):
                    self.assertEqual(400, request_json(port, "GET", path, headers=headers)[0])
            (state_dir / "zeus.db").unlink()
            code, body = request_json(port, "GET", "/fleet", headers=headers)
            self.assertEqual(503, code)
            self.assertEqual("not_ready", body["error"]["code"])
            self.assertFalse((state_dir / "zeus.db").exists())

    def test_route_templates_hide_identifiers(self) -> None:
        self.assertEqual(
            "/reconcile/runs/{run_id}", route_template("/v1/reconcile/runs/private-id")
        )
        self.assertEqual("/fleet", route_template("/fleet"))
        self.assertEqual("/reconcile/runs", route_template("/reconcile/runs"))

    def test_openapi_matches_nonempty_operator_payloads(self) -> None:
        schemas = json.loads(Path("docs/openapi.json").read_text())["components"]["schemas"]
        headers = {"x-zeus-api-key": "test-key"}
        with api_server_with_state({"ZEUS_API_KEY": "test-key"}) as (port, state_dir):
            store = seed_history(state_dir / "zeus.db")
            store.upsert_bot(
                BotRecord(
                    bot_id="one",
                    template_id="coding-bot",
                    display_name="One",
                    profile_path=str(state_dir / "profiles" / "one"),
                    created_at=datetime(2026, 7, 1, tzinfo=UTC),
                )
            )
            _, fleet = request_json(port, "GET", "/fleet", headers=headers)
            _, detail = request_json(port, "GET", "/reconcile/runs/run-a", headers=headers)
            _, listing = request_json(port, "GET", "/reconcile/runs", headers=headers)
            for name, payload in (
                ("FleetOverview", fleet),
                ("FleetOverviewItem", fleet["items"][0]),
                ("FleetObservation", fleet["items"][0]["observation"]),
                ("ReconcileRunDetail", detail),
                ("ReconcileRunMetadata", detail["run"]),
                ("ReconcileHistoryResult", detail["results"][0]),
                ("ReconcileRunPage", listing),
            ):
                with self.subTest(schema=name):
                    self.assertEqual(set(schemas[name]["required"]), set(payload))
                    self.assertEqual(set(schemas[name]["properties"]), set(payload))
