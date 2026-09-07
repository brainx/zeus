from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from zeus.bot_diagnostics import diagnose_bot
from zeus.models import BotRecord, BotStatus, DesiredState
from zeus.readiness import ReadinessProbe
from zeus.sqlite_db import StateReadinessError
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class BotDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.profile = self.root / "hermes" / "profiles" / "coder"
        self.profile.mkdir(parents=True)
        self.api_key = "private-diagnostic-fixture-key"
        self.env_file = self.profile / ".env"
        self.env_file.write_text(f"API_SERVER_KEY={self.api_key}\n", encoding="utf-8")
        (self.profile / "config.yaml").write_text("model: test\n", encoding="utf-8")
        self.hermes = self.root / "bin" / "hermes"
        self.hermes.parent.mkdir()
        self.hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        self.hermes.chmod(0o755)
        self.pid = 4321
        self.alive = True
        self.store = StateStore(self.root / "zeus.db")
        self.store.init()
        self.record = BotRecord(
            "coder",
            "coding-bot",
            "Coder",
            str(self.profile),
            status=BotStatus.running,
            pid=self.pid,
            desired_state=DesiredState.running,
            desired_revision=1,
        )
        self.store.upsert_bot(self.record)
        self.supervisor = Supervisor(
            self.store,
            str(self.hermes),
            self.root / "hermes",
            pid_alive_fn=lambda _pid: self.alive,
            cmdline_reader=lambda _pid: [str(self.hermes), "-p", "coder", "gateway", "run"],
            proc_start_fingerprint_reader=lambda pid: f"fixture-start:{pid}",
        )
        self.marker_path = self.supervisor.pid_marker_path(str(self.profile))
        self.marker_path.parent.mkdir()
        self.probe = ReadinessProbe("http://127.0.0.1:8642/health")
        payload = self.supervisor.adapter.launcher_payload(
            "coder", operation_id="a" * 32, desired_revision=1, readiness_probe=self.probe
        )
        self.marker = dict(payload["marker"])
        self.marker.update(
            pid=self.pid,
            started_at=1_780_000_000.0,
            proc_start_fingerprint=f"fixture-start:{self.pid}",
        )
        self._write_marker()
        self.transport = self.enterContext(patch("zeus.bot_diagnostics.probe_gateway_health"))
        self.transport.return_value = ("ok", {"status": "ok", "pid": self.pid})
        self.enterContext(
            patch.object(self.store, "get_bot", side_effect=AssertionError("write-capable read"))
        )
        self.enterContext(patch.object(self.store, "init", side_effect=AssertionError("init")))
        self.enterContext(
            patch.object(self.supervisor, "status", side_effect=AssertionError("status"))
        )
        self.enterContext(
            patch.object(self.supervisor, "kill_fn", side_effect=AssertionError("signal"))
        )

    def _write_marker(self) -> None:
        self.marker_path.write_text(json.dumps(self.marker), encoding="utf-8")

    def _diagnose(self) -> dict[str, object]:
        result = diagnose_bot(self.supervisor, "coder")
        self.assertEqual(
            {"bot_id", "observed_at", "status", "reason", "process", "health"}, set(result)
        )
        self.assertEqual({"pid", "verified"}, set(result["process"]))
        self.assertEqual(timedelta(0), datetime.fromisoformat(result["observed_at"]).utcoffset())
        self.assertTrue(self.api_key not in json.dumps(result))
        return result

    def test_ok_and_degraded_health_are_bound_to_owned_process(self) -> None:
        for status in ("ok", "degraded"):
            with self.subTest(status=status):
                self.transport.return_value = (status, {"status": status, "pid": self.pid})
                result = self._diagnose()
                self.assertEqual(status, result["status"])
                self.assertEqual(status, result["reason"])
                self.assertEqual({"pid": self.pid, "verified": True}, result["process"])
                self.assertEqual(status, result["health"]["status"])
                self.assertEqual((self.probe.url,), self.transport.call_args.args)
                self.assertEqual(self.pid, self.transport.call_args.kwargs["expected_pid"])
                self.assertTrue(self.transport.call_args.kwargs["api_key"] == self.api_key)

    def test_unknown_bot_and_invalid_id_do_not_probe(self) -> None:
        with self.assertRaises(KeyError):
            diagnose_bot(self.supervisor, "unknown-bot")
        with patch("zeus.bot_diagnostics.sqlite3.connect") as connect:
            with self.assertRaises(ValueError):
                diagnose_bot(self.supervisor, "../invalid")
            connect.assert_not_called()
        self.transport.assert_not_called()

    def test_absent_or_unreadable_database_never_creates_state(self) -> None:
        missing_root = self.root / "missing"
        supervisor = Supervisor(
            StateStore(missing_root / "zeus.db"), "hermes", missing_root / "hermes"
        )
        with self.assertRaisesRegex(StateReadinessError, "bot diagnostics state is unavailable"):
            diagnose_bot(supervisor, "coder")
        self.assertFalse(missing_root.exists())
        self.store.database_path.write_bytes(b"invalid-database")
        with self.assertRaisesRegex(StateReadinessError, "bot diagnostics state is unavailable"):
            self._diagnose()
        self.transport.assert_not_called()

    def test_pending_operation_precedes_process_observation(self) -> None:
        for action in ("start", "stop", "restart"):
            with self.subTest(action=action):
                self.store.upsert_bot(
                    replace(
                        self.record,
                        pending_operation_id="b" * 32,
                        pending_action=action,
                        pending_since=datetime.now(UTC),
                    )
                )
                result = self._diagnose()
                self.assertEqual("operation_pending", result["reason"])
                self.assertFalse(result["process"]["verified"])
        self.transport.assert_not_called()

    def test_missing_or_dead_pid_is_not_running_without_cleanup(self) -> None:
        for pid in (None, self.pid):
            with self.subTest(pid=pid):
                self.alive = False
                self.store.upsert_bot(replace(self.record, pid=pid))
                result = self._diagnose()
                self.assertEqual("not_running", result["status"])
                self.assertTrue(self.marker_path.exists())
        self.transport.assert_not_called()

    def test_untrusted_marker_and_unknown_process_do_not_probe(self) -> None:
        for case in (
            "missing",
            "legacy",
            "invalid",
            "symlink",
            "hardlink",
            "wrong_revision",
            "wrong_pid",
            "unknown_pid",
            "wrong_command",
            "wrong_start",
        ):
            with self.subTest(case=case):
                original = dict(self.marker)
                linked = self.root / "linked-marker"
                self._write_marker()
                if case == "missing":
                    self.marker_path.unlink()
                elif case == "legacy":
                    self.marker_path.write_text(json.dumps({"pid": self.pid}), encoding="utf-8")
                elif case == "invalid":
                    self.marker_path.write_text("invalid", encoding="utf-8")
                elif case in {"symlink", "hardlink"}:
                    linked.write_bytes(self.marker_path.read_bytes())
                    self.marker_path.unlink()
                    if case == "symlink":
                        self.marker_path.symlink_to(linked)
                    else:
                        os.link(linked, self.marker_path)
                elif case == "wrong_revision":
                    self.marker["desired_revision"] = 2
                    self._write_marker()
                elif case == "wrong_pid":
                    self.marker["pid"] = self.pid + 1
                    self._write_marker()
                elif case == "unknown_pid":

                    def unknown(_pid):
                        raise PermissionError

                    self.supervisor.pid_alive_fn = unknown
                elif case == "wrong_command":
                    self.supervisor.cmdline_reader = lambda _pid: ["unrelated-process"]
                else:
                    self.supervisor.proc_start_fingerprint_reader = lambda _pid: "reused"
                result = self._diagnose()
                self.assertEqual("unverified", result["status"])
                self.assertEqual("process_unverified", result["reason"])
                self.assertIsNone(result["health"])
                self.marker_path.unlink(missing_ok=True)
                linked.unlink(missing_ok=True)
                self.marker = original
                self.supervisor.pid_alive_fn = lambda _pid: True
                self.supervisor.cmdline_reader = lambda _pid: [
                    str(self.hermes),
                    "-p",
                    "coder",
                    "gateway",
                    "run",
                ]
                self.supervisor.proc_start_fingerprint_reader = lambda pid: f"fixture-start:{pid}"
        self.transport.assert_not_called()

    def test_missing_probe_and_credentials_have_distinct_safe_results(self) -> None:
        self.marker["readiness_probe"] = None
        self._write_marker()
        result = self._diagnose()
        self.assertEqual("not_configured", result["status"])
        self.assertEqual("probe_not_configured", result["reason"])
        self.assertTrue(result["process"]["verified"])
        self.marker["readiness_probe"] = {
            "url": self.probe.url,
            "expected_status": "ok",
            "expected_platform": "hermes-agent",
            "timeout_seconds": 30,
            "interval_seconds": 0.5,
        }
        self._write_marker()
        self.env_file.write_text("", encoding="utf-8")
        result = self._diagnose()
        self.assertEqual("credentials_unavailable", result["reason"])
        self.env_file.write_text(f"HERMES_HOME={self.api_key}\n", encoding="utf-8")
        result = self._diagnose()
        self.assertEqual("configuration_invalid", result["reason"])
        self.assertEqual("unavailable", result["status"])
        self.transport.assert_not_called()

    def test_profile_endpoint_edits_cannot_redirect_diagnostic_request(self) -> None:
        self.env_file.write_text(
            f"API_SERVER_KEY={self.api_key}\nAPI_SERVER_ENABLED=1\nAPI_SERVER_PORT=9988\n",
            encoding="utf-8",
        )

        def probe(url, **_kwargs):
            self.assertEqual(self.probe.url, url)
            self.env_file.write_text(
                f"API_SERVER_KEY={self.api_key}\nAPI_SERVER_PORT=9977\n", encoding="utf-8"
            )
            return "ok", {"status": "ok", "pid": self.pid}

        self.transport.side_effect = probe
        self.assertEqual("ok", self._diagnose()["status"])

    def test_changed_runtime_discards_health_even_when_transport_failed(self) -> None:
        for case in (
            "operation",
            "pid",
            "revision",
            "created",
            "status",
            "pending",
            "endpoint",
            "start",
            "dead",
            "missing_marker",
            "deleted",
            "database",
        ):
            for transport_ok in (True, False):
                with self.subTest(case=case, transport_ok=transport_ok):

                    def probe(_url, case=case, transport_ok=transport_ok, **_kwargs):
                        if case == "operation":
                            self.marker["operation_id"] = "b" * 32
                            self._write_marker()
                        elif case in {"pid", "revision", "created", "status", "pending"}:
                            change = {
                                "pid": {"pid": self.pid + 1},
                                "revision": {"desired_revision": 2},
                                "created": {
                                    "created_at": self.record.created_at + timedelta(seconds=1)
                                },
                                "status": {"status": BotStatus.failed},
                                "pending": {
                                    "pending_action": "restart",
                                    "pending_operation_id": "b" * 32,
                                    "pending_since": datetime.now(UTC),
                                },
                            }[case]
                            if case == "created":
                                self.store.delete_bot("coder")
                            self.store.upsert_bot(replace(self.record, **change))
                        elif case == "endpoint":
                            self.marker["readiness_probe"]["url"] = "http://127.0.0.1:9876/health"
                            self._write_marker()
                        elif case == "start":
                            self.supervisor.proc_start_fingerprint_reader = lambda _pid: (
                                "new-process"
                            )
                        elif case == "dead":
                            self.alive = False
                        elif case == "missing_marker":
                            self.marker_path.unlink()
                        elif case == "deleted":
                            self.store.delete_bot("coder")
                        else:
                            self.store.database_path.rename(self.root / "temporarily-moved.db")
                        return (
                            ("ok", {"status": "ok", "pid": self.pid})
                            if transport_ok
                            else ("timeout", None)
                        )

                    original = json.loads(json.dumps(self.marker))
                    self.transport.side_effect = probe
                    result = self._diagnose()
                    self.assertEqual("unverified", result["status"])
                    self.assertEqual("runtime_changed", result["reason"])
                    self.assertFalse(result["process"]["verified"])
                    self.assertIsNone(result["health"])
                    moved = self.root / "temporarily-moved.db"
                    if moved.exists():
                        moved.rename(self.store.database_path)
                    self.store.delete_bot("coder")
                    self.store.upsert_bot(self.record)
                    self.marker = original
                    self._write_marker()
                    self.alive = True
                    self.supervisor.proc_start_fingerprint_reader = lambda pid: (
                        f"fixture-start:{pid}"
                    )

    def test_health_failures_and_exception_details_are_not_exposed(self) -> None:
        for reason in (
            "authentication_failed",
            "unsupported_runtime",
            "invalid_health",
            "timeout",
            "pid_mismatch",
        ):
            with self.subTest(reason=reason):
                self.transport.return_value = (reason, None)
                result = self._diagnose()
                self.assertEqual("unavailable", result["status"])
                self.assertEqual(reason, result["reason"])
                self.assertIsNone(result["health"])
                self.assertTrue(result["process"]["verified"])
        self.transport.side_effect = OSError(self.api_key)
        self.assertEqual("health_unavailable", self._diagnose()["reason"])

    def test_diagnosis_preserves_database_history_marker_and_lock_files(self) -> None:
        def snapshot():
            with closing(sqlite3.connect(self.store.database_path)) as conn:
                return list(conn.iterdump()), conn.execute("PRAGMA journal_mode").fetchone()[0]

        with closing(sqlite3.connect(self.store.database_path)) as conn:
            conn.execute("PRAGMA journal_mode=DELETE")
        before = snapshot()
        self.assertEqual("delete", before[1])
        marker = self.marker_path.read_bytes()
        for _ in range(2):
            self.assertEqual("ok", self._diagnose()["status"])
        self.assertEqual(before, snapshot())
        self.assertEqual(marker, self.marker_path.read_bytes())
        self.assertFalse((self.root / "locks").exists())
        self.assertFalse((self.profile / "logs" / "zeus-gateway.lock").exists())
        self.assertFalse(Path(str(self.store.database_path) + "-wal").exists())

    def test_incompatible_schema_and_corrupt_record_have_safe_errors(self) -> None:
        with closing(sqlite3.connect(self.store.database_path)) as conn:
            conn.execute("UPDATE bots SET created_at = ? WHERE bot_id = ?", ("invalid", "coder"))
            conn.commit()
        with self.assertRaisesRegex(StateReadinessError, "bot diagnostics state is unavailable"):
            self._diagnose()
        with closing(sqlite3.connect(self.store.database_path)) as conn:
            conn.execute(
                "UPDATE bots SET created_at = ? WHERE bot_id = ?",
                (self.record.created_at.isoformat(), "coder"),
            )
            conn.execute("UPDATE schema_version SET version = 999")
            conn.commit()
        with self.assertRaisesRegex(StateReadinessError, "bot diagnostics state is unavailable"):
            self._diagnose()
        self.transport.assert_not_called()
