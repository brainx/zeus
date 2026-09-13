from __future__ import annotations

import inspect
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from zeus.gateway_runtime import OwnershipCheck
from zeus.models import BotRecord, BotStatus, DesiredState
from zeus.state import StateStore
from zeus.supervisor import Supervisor

EXPECTED_SIGNATURES = {
    "archive_bot": (
        "(self, bot_id: 'str', *, stop_if_running: 'bool' = False, source: 'str' = 'cli',"
        " request_id: 'str | None' = None) -> 'dict[str, object]'"
    ),
    "bot_lock": ("(self, bot_id: 'str') -> 'threading.RLock'"),
    "create_bot": (
        "(self, request: 'BotCreateRequest', template: 'HermesTemplate', *, replace_exist"
        "ing: 'bool' = False, stop_if_running: 'bool' = False, source: 'str' = 'cli', req"
        "uest_id: 'str | None' = None) -> 'BotRecord'"
    ),
    "delete_bot": (
        "(self, bot_id: 'str', *, stop_if_running: 'bool' = False, remove_profile: 'bool'"
        " = False, source: 'str' = 'cli', request_id: 'str | None' = None) -> 'BotStatusR"
        "esponse'"
    ),
    "inspect": ("(self, bot_id: 'str', max_log_bytes: 'int' = 20000) -> 'dict[str, object]'"),
    "log_path": ("(self, profile_path: 'str') -> 'Path'"),
    "logs": ("(self, bot_id: 'str', max_bytes: 'int' = 20000) -> 'str'"),
    "pid_marker_path": ("(self, profile_path: 'str') -> 'Path'"),
    "reconcile": (
        "(self, bot_id: 'str | None' = None, *, now: 'datetime | None' = None, force: 'bo"
        "ol' = False, reset_restart: 'bool' = False, source: 'str' = 'reconcile', request"
        "_id: 'str | None' = None, bot_snapshot: 'Sequence[tuple[str, str]] | None' = Non"
        "e) -> 'list[BotStatusResponse]'"
    ),
    "reconcile_execution": (
        "(self, bot_id: 'str | None' = None, *, now: 'datetime | None' = None, force: 'bo"
        "ol' = False, reset_restart: 'bool' = False, source: 'str' = 'reconcile', request"
        "_id: 'str | None' = None, bot_snapshot: 'Sequence[tuple[str, str]] | None' = Non"
        "e) -> 'ReconcileExecution'"
    ),
    "reconcile_one": (
        "(self, bot_id: 'str', *, now: 'datetime | None' = None, force: 'bool' = False, r"
        "eset_restart: 'bool' = False, source: 'str' = 'reconcile', request_id: 'str | No"
        "ne' = None, expected_profile_path: 'str | None' = None) -> 'BotReconcileResult'"
    ),
    "reconcile_one_execution": (
        "(self, bot_id: 'str', *, now: 'datetime | None' = None, force: 'bool' = False, r"
        "eset_restart: 'bool' = False, source: 'str' = 'reconcile', request_id: 'str | No"
        "ne' = None, expected_profile_path: 'str | None' = None) -> 'tuple[BotReconcileRe"
        "sult, BotStatusResponse]'"
    ),
    "reconcile_summary": (
        "(self, bot_id: 'str | None' = None, *, now: 'datetime | None' = None, force: 'bo"
        "ol' = False, reset_restart: 'bool' = False, source: 'str' = 'reconcile', request"
        "_id: 'str | None' = None, bot_snapshot: 'Sequence[tuple[str, str]] | None' = Non"
        "e) -> 'ReconcileRunSummary'"
    ),
    "restart": (
        "(self, bot_id: 'str', *, wait: 'bool' = False, timeout_seconds: 'float | None' ="
        " None, source: 'str' = 'cli', request_id: 'str | None' = None) -> 'BotStatusResp"
        "onse'"
    ),
    "start": (
        "(self, bot_id: 'str', *, wait: 'bool' = False, timeout_seconds: 'float | None' ="
        " None, source: 'str' = 'cli', request_id: 'str | None' = None) -> 'BotStatusResp"
        "onse'"
    ),
    "status": (
        "(self, bot_id: 'str', *, source: 'str' = 'cli', request_id: 'str | None' = None)"
        " -> 'BotStatusResponse'"
    ),
    "stop": (
        "(self, bot_id: 'str', *, kill_after_timeout: 'bool | None' = None, source: 'str'"
        " = 'cli', request_id: 'str | None' = None) -> 'BotStatusResponse'"
    ),
    "validate_reconcile_request": ("(self, source: 'str', request_id: 'str | None') -> 'None'"),
    "validate_reconcile_target": (
        "(self, bot_id: 'str', *, expected_profile_path: 'str | None' = None) -> 'str'"
    ),
    "__init__": (
        "(self, store: 'StateStore', hermes_bin: 'str', hermes_root: 'Path | str', popen_"
        "factory: 'PopenFactory' = <class 'subprocess.Popen'>, kill_fn: 'KillFn' = <built"
        "-in function kill>, pid_alive_fn: 'PidAliveFn | None' = None, cmdline_reader: 'C"
        "mdlineReader | None' = None, startup_grace_seconds: 'float' = 0.25, stop_grace_s"
        "econds: 'float' = 60.0, kill_after_timeout: 'bool' = False, lock_timeout_seconds"
        ": 'float' = 30.0, readiness_timeout_seconds: 'float' = 30.0, readiness_interval_"
        "seconds: 'float' = 0.5, allow_legacy_pid_markers: 'bool' = True, restart_backoff"
        "_cap_seconds: 'float' = 3600.0, proc_start_fingerprint_reader: 'ProcStartFingerp"
        "rintReader | None' = None, restart_stability_seconds: 'float' = 30.0) -> 'None'"
    ),
}


class SupervisorCompositionCharacterizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.store = StateStore(self.root / "state.db")
        self.store.init()
        self.launch = Mock(side_effect=AssertionError("unexpected process launch"))
        self.signal = Mock(side_effect=AssertionError("unexpected process signal"))
        self.alive = Mock(return_value=False)
        self.cmdline = Mock(return_value=None)
        self.fingerprint = Mock(return_value=None)
        self.supervisor = Supervisor(
            self.store,
            "hermes",
            self.root / "hermes",
            popen_factory=self.launch,
            kill_fn=self.signal,
            pid_alive_fn=self.alive,
            cmdline_reader=self.cmdline,
            proc_start_fingerprint_reader=self.fingerprint,
        )

    def test_complete_public_signatures(self) -> None:
        signatures = {
            name: str(inspect.signature(getattr(Supervisor, name)))
            for name in dir(Supervisor)
            if not name.startswith("_") and callable(getattr(Supervisor, name))
        }
        signatures["__init__"] = str(inspect.signature(Supervisor.__init__))
        self.assertEqual(EXPECTED_SIGNATURES, signatures)

    def test_constructor_callbacks_and_all_proxy_nested_exception_restoration(self) -> None:
        callbacks = {
            "popen_factory": self.launch,
            "kill_fn": self.signal,
            "pid_alive_fn": self.alive,
            "cmdline_reader": self.cmdline,
            "proc_start_fingerprint_reader": self.fingerprint,
        }
        for name, value in callbacks.items():
            self.assertIs(value, getattr(self.supervisor._runtime, name))
        proxies = (
            *callbacks,
            "stop_grace_seconds",
            "kill_after_timeout",
            "lock_timeout_seconds",
            "_processes",
        )
        for name in proxies:
            with self.subTest(name=name):
                original = getattr(self.supervisor, name)
                first = Mock() if name in callbacks else 0.5
                second = Mock() if name in callbacks else 0.75
                if name == "_processes":
                    first, second = {}, {}
                if name == "kill_after_timeout":
                    first, second = True, False
                with patch.object(self.supervisor, name, first):
                    self.assertIs(first, getattr(self.supervisor._runtime, name))
                    with (
                        self.assertRaisesRegex(RuntimeError, "exit"),
                        patch.object(self.supervisor, name, second),
                    ):
                        self.assertIs(second, getattr(self.supervisor._runtime, name))
                        raise RuntimeError("exit")
                    self.assertIs(first, getattr(self.supervisor._runtime, name))
                self.assertIs(original, getattr(self.supervisor._runtime, name))

    def test_hooks_resolve_public_globals_after_construction(self) -> None:
        hooks = {
            "os.pipe": "pipe",
            "os.close": "close",
            "_read_bounded_file": "read_bounded_file",
            "_remove_marker_if_owned_locked": "remove_marker_if_owned_locked",
            "probe_once": "probe_once",
        }
        provider = self.supervisor._runtime._hooks_provider
        for target, field in hooks.items():
            with self.subTest(target=target), patch(f"zeus.supervisor.{target}") as replacement:
                self.assertIs(replacement, getattr(provider(), field))
        # Constructor captures the provider; each invocation resolves its globals.
        with patch.object(self.supervisor, "_runtime_hooks", Mock()):
            self.assertIs(provider, self.supervisor._runtime._hooks_provider)

    def test_late_method_replacement_used_by_public_operations(self) -> None:
        replacement = Mock(return_value="replacement status")
        self.store.upsert_bot(
            BotRecord("bot", "test", "Bot", str(self.root / "hermes/profiles/bot"))
        )
        with patch.object(self.supervisor, "_status_locked", replacement):
            self.assertEqual("replacement status", self.supervisor.status("bot"))
        replacement.assert_called_once()
        runtime_replacement = Mock(return_value=OwnershipCheck(True, "owned"))
        with patch.object(
            self.supervisor._runtime, "verify_gateway_pid_ownership", runtime_replacement
        ):
            self.assertTrue(self.supervisor._pid_owned("profile", 123, "bot"))
        runtime_replacement.assert_called_once()

    def test_status_and_inspect_never_launch_or_signal(self) -> None:
        record = BotRecord(
            "bot",
            "test",
            "Bot",
            str(self.root / "hermes/profiles/bot"),
            desired_state=DesiredState.running,
        )
        self.store.upsert_bot(record)
        response = self.supervisor.status("bot")
        self.assertEqual(BotStatus.failed, response.status)
        before = self.store.get_bot("bot")
        self.supervisor.inspect("bot")
        self.assertEqual(before, self.store.get_bot("bot"))
        self.launch.assert_not_called()
        self.signal.assert_not_called()

    def test_status_pending_intents_never_launch_or_signal(self) -> None:
        record = BotRecord(
            "bot",
            "test",
            "Bot",
            str(self.root / "hermes/profiles/bot"),
            desired_state=DesiredState.running,
            pending_operation_id="a" * 32,
            pending_since=datetime.now(UTC),
        )
        for action in ("start", "stop", "restart"):
            with self.subTest(action=action):
                self.store.upsert_bot(replace(record, pending_action=action))
                self.supervisor.status("bot")
                self.launch.assert_not_called()
                self.signal.assert_not_called()
