from __future__ import annotations

import contextlib
import errno
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from zeus.errors import BotExistsError
from zeus.models import (
    BotCreateRequest,
    BotRecord,
    BotStatus,
    DesiredState,
    RestartPolicy,
    TemplateError,
)
from zeus.readiness import ReadinessResult
from zeus.reconciliation import ReconcileOutcome
from zeus.state import StateStore
from zeus.supervisor import Supervisor
from zeus.templates import TemplateStore


class _FakePopen:
    pid = 4321

    def __init__(self, argv, env, stdout, stderr, **kwargs):
        self.returncode: int | None = None
        _emulate_launcher_handshake(argv, self.pid)

    def poll(self) -> int | None:
        return self.returncode


def _emulate_launcher_handshake(argv: list[str], pid: int) -> None:
    if len(argv) < 5 or argv[1:3] != ["-m", "zeus.gateway_launcher"]:
        return
    payload_fd = os.dup(int(argv[-2]))
    ack_fd = os.dup(int(argv[-1]))

    def publish() -> None:
        try:
            chunks: list[bytes] = []
            while chunk := os.read(payload_fd, 65536):
                chunks.append(chunk)
            payload = json.loads(b"".join(chunks))
            marker = dict(payload["marker"])
            marker.update(
                {
                    "pid": pid,
                    "started_at": time.time(),
                    "proc_start_fingerprint": f"test-process-start:{pid}",
                }
            )
            marker_path = Path(payload["marker_path"])
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.write_text(json.dumps(marker), encoding="utf-8")
            os.write(ack_fd, b"1")
        finally:
            os.close(payload_fd)
            os.close(ack_fd)

    threading.Thread(target=publish, daemon=True).start()


class _TrackingPopen(_FakePopen):
    instances: ClassVar[list[_TrackingPopen]] = []

    def __init__(self, argv, env, stdout, stderr, **kwargs):
        super().__init__(argv, env, stdout, stderr, **kwargs)
        self.signals: list[signal.Signals] = []
        self.wait_calls = 0
        self.__class__.instances.append(self)

    def terminate(self) -> None:
        self.signals.append(signal.SIGTERM)
        self.returncode = -signal.SIGTERM

    def kill(self) -> None:
        self.signals.append(signal.SIGKILL)
        self.returncode = -signal.SIGKILL

    def wait(self, timeout: float) -> int:
        self.wait_calls += 1
        if self.returncode is None:
            raise subprocess.TimeoutExpired("hermes", timeout)
        return self.returncode


class _AlwaysTimeoutPopen(_FakePopen):
    def wait(self, timeout: float) -> int:
        raise subprocess.TimeoutExpired("hermes", timeout)


class _UnstoppablePopen(_FakePopen):
    def terminate(self) -> None:
        raise PermissionError(errno.EPERM, "operation not permitted")


class LifecycleRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        _TrackingPopen.instances.clear()

    def _fake_hermes(self, root: Path) -> str:
        hermes = root / "bin" / "hermes"
        hermes.parent.mkdir(parents=True, exist_ok=True)
        hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        hermes.chmod(0o755)
        return str(hermes.resolve())

    def _store_with_bot(
        self,
        root: Path,
        *,
        status: BotStatus = BotStatus.stopped,
        pid: int | None = None,
        restart_policy: RestartPolicy = RestartPolicy.manual,
        last_error: str | None = None,
    ) -> tuple[StateStore, Path]:
        profile_path = root / "hermes" / "profiles" / "coder"
        profile_path.mkdir(parents=True, exist_ok=True)
        (profile_path / ".env").write_text("", encoding="utf-8")
        store = StateStore(root / "zeus.db")
        store.init()
        store.upsert_bot(
            BotRecord(
                bot_id="coder",
                template_id="coding-bot",
                display_name="Coder",
                profile_path=str(profile_path),
                status=status,
                pid=pid,
                restart_policy=restart_policy,
                restart_backoff_seconds=1.0,
                last_error=last_error,
                desired_state=(
                    DesiredState.running
                    if status in {BotStatus.running, BotStatus.starting}
                    or (
                        status in {BotStatus.failed, BotStatus.unknown}
                        and restart_policy is RestartPolicy.on_failure
                    )
                    else DesiredState.stopped
                ),
            )
        )
        return store, profile_path

    def _gateway_argv(self, hermes_bin: str) -> list[str]:
        return [hermes_bin, "-p", "coder", "gateway", "run"]

    def _write_schema_v3_marker(
        self,
        supervisor: Supervisor,
        profile_path: Path,
        *,
        pid: int,
    ) -> None:
        payload = supervisor.adapter.launcher_payload(
            "coder",
            operation_id="a" * 32,
            desired_revision=1,
            readiness_probe=None,
        )
        marker = dict(payload["marker"])
        marker.update(
            {
                "pid": pid,
                "started_at": 1_780_000_000.0,
                "proc_start_fingerprint": f"test-process-start:{pid}",
            }
        )
        marker_path = supervisor.pid_marker_path(str(profile_path))
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text(json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8")

    def test_status_preserves_failed_and_unknown_for_on_failure_reconcile(self) -> None:
        for persisted_status in (BotStatus.failed, BotStatus.unknown):
            with self.subTest(status=persisted_status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store, _profile_path = self._store_with_bot(
                    root,
                    status=persisted_status,
                    pid=4321,
                    restart_policy=RestartPolicy.on_failure,
                    last_error="original lifecycle error",
                )
                supervisor = Supervisor(
                    store,
                    "hermes",
                    root / "hermes",
                    pid_alive_fn=lambda pid: False,
                )

                status = supervisor.status("coder")

                self.assertEqual(BotStatus.failed, status.status)
                self.assertIn("action required", status.message)
                loaded = store.get_bot("coder")
                self.assertIsNotNone(loaded)
                assert loaded is not None
                self.assertEqual(BotStatus.failed, loaded.status)
                self.assertIsNone(loaded.pid)
                self.assertIn("action required", loaded.last_error or "")

                scheduled = supervisor.reconcile("coder", now=datetime(2026, 7, 9, tzinfo=UTC))[0]
                self.assertEqual(BotStatus.failed, scheduled.status)
                self.assertIn("restart scheduled", scheduled.message)

    def test_live_failed_and_unknown_status_preserve_failure_metadata(self) -> None:
        for persisted_status in (BotStatus.failed, BotStatus.unknown):
            with self.subTest(status=persisted_status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                hermes_bin = self._fake_hermes(root)
                store, profile_path = self._store_with_bot(
                    root,
                    status=persisted_status,
                    pid=4321,
                    last_error="original lifecycle error",
                )
                original = store.get_bot("coder")
                assert original is not None
                store.upsert_bot(
                    replace(
                        original,
                        last_exit_code=17,
                        last_transition_reason="original transition",
                    )
                )
                supervisor = Supervisor(
                    store,
                    hermes_bin,
                    root / "hermes",
                    pid_alive_fn=lambda pid: True,
                    cmdline_reader=lambda pid, hermes_bin=hermes_bin: self._gateway_argv(
                        hermes_bin
                    ),
                    proc_start_fingerprint_reader=lambda pid: None,
                )
                supervisor._write_pid_marker(
                    str(profile_path),
                    4321,
                    "coder",
                    self._gateway_argv(hermes_bin),
                )

                response = supervisor.status("coder")

                self.assertEqual(persisted_status, response.status)
                loaded = store.get_bot("coder")
                assert loaded is not None
                self.assertEqual(persisted_status, loaded.status)
                self.assertEqual("original lifecycle error", loaded.last_error)
                self.assertEqual(17, loaded.last_exit_code)
                self.assertEqual("original transition", loaded.last_transition_reason)

    def test_invalid_readiness_timeout_is_rejected_before_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(root)

            def unexpected_spawn(*args, **kwargs):
                self.fail("gateway must not spawn for an invalid readiness timeout")

            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=unexpected_spawn,
                startup_grace_seconds=0,
            )

            for timeout in (-1.0, 0.09, 301.0, float("inf"), float("nan")):
                with self.subTest(timeout=timeout), self.assertRaises(TemplateError):
                    supervisor.start("coder", timeout_seconds=timeout)

    def test_start_and_stop_events_share_operation_context_without_synthetic_cli_request_id(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes(root)
            store, _profile_path = self._store_with_bot(root)
            alive: set[int] = set()

            def spawn(*args, **kwargs):
                process = _FakePopen(*args, **kwargs)
                alive.add(process.pid)
                return process

            def kill(pid: int, sig: signal.Signals) -> None:
                alive.discard(pid)

            supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                popen_factory=spawn,
                kill_fn=kill,
                pid_alive_fn=lambda pid: pid in alive,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                startup_grace_seconds=0,
                stop_grace_seconds=0.01,
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            request_id = "b" * 32

            started = supervisor.start("coder", source="api", request_id=request_id)
            stopped = supervisor.stop("coder")

            self.assertEqual(BotStatus.running, started.status)
            self.assertEqual(BotStatus.stopped, stopped.status)
            events = list(reversed(store.list_lifecycle_events("coder", limit=50, before=None)))
            self.assertEqual(
                [
                    ("stopped", "stopped"),
                    ("stopped", "running"),
                    ("running", "running"),
                    ("running", "stopped"),
                ],
                [(event.status_before, event.status_after) for event in events],
            )
            self.assertEqual(events[0].operation_id, events[1].operation_id)
            self.assertEqual(events[2].operation_id, events[3].operation_id)
            self.assertNotEqual(events[1].operation_id, events[2].operation_id)
            self.assertEqual(
                [request_id, request_id, None, None],
                [event.request_id for event in events],
            )
            self.assertEqual(["api", "api", "cli", "cli"], [event.source for event in events])

    def test_lifecycle_request_context_rejects_untrusted_or_synthetic_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(root)
            supervisor = Supervisor(store, "hermes", root / "hermes")

            with self.assertRaises(ValueError):
                supervisor.start("coder", source="api", request_id="caller-controlled")
            with self.assertRaises(ValueError):
                supervisor.start("coder", source="cli", request_id="a" * 32)
            with self.assertRaises(ValueError):
                supervisor.start("coder", source="untrusted", request_id=None)

    def test_create_delete_and_reconcile_transitions_record_public_operation_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, self._fake_hermes(root), root / "hermes")
            create_request_id = "c" * 32
            delete_request_id = "d" * 32

            supervisor.create_bot(
                BotCreateRequest(bot_id="coder", template_id="coding-bot"),
                TemplateStore().get("coding-bot"),
                source="api",
                request_id=create_request_id,
            )
            supervisor.delete_bot(
                "coder",
                source="api",
                request_id=delete_request_id,
            )

            events = list(reversed(store.list_lifecycle_events("coder", limit=50, before=None)))
            self.assertEqual(["bot.create", "bot.delete"], [event.action for event in events])
            self.assertEqual(
                [create_request_id, delete_request_id],
                [event.request_id for event in events],
            )
            self.assertNotEqual(events[0].operation_id, events[1].operation_id)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(
                root,
                status=BotStatus.failed,
                restart_policy=RestartPolicy.on_failure,
            )
            supervisor = Supervisor(store, "hermes", root / "hermes")

            supervisor.reconcile("coder", now=datetime(2026, 1, 1, tzinfo=UTC))

            event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
            self.assertEqual("bot.restart.schedule", event.action)
            self.assertEqual("success", event.outcome)
            self.assertEqual("reconcile", event.source)
            self.assertIsNone(event.request_id)

    def test_reconcile_one_stable_stopped_is_healthy_without_ledger_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(root)
            supervisor = Supervisor(store, "hermes", root / "hermes")

            result = supervisor.reconcile_one("coder", source="cli")

            self.assertEqual(ReconcileOutcome.healthy, result.outcome)
            self.assertEqual("none", result.action)
            self.assertIsNone(result.event_id)
            self.assertEqual([], store.list_lifecycle_events("coder", limit=10, before=None))
            legacy = supervisor.reconcile("coder", source="cli")
            self.assertEqual(1, len(legacy))
            self.assertEqual(BotStatus.stopped, legacy[0].status)
            self.assertEqual("not running", legacy[0].message)

    def test_reconcile_one_links_transition_event_and_classifies_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(
                root,
                status=BotStatus.failed,
                restart_policy=RestartPolicy.on_failure,
            )
            supervisor = Supervisor(store, "hermes", root / "hermes")

            result = supervisor.reconcile_one(
                "coder",
                now=datetime(2026, 1, 1, tzinfo=UTC),
                source="cli",
            )

            self.assertEqual(ReconcileOutcome.pending, result.outcome)
            event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
            self.assertEqual(event.event_id, result.event_id)
            self.assertEqual("bot.restart.schedule", result.action)
            self.assertEqual("cli", event.source)

    def test_reconcile_one_marks_successful_state_transition_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(
                root,
                status=BotStatus.running,
                pid=4321,
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(replace(record, desired_state=DesiredState.stopped))
            supervisor = Supervisor(
                store,
                "hermes",
                root / "hermes",
                pid_alive_fn=lambda pid: False,
            )

            result = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.changed, result.outcome)
            self.assertEqual(BotStatus.stopped.value, result.observed_status)
            event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
            self.assertEqual(event.event_id, result.event_id)
            self.assertEqual("bot.reconcile.stopped", result.action)

    def test_reconcile_one_resets_stale_running_metadata_then_becomes_true_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes(root)
            store, profile_path = self._store_with_bot(
                root,
                status=BotStatus.running,
                pid=4321,
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    restart_attempts=2,
                    next_restart_at=datetime.now(UTC) + timedelta(minutes=5),
                    ready_at=None,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: None,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            changed = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.changed, changed.outcome)
            self.assertIsNotNone(changed.event_id)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(0, loaded.restart_attempts)
            self.assertIsNone(loaded.next_restart_at)
            self.assertIsNotNone(loaded.ready_at)
            event_count = len(store.list_lifecycle_events("coder", limit=10, before=None))

            healthy = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.healthy, healthy.outcome)
            self.assertIsNone(healthy.event_id)
            self.assertEqual(
                event_count,
                len(store.list_lifecycle_events("coder", limit=10, before=None)),
            )

    def test_reconcile_one_repairs_only_stale_live_failure_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes(root)
            store, profile_path = self._store_with_bot(
                root,
                status=BotStatus.running,
                pid=4321,
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    ready_at=datetime.now(UTC) - timedelta(seconds=1),
                    last_error="stale gateway failure",
                    last_exit_code=17,
                )
            )
            supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: None,
            )
            supervisor._write_pid_marker(
                str(profile_path),
                4321,
                "coder",
                self._gateway_argv(hermes_bin),
            )

            changed = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.changed, changed.outcome)
            self.assertIsNotNone(changed.event_id)
            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertIsNone(loaded.last_error)
            self.assertIsNone(loaded.last_exit_code)
            event_count = len(store.list_lifecycle_events("coder", limit=10, before=None))

            healthy = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.healthy, healthy.outcome)
            self.assertIsNone(healthy.event_id)
            self.assertEqual(
                event_count,
                len(store.list_lifecycle_events("coder", limit=10, before=None)),
            )

    def test_reconcile_one_preserves_safe_restart_limit_error_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(
                root,
                status=BotStatus.failed,
                restart_policy=RestartPolicy.on_failure,
            )
            record = store.get_bot("coder")
            assert record is not None
            store.upsert_bot(
                replace(
                    record,
                    restart_attempts=record.restart_max_attempts,
                    desired_state=DesiredState.running,
                )
            )
            supervisor = Supervisor(store, "hermes", root / "hermes")

            result = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.error, result.outcome)
            self.assertEqual("restart_limit_reached", result.error_code)
            self.assertEqual("bot reconciliation failed", result.message)
            event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
            self.assertEqual(event.event_id, result.event_id)
            self.assertEqual("bot.restart.limit_reached", result.action)

    def test_reconcile_one_error_links_event_created_before_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(root)
            supervisor = Supervisor(store, "hermes", root / "hermes")

            def fail_after_event(record, now, *, force, reset_restart, context):
                del now, force, reset_restart
                supervisor._update_lifecycle(
                    context,
                    record.bot_id,
                    BotStatus.failed,
                    action="bot.reconcile.partial",
                    last_error="partial reconcile failure",
                    last_transition_reason="partial reconcile mutation",
                )
                raise RuntimeError("token-secret /private/reconcile")

            with patch.object(supervisor, "_reconcile_record", side_effect=fail_after_event):
                result = supervisor.reconcile_one("coder")

            self.assertEqual(ReconcileOutcome.error, result.outcome)
            self.assertEqual("bot reconciliation failed", result.message)
            self.assertNotIn("token-secret", result.message)
            event = store.list_lifecycle_events("coder", limit=1, before=None)[0]
            self.assertEqual(event.event_id, result.event_id)
            self.assertEqual("bot.reconcile.partial", result.action)

    def test_reconcile_one_and_legacy_adapter_preserve_explicit_missing_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, "hermes", root / "hermes")

            with self.assertRaisesRegex(KeyError, "unknown bot"):
                supervisor.reconcile_one("missing")
            with self.assertRaisesRegex(KeyError, "unknown bot"):
                supervisor.reconcile("missing")

    def test_unregistered_profile_requires_explicit_replace_and_preserves_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_root = root / "hermes"
            profile = hermes_root / "profiles" / "coder"
            profile.mkdir(parents=True)
            (profile / "custom.txt").write_text("retain me\n", encoding="utf-8")
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, self._fake_hermes(root), hermes_root)
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            template = TemplateStore().get("coding-bot")

            with self.assertRaises(BotExistsError):
                supervisor.create_bot(request, template)

            created = supervisor.create_bot(request, template, replace_existing=True)

            self.assertEqual("coder", created.bot_id)
            self.assertEqual("retain me\n", (profile / "custom.txt").read_text(encoding="utf-8"))

    def test_failed_active_replacement_restores_profile_and_restarts_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root, status=BotStatus.running)
            sentinel = profile_path / "sentinel.txt"
            sentinel.write_text("original\n", encoding="utf-8")
            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=_TrackingPopen,
                startup_grace_seconds=0,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(self._fake_hermes(root)),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            real_upsert = store.upsert_bot_with_event
            calls = 0

            def fail_replacement_once(record: BotRecord, *, event) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise RuntimeError("database unavailable")
                real_upsert(record, event=event)

            with (
                patch.object(store, "upsert_bot_with_event", side_effect=fail_replacement_once),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.create_bot(
                    BotCreateRequest(bot_id="coder", template_id="coding-bot"),
                    TemplateStore().get("coding-bot"),
                    replace_existing=True,
                    stop_if_running=True,
                )

            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(BotStatus.running, loaded.status)
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("original\n", sentinel.read_text(encoding="utf-8"))
            recovery_events = store.list_lifecycle_events("coder", limit=50, before=None)
            self.assertIn("bot.recovery.prepare", [event.action for event in recovery_events])
            self.assertEqual(1, len({event.operation_id for event in recovery_events}))
            self.assertTrue(all(event.request_id is None for event in recovery_events))
            self.assertEqual(
                "recovery",
                next(
                    event.source
                    for event in recovery_events
                    if event.action == "bot.recovery.prepare"
                ),
            )

    def test_failed_active_delete_restores_profile_and_restarts_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root, status=BotStatus.running)
            sentinel = profile_path / "sentinel.txt"
            sentinel.write_text("original\n", encoding="utf-8")
            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=_TrackingPopen,
                startup_grace_seconds=0,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(self._fake_hermes(root)),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            with (
                patch.object(
                    store,
                    "delete_bot_with_event",
                    side_effect=RuntimeError("database unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.delete_bot("coder", stop_if_running=True, remove_profile=True)

            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(BotStatus.running, loaded.status)
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("original\n", sentinel.read_text(encoding="utf-8"))

    def test_failed_active_archive_restores_profile_and_restarts_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root, status=BotStatus.running)
            sentinel = profile_path / "sentinel.txt"
            sentinel.write_text("original\n", encoding="utf-8")
            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=_TrackingPopen,
                startup_grace_seconds=0,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(self._fake_hermes(root)),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            with (
                patch.object(
                    store,
                    "delete_bot_with_event",
                    side_effect=RuntimeError("database unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.archive_bot("coder", stop_if_running=True)

            loaded = store.get_bot("coder")
            assert loaded is not None
            self.assertEqual(BotStatus.running, loaded.status)
            self.assertEqual(4321, loaded.pid)
            self.assertEqual("original\n", sentinel.read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "posix", "process-group cleanup requires POSIX")
    def test_registration_failure_terminates_spawned_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_file = root / "spawned-pids.txt"
            hermes = root / "bin" / "hermes"
            hermes.parent.mkdir(parents=True)
            hermes.write_text(
                "#!/bin/sh\n"
                "sleep 60 &\n"
                "child=$!\n"
                'printf \'%s\\n%s\\n\' "$$" "$child" >"$ZEUS_TEST_CHILD_PID_FILE"\n'
                'wait "$child"\n',
                encoding="utf-8",
            )
            hermes.chmod(0o755)
            store, profile_path = self._store_with_bot(root)
            (profile_path / ".env").write_text(
                f'ZEUS_TEST_CHILD_PID_FILE="{pid_file}"\n', encoding="utf-8"
            )
            supervisor = Supervisor(
                store,
                str(hermes),
                root / "hermes",
                startup_grace_seconds=0,
                stop_grace_seconds=1,
                cmdline_reader=lambda pid: self._gateway_argv(str(hermes.resolve())),
            )

            def fail_after_descendant_spawn(*args, **kwargs) -> None:
                deadline = time.monotonic() + 3
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not pid_file.exists():
                    self.fail("fake Hermes did not spawn its descendant")
                raise OSError("disk full")

            process_ids: list[int] = []
            try:
                with patch.object(
                    store,
                    "complete_lifecycle_intent",
                    side_effect=fail_after_descendant_spawn,
                ):
                    result = supervisor.start("coder")
                process_ids = [int(value) for value in pid_file.read_text().splitlines()]

                self.assertEqual(BotStatus.failed, result.status)
                for process_id in process_ids:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(process_id, 0)
            finally:
                if process_ids:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process_ids[0], signal.SIGKILL)

    def test_status_uses_launch_readiness_provenance_in_a_new_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes(root)
            store, profile_path = self._store_with_bot(root)
            launch_supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                popen_factory=_FakePopen,
                startup_grace_seconds=0,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            launch_env = {
                "ZEUS_ENV_PASSTHROUGH": "API_SERVER_ENABLED,API_SERVER_PORT",
                "API_SERVER_ENABLED": "1",
                "API_SERVER_PORT": "4312",
            }
            with patch.dict(os.environ, launch_env, clear=False):
                started = launch_supervisor.start("coder")

            self.assertEqual(BotStatus.starting, started.status)
            marker = json.loads(
                launch_supervisor.pid_marker_path(str(profile_path)).read_text(encoding="utf-8")
            )
            self.assertEqual(
                {
                    "url": "http://127.0.0.1:4312/health",
                    "expected_status": "ok",
                    "expected_platform": "hermes-agent",
                    "timeout_seconds": 30.0,
                    "interval_seconds": 0.5,
                },
                marker["readiness_probe"],
            )

            status_supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            with (
                patch.dict(os.environ, {"ZEUS_ENV_PASSTHROUGH": ""}, clear=False),
                patch(
                    "zeus.supervisor.probe_once",
                    return_value=ReadinessResult(False, "connection refused"),
                ) as probe_once,
            ):
                status = status_supervisor.status("coder")

            self.assertEqual(BotStatus.starting, status.status)
            self.assertEqual("connection refused", status.message)
            probe_once.assert_called_once_with(
                "http://127.0.0.1:4312/health",
                timeout_seconds=0.5,
                expected_status="ok",
                expected_platform="hermes-agent",
            )

    def test_marker_write_failure_terminates_reaps_and_restores_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root)
            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=_TrackingPopen,
                startup_grace_seconds=0,
            )

            def fail_after_marker(_fd: int) -> bytes:
                marker = supervisor.pid_marker_path(str(profile_path))
                deadline = time.monotonic() + 1
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.001)
                raise OSError("ack unavailable")

            with patch.object(
                supervisor,
                "_read_launcher_ack",
                side_effect=fail_after_marker,
            ):
                result = supervisor.start("coder")

            self.assertEqual(BotStatus.failed, result.status)
            self.assertIsNone(result.pid)
            self.assertNotIn("disk full", result.message)
            process = _TrackingPopen.instances[-1]
            self.assertEqual([signal.SIGTERM], process.signals)
            self.assertGreaterEqual(process.wait_calls, 1)
            self.assertNotIn("coder", supervisor._processes)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.stopped, loaded.status)
            self.assertIsNone(loaded.pid)
            self.assertEqual("start", loaded.pending_action)

    def test_database_registration_failure_terminates_reaps_and_removes_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root)
            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=_TrackingPopen,
                startup_grace_seconds=0,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(self._fake_hermes(root)),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            with patch.object(
                store,
                "complete_lifecycle_intent",
                side_effect=RuntimeError("database unavailable"),
            ):
                result = supervisor.start("coder")

            self.assertEqual(BotStatus.failed, result.status)
            self.assertIsNone(result.pid)
            self.assertNotIn("database unavailable", result.message)
            process = _TrackingPopen.instances[-1]
            self.assertEqual([signal.SIGTERM], process.signals)
            self.assertGreaterEqual(process.wait_calls, 1)
            self.assertNotIn("coder", supervisor._processes)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.stopped, loaded.status)
            self.assertIsNone(loaded.pid)
            self.assertEqual("start", loaded.pending_action)

    def test_registration_failure_returns_unknown_when_child_cleanup_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _profile_path = self._store_with_bot(root)
            supervisor = Supervisor(
                store,
                self._fake_hermes(root),
                root / "hermes",
                popen_factory=_UnstoppablePopen,
                startup_grace_seconds=0,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(self._fake_hermes(root)),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )

            with patch.object(
                store,
                "complete_lifecycle_intent",
                side_effect=RuntimeError("database unavailable"),
            ):
                result = supervisor.start("coder")

            self.assertEqual(BotStatus.unknown, result.status)
            self.assertEqual(4321, result.pid)
            self.assertNotIn("disk full", result.message)
            self.assertIn("coder", supervisor._processes)
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.stopped, loaded.status)
            self.assertIsNone(loaded.pid)
            self.assertEqual("start", loaded.pending_action)

    def test_new_create_upsert_failure_removes_the_unregistered_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, self._fake_hermes(root), root / "hermes")
            request = BotCreateRequest(bot_id="coder", template_id="coding-bot")
            template = TemplateStore().get("coding-bot")
            profile_path = root / "hermes" / "profiles" / "coder"

            with (
                patch.object(
                    store,
                    "upsert_bot_with_event",
                    side_effect=RuntimeError("database unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.create_bot(request, template)

            self.assertIsNone(store.get_bot("coder"))
            self.assertFalse(profile_path.exists())
            self.assertEqual([], list(profile_path.parent.iterdir()))

    def test_replacement_upsert_failure_restores_exact_database_and_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root)
            sentinel = profile_path / "SOUL.md"
            sentinel.write_text("original profile\n", encoding="utf-8")
            marker = profile_path / "logs" / "zeus-gateway.pid.json"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text('{"stale": true}\n', encoding="utf-8")
            before_inode = profile_path.stat().st_ino
            before_files = {
                path.relative_to(profile_path): path.read_bytes()
                for path in profile_path.rglob("*")
                if path.is_file()
            }
            before_record = store.get_bot("coder")
            self.assertIsNotNone(before_record)
            supervisor = Supervisor(store, self._fake_hermes(root), root / "hermes")
            request = BotCreateRequest(
                bot_id="coder",
                template_id="coding-bot",
                display_name="Replacement",
            )
            template = replace(
                TemplateStore().get("coding-bot"),
                soul="replacement profile",
            )

            with (
                patch.object(
                    store,
                    "upsert_bot_with_event",
                    side_effect=RuntimeError("database unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.create_bot(request, template, replace_existing=True)

            after_files = {
                path.relative_to(profile_path): path.read_bytes()
                for path in profile_path.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before_inode, profile_path.stat().st_ino)
            self.assertEqual(before_files, after_files)
            self.assertEqual(before_record, store.get_bot("coder"))
            self.assertEqual(
                ["coder"],
                sorted(path.name for path in profile_path.parent.iterdir()),
            )

    def test_archive_database_failure_restores_the_live_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root)
            sentinel = profile_path / "SOUL.md"
            sentinel.write_text("original profile\n", encoding="utf-8")
            supervisor = Supervisor(store, self._fake_hermes(root), root / "hermes")

            with (
                patch.object(
                    store,
                    "delete_bot_with_event",
                    side_effect=RuntimeError("database unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.archive_bot("coder")

            self.assertEqual("original profile\n", sentinel.read_text(encoding="utf-8"))
            self.assertIsNotNone(store.get_bot("coder"))
            archive_root = store.database_path.parent / "archive"
            self.assertEqual([], list(archive_root.iterdir()))

    def test_delete_database_failure_restores_the_tombstoned_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(root)
            sentinel = profile_path / "SOUL.md"
            sentinel.write_text("original profile\n", encoding="utf-8")
            supervisor = Supervisor(store, self._fake_hermes(root), root / "hermes")

            with (
                patch.object(
                    store,
                    "delete_bot_with_event",
                    side_effect=RuntimeError("database unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "database unavailable"),
            ):
                supervisor.delete_bot("coder", remove_profile=True)

            self.assertEqual("original profile\n", sentinel.read_text(encoding="utf-8"))
            self.assertIsNotNone(store.get_bot("coder"))
            self.assertEqual(
                ["coder"],
                sorted(path.name for path in profile_path.parent.iterdir()),
            )

    def test_permission_denied_liveness_is_unknown_and_preserves_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, profile_path = self._store_with_bot(
                root,
                status=BotStatus.running,
                pid=4321,
            )
            supervisor = Supervisor(store, self._fake_hermes(root), root / "hermes")
            marker_path = supervisor.pid_marker_path(str(profile_path))
            marker_path.parent.mkdir(parents=True, exist_ok=True)
            marker_path.write_text("{}\n", encoding="utf-8")

            with patch(
                "zeus.supervisor.os.kill",
                side_effect=PermissionError(errno.EPERM, "operation not permitted"),
            ):
                status = supervisor.status("coder")

            self.assertEqual(BotStatus.unknown, status.status)
            self.assertEqual(4321, status.pid)
            self.assertTrue(marker_path.exists())
            loaded = store.get_bot("coder")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(BotStatus.unknown, loaded.status)
            self.assertEqual(4321, loaded.pid)

    def test_sigterm_exit_race_is_treated_as_a_completed_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes(root)
            store, profile_path = self._store_with_bot(
                root,
                status=BotStatus.running,
                pid=4321,
            )

            def vanished(pid: int, sig: signal.Signals) -> None:
                raise ProcessLookupError(errno.ESRCH, "no such process")

            supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                kill_fn=vanished,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
            )
            self._write_schema_v3_marker(supervisor, profile_path, pid=4321)

            stopped = supervisor.stop("coder")

            self.assertEqual(BotStatus.stopped, stopped.status)
            self.assertIsNone(stopped.pid)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())

    def test_sigkill_exit_race_is_treated_as_a_completed_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hermes_bin = self._fake_hermes(root)
            store, profile_path = self._store_with_bot(
                root,
                status=BotStatus.running,
                pid=4321,
            )
            sent: list[signal.Signals] = []

            def race_on_kill(pid: int, sig: signal.Signals) -> None:
                sent.append(sig)
                if sig == signal.SIGKILL:
                    raise ProcessLookupError(errno.ESRCH, "no such process")

            supervisor = Supervisor(
                store,
                hermes_bin,
                root / "hermes",
                kill_fn=race_on_kill,
                pid_alive_fn=lambda pid: True,
                cmdline_reader=lambda pid: self._gateway_argv(hermes_bin),
                proc_start_fingerprint_reader=lambda pid: f"test-process-start:{pid}",
                stop_grace_seconds=0.01,
                kill_after_timeout=True,
            )
            supervisor._processes["coder"] = _AlwaysTimeoutPopen([], {}, None, None)
            self._write_schema_v3_marker(supervisor, profile_path, pid=4321)

            stopped = supervisor.stop("coder")

            self.assertEqual([signal.SIGTERM, signal.SIGKILL], sent)
            self.assertEqual(BotStatus.stopped, stopped.status)
            self.assertFalse(supervisor.pid_marker_path(str(profile_path)).exists())


if __name__ == "__main__":
    unittest.main()
