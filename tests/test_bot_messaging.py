from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from zeus.bot_messaging import BotMessaging, MessagingError
from zeus.hermes_runs_client import HermesRunsClientError
from zeus.message_store import MessageStoreError
from zeus.messaging_policy import MessagePolicyError, load_message_policy
from zeus.models import BotCreateRequest, BotRecord, BotStatus, DesiredState, HermesTemplate
from zeus.readiness import ReadinessProbe
from zeus.renderer import ProfileRenderer
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class BotMessagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.profile = self.root / "hermes" / "profiles" / "coder"
        self.profile.mkdir(parents=True)
        self.key = "fixture-private-api-server-key"
        self._write_environment()
        (self.profile / "config.yaml").write_text("model: test\n", encoding="utf-8")
        self.hermes = self.root / "bin" / "hermes"
        self.hermes.parent.mkdir()
        self.hermes.write_text("#!/bin/sh\n", encoding="utf-8")
        self.hermes.chmod(0o755)
        self.now = datetime.now(UTC)
        self.state = StateStore(self.root / "zeus.db")
        self.state.init()
        self.record = BotRecord(
            "coder",
            "coding-bot",
            "Coder",
            str(self.profile),
            status=BotStatus.running,
            pid=4321,
            desired_state=DesiredState.running,
            desired_revision=1,
            created_at=self.now - timedelta(days=1),
        )
        self.state.upsert_bot(self.record)
        self.supervisor = Supervisor(
            self.state,
            str(self.hermes),
            self.root / "hermes",
            pid_alive_fn=lambda _pid: True,
            cmdline_reader=lambda _pid: [str(self.hermes), "-p", "coder", "gateway", "run"],
            proc_start_fingerprint_reader=lambda pid: f"fixture-start:{pid}",
        )
        self.policy = SimpleNamespace(
            fingerprint="a" * 64,
            api_key=self.key,
            credential_fingerprint=hashlib.sha256(self.key.encode()).hexdigest(),
        )
        self.policy_loader = self.enterContext(patch("zeus.bot_messaging.load_message_policy"))
        self.policy_loader.return_value = self.policy
        self.marker_path = self.supervisor.pid_marker_path(str(self.profile))
        self.marker_path.parent.mkdir()
        # Build an ordinary launch fixture, then attach the explicitly validated
        # policy which the production launcher records for opted-in profiles.
        with patch("zeus.hermes_adapter.load_message_policy", return_value=self.policy):
            payload = self.supervisor.adapter.launcher_payload(
                "coder",
                operation_id="b" * 32,
                desired_revision=1,
                readiness_probe=ReadinessProbe("http://127.0.0.1:8642/health"),
            )
        self.marker = dict(payload["marker"])
        self.marker.update(
            pid=4321,
            started_at=self.now.timestamp(),
            proc_start_fingerprint="fixture-start:4321",
            messaging_policy_fingerprint=self.policy.fingerprint,
        )
        self._write_marker()
        self.messaging = BotMessaging(self.supervisor, clock=lambda: self.now)
        self.health = self.enterContext(patch("zeus.bot_messaging.probe_gateway_health"))
        self.health.return_value = ("ok", {"pid": 4321, "version": "0.21.0"})
        self.capabilities = self.enterContext(patch("zeus.bot_messaging.client.capabilities"))
        self.capabilities.return_value = {
            "features": {"runs_idempotency": {"retention_seconds": 86400}}
        }
        self.submit = self.enterContext(patch("zeus.bot_messaging.client.submit"))
        self.run_id = "run_" + "c" * 32
        self.submit.return_value = {"run_id": self.run_id, "status": "started", "replayed": False}
        self.remote_status = self.enterContext(patch("zeus.bot_messaging.client.status"))
        self.remote_status.return_value = {"run_id": self.run_id, "status": "running"}
        self.stop = self.enterContext(patch("zeus.bot_messaging.client.stop"))
        self.stop.return_value = {"run_id": self.run_id, "status": "stopping"}

    def _write_marker(self) -> None:
        self.marker_path.write_text(json.dumps(self.marker), encoding="utf-8")

    def _write_environment(self, *, enabled: bool = True) -> None:
        (self.profile / ".env").write_text(
            f"API_SERVER_KEY={self.key}\nZEUS_MESSAGES_ENABLED={int(enabled)}\n", encoding="utf-8"
        )

    def _unknown(self) -> dict[str, object]:
        self.submit.side_effect = HermesRunsClientError("timeout", uncertain=True)
        result = self.messaging.send("coder", "operator message", request_key="original-request")
        self.submit.side_effect = None
        self.assertEqual("unknown", result["dispatch_state"])
        return result

    def test_prepare_commits_before_post_without_holding_database_lock(self) -> None:
        def submit(url, api_key, text, upstream_key):
            with closing(sqlite3.connect(self.state.database_path, timeout=0.1)) as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT dispatch_state, upstream_key FROM message_receipts"
                ).fetchone()
                self.assertEqual(("prepared", upstream_key), row)
                conn.rollback()
            self.assertEqual("http://127.0.0.1:8642/health", url)
            self.assertEqual(self.key, api_key)
            self.assertEqual("operator message", text)
            return {"run_id": self.run_id, "status": "started", "replayed": False}

        self.submit.side_effect = submit
        result = self.messaging.send("coder", "operator message")
        self.assertEqual("accepted", result["dispatch_state"])
        self.assertEqual("running", result["run_status"])
        self.assertEqual(self.run_id, result["run_id"])

    def test_input_and_request_keys_are_validated_before_any_probe(self) -> None:
        for text in ("", " \n", "a" * 16001, "\ud800"):
            with self.subTest(text_length=len(text)), self.assertRaises(MessagingError):
                self.messaging.send("coder", text)
        for key in ("", "a b", "a\n", "x" * 256, "é"):
            with self.subTest(key_length=len(key)), self.assertRaises(MessagingError):
                self.messaging.send("coder", "hello", request_key=key)
        self.health.assert_not_called()
        self.submit.assert_not_called()
        self.assertEqual([], self.messaging.list()["items"])

    def test_largest_input_and_unicode_preserve_exact_content(self) -> None:
        text = "😀" * 16000
        self.messaging.send("coder", text)
        self.assertEqual(text, self.submit.call_args.args[2])

    def test_real_rendered_policy_is_required_and_bound_to_launch(self) -> None:
        template = HermesTemplate.from_dict(
            {
                "id": "message-bot",
                "name": "Message Bot",
                "description": "Explicit operator messages",
                "version": "0.1.0",
                "soul": "Handle the operator's explicit request.",
                "hermes": {
                    "model": {"provider": "openrouter", "default": "fixture-model"},
                    "required_env": [
                        "ZEUS_MESSAGES_ENABLED",
                        "API_SERVER_ENABLED",
                        "API_SERVER_PORT",
                        "API_SERVER_KEY",
                    ],
                    "agent": {"max_turns": 10},
                    "gateway": {"enabled": True, "api_server": {"max_concurrent_runs": 1}},
                },
            }
        )
        request = BotCreateRequest(
            "coder",
            "message-bot",
            env={
                "ZEUS_MESSAGES_ENABLED": "1",
                "API_SERVER_ENABLED": "1",
                "API_SERVER_PORT": "8642",
                "API_SERVER_KEY": self.key,
            },
        )
        rendered = ProfileRenderer(self.root / "hermes").preflight(request, template)
        for name, content in rendered.items():
            path = self.profile / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.policy_loader.side_effect = load_message_policy
        payload = self.supervisor.adapter.launcher_payload(
            "coder",
            operation_id="b" * 32,
            desired_revision=1,
            readiness_probe=ReadinessProbe("http://127.0.0.1:8642/health"),
        )
        self.marker.update(payload["marker"])
        self._write_marker()
        result = self.messaging.send("coder", "hello")
        self.assertEqual("accepted", result["dispatch_state"])
        (self.profile / "SOUL.md").write_text("Changed instructions", encoding="utf-8")
        with self.assertRaisesRegex(MessagingError, "policy_restart_required"):
            self.messaging.send("coder", "new request")
        self.submit.assert_called_once()

    def test_opt_in_and_launch_policy_are_required_before_http(self) -> None:
        self.policy_loader.side_effect = MessagePolicyError("messages_disabled")
        with self.assertRaisesRegex(MessagingError, "messages_disabled"):
            self.messaging.send("coder", "hello")
        self.policy_loader.side_effect = None
        for fingerprint in (None, "d" * 64):
            with self.subTest(fingerprint=fingerprint):
                if fingerprint is None:
                    self.marker.pop("messaging_policy_fingerprint", None)
                else:
                    self.marker["messaging_policy_fingerprint"] = fingerprint
                self._write_marker()
                with self.assertRaisesRegex(MessagingError, "policy_restart_required"):
                    self.messaging.send("coder", "hello")
        self.health.assert_not_called()
        self.submit.assert_not_called()

    def test_pending_and_untrusted_processes_never_submit(self) -> None:
        self.state.upsert_bot(
            replace(
                self.record,
                pending_operation_id="d" * 32,
                pending_action="restart",
                pending_since=self.now,
            )
        )
        with self.assertRaisesRegex(MessagingError, "operation_pending"):
            self.messaging.send("coder", "hello")
        self.state.upsert_bot(self.record)
        self.supervisor.cmdline_reader = lambda _pid: ["unrelated-process"]
        with self.assertRaisesRegex(MessagingError, "process_unverified"):
            self.messaging.send("coder", "hello")
        self.submit.assert_not_called()

    def test_health_pid_version_and_ok_are_required(self) -> None:
        for reason, payload in (
            ("ok", {"pid": 1, "version": "0.21.0"}),
            ("ok", {"pid": 4321, "version": "0.20.0"}),
            ("degraded", {"pid": 4321, "version": "0.21.0"}),
            ("timeout", None),
        ):
            self.health.return_value = reason, payload
            with self.assertRaisesRegex(MessagingError, "health_unavailable"):
                self.messaging.send("coder", "hello")
        self.submit.assert_not_called()

    def test_capabilities_failure_and_short_retention_leave_no_receipt(self) -> None:
        self.capabilities.side_effect = HermesRunsClientError(
            "unsupported_runtime", uncertain=False
        )
        with self.assertRaises(HermesRunsClientError):
            self.messaging.send("coder", "hello")
        self.capabilities.side_effect = None
        for retention in (60, 0, True, float("inf")):
            self.capabilities.return_value["features"]["runs_idempotency"]["retention_seconds"] = (
                retention
            )
            with self.assertRaisesRegex(MessagingError, "idempotency_unavailable"):
                self.messaging.send("coder", "hello")
        self.assertEqual([], self.messaging.list()["items"])
        self.submit.assert_not_called()

    def test_accepted_request_key_repeat_never_posts_again_and_conflicts_fail(self) -> None:
        result = self.messaging.send("coder", "first message", request_key="request-key")
        duplicate = self.messaging.send("coder", "first message", request_key="request-key")
        self.assertEqual(result, duplicate)
        with self.assertRaisesRegex(MessageStoreError, "request_conflict"):
            self.messaging.send("coder", "different message", request_key="request-key")
        self.submit.assert_called_once()

    def test_unknown_blocks_new_send_and_identical_retry_reuses_stable_key(self) -> None:
        result = self._unknown()
        original_key = self.submit.call_args.args[3]
        with self.assertRaisesRegex(MessageStoreError, "bot_busy"):
            self.messaging.send("coder", "another message")
        with self.assertRaisesRegex(MessagingError, "request_conflict"):
            self.messaging.retry(result["message_id"], "operator message ")
        self.now += timedelta(seconds=31)
        self.submit.return_value = {"run_id": self.run_id, "status": "completed", "replayed": True}
        retried = self.messaging.retry(result["message_id"], "operator message")
        self.assertEqual("accepted", retried["dispatch_state"])
        self.assertEqual("completed", retried["run_status"])
        self.assertEqual(original_key, self.submit.call_args.args[3])
        self.messaging.retry(result["message_id"], "operator message")
        self.assertEqual(2, self.submit.call_count)

    def test_retry_rejection_cannot_disprove_original_uncertain_send(self) -> None:
        result = self._unknown()
        self.now += timedelta(seconds=31)
        self.submit.side_effect = HermesRunsClientError("rate_limited", uncertain=False)
        retried = self.messaging.retry(result["message_id"], "operator message")
        self.assertEqual("unknown", retried["dispatch_state"])
        self.assertEqual("rate_limited", retried["error_code"])

    def test_first_attempt_definite_rejection_is_not_reported_as_accepted(self) -> None:
        self.submit.side_effect = HermesRunsClientError("rate_limited", uncertain=False)
        result = self.messaging.send("coder", "hello")
        self.assertEqual("rejected", result["dispatch_state"])
        self.assertIsNone(result["run_id"])

    def test_interrupt_keeps_durable_unknown_receipt(self) -> None:
        self.submit.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.messaging.send("coder", "hello")
        receipt = self.messaging.list()["items"][0]
        self.assertEqual("unknown", receipt["dispatch_state"])
        self.assertEqual("interrupted", receipt["error_code"])

    def test_reservation_wait_cannot_dispatch_after_policy_or_generation_changes(self) -> None:
        prepare = self.messaging.store.prepare

        def race(**kwargs):
            result = prepare(**kwargs)
            self.marker["operation_id"] = "e" * 32
            self._write_marker()
            return result

        with patch.object(self.messaging.store, "prepare", side_effect=race):
            result = self.messaging.send("coder", "hello")
        self.assertEqual("unknown", result["dispatch_state"])
        self.assertEqual("runtime_changed", result["error_code"])
        self.submit.assert_not_called()

    def test_retry_claim_wait_cannot_dispatch_to_changed_generation(self) -> None:
        result = self._unknown()
        self.now += timedelta(seconds=31)
        claim = self.messaging.store.claim_retry

        def race(*args, **kwargs):
            receipt = claim(*args, **kwargs)
            self.marker["operation_id"] = "e" * 32
            self._write_marker()
            return receipt

        with patch.object(self.messaging.store, "claim_retry", side_effect=race):
            result = self.messaging.retry(result["message_id"], "operator message")
        self.assertEqual("unknown", result["dispatch_state"])
        self.assertEqual("runtime_changed", result["error_code"])
        self.assertEqual(1, self.submit.call_count)

    def test_suspended_reservation_does_not_dispatch_past_lease_or_retry_window(self) -> None:
        for elapsed, error in ((29, "attempt_expired"), (3601, "retry_expired")):
            with self.subTest(elapsed=elapsed):
                prepare = self.messaging.store.prepare

                def paused(*, pause=elapsed, reserve=prepare, **kwargs):
                    result = reserve(**kwargs)
                    self.now += timedelta(seconds=pause)
                    return result

                with (
                    patch.object(self.messaging.store, "prepare", side_effect=paused),
                    self.assertRaisesRegex(MessagingError, error),
                ):
                    self.messaging.send("coder", "hello")
                self.submit.assert_not_called()
                # Move to another disposable database for the next case while
                # preserving the unresolved receipt in the first database.
                self.state = StateStore(self.root / f"next-{elapsed}.db")
                self.state.init()
                self.state.upsert_bot(self.record)
                self.supervisor.store = self.state
                self.messaging = BotMessaging(self.supervisor, clock=lambda: self.now)

    def test_suspended_retry_claim_does_not_dispatch_after_lease(self) -> None:
        result = self._unknown()
        self.now += timedelta(seconds=31)
        claim = self.messaging.store.claim_retry

        def paused(*args, **kwargs):
            receipt = claim(*args, **kwargs)
            self.now += timedelta(seconds=31)
            return receipt

        with (
            patch.object(self.messaging.store, "claim_retry", side_effect=paused),
            self.assertRaisesRegex(MessagingError, "attempt_expired"),
        ):
            self.messaging.retry(result["message_id"], "operator message")
        self.assertEqual(1, self.submit.call_count)

    def test_superseded_attempt_never_dispatches_or_overwrites_newer_receipt(self) -> None:
        prepare = self.messaging.store.prepare

        def superseded(**kwargs):
            receipt, created = prepare(**kwargs)
            self.messaging.store.finish_attempt(
                receipt.message_id,
                expected_version=receipt.version,
                dispatch_state="accepted",
                run_id=self.run_id,
                run_status="running",
                now=self.now,
            )
            return receipt, created

        with (
            patch.object(self.messaging.store, "prepare", side_effect=superseded),
            self.assertRaisesRegex(MessagingError, "receipt_changed"),
        ):
            self.messaging.send("coder", "hello")
        self.submit.assert_not_called()
        self.assertEqual("accepted", self.messaging.list()["items"][0]["dispatch_state"])

    def test_cancel_intent_wait_cannot_send_to_changed_generation(self) -> None:
        result = self.messaging.send("coder", "hello")
        update = self.messaging.store.update_run

        def race(*args, **kwargs):
            receipt = update(*args, **kwargs)
            self.marker["operation_id"] = "e" * 32
            self._write_marker()
            return receipt

        with (
            patch.object(self.messaging.store, "update_run", side_effect=race),
            self.assertRaisesRegex(MessagingError, "runtime_changed"),
        ):
            self.messaging.cancel(result["message_id"])
        self.stop.assert_not_called()

    def test_generation_and_profile_races_discard_acknowledgement(self) -> None:
        for changed in ("generation", "credentials", "policy", "record"):
            with self.subTest(changed=changed):
                original_marker = dict(self.marker)

                def submit(*_args, changed=changed):
                    if changed == "generation":
                        self.marker["operation_id"] = "e" * 32
                        self._write_marker()
                    elif changed == "credentials":
                        self.policy_loader.return_value = SimpleNamespace(
                            **{**vars(self.policy), "credential_fingerprint": "e" * 64}
                        )
                    elif changed == "policy":
                        self.policy_loader.return_value = SimpleNamespace(
                            **{**vars(self.policy), "fingerprint": "e" * 64}
                        )
                    else:
                        self.state.upsert_bot(replace(self.record, desired_revision=2))
                    return {"run_id": self.run_id, "status": "started", "replayed": False}

                self.submit.side_effect = submit
                result = self.messaging.send("coder", "hello")
                self.assertEqual("unknown", result["dispatch_state"])
                self.assertEqual("runtime_changed", result["error_code"])
                self.assertIsNone(result["run_id"])
                # A new profile incarnation is independent of the unresolved
                # receipt; old records survive without following a reused ID.
                self.now += timedelta(seconds=1)
                self.record = replace(self.record, created_at=self.now)
                self.state.upsert_bot(self.record)
                with closing(sqlite3.connect(self.state.database_path)) as conn:
                    conn.execute(
                        "UPDATE bots SET created_at = ? WHERE bot_id = 'coder'",
                        (self.now.isoformat(),),
                    )
                    conn.commit()
                self.marker = original_marker
                self._write_marker()
                self.policy_loader.return_value = self.policy

    def test_retry_rejects_changed_namespace_before_network(self) -> None:
        result = self._unknown()
        self.now += timedelta(seconds=31)
        self.health.reset_mock()
        self.policy_loader.return_value = SimpleNamespace(
            **{**vars(self.policy), "credential_fingerprint": "e" * 64}
        )
        with self.assertRaisesRegex(MessagingError, "target_changed"):
            self.messaging.retry(result["message_id"], "operator message")
        self.health.assert_not_called()
        self.assertEqual(1, self.submit.call_count)

    def test_retry_expiry_shortened_retention_and_clock_rollback(self) -> None:
        result = self._unknown()
        self.now -= timedelta(seconds=1)
        with self.assertRaisesRegex(MessagingError, "clock_rollback"):
            self.messaging.retry(result["message_id"], "operator message")
        self.now += timedelta(seconds=121)
        self.capabilities.return_value["features"]["runs_idempotency"]["retention_seconds"] = 120
        with self.assertRaisesRegex(MessagingError, "retry_expired"):
            self.messaging.retry(result["message_id"], "operator message")
        self.capabilities.return_value["features"]["runs_idempotency"]["retention_seconds"] = 86400
        self.now += timedelta(hours=1)
        with self.assertRaisesRegex(MessagingError, "retry_expired"):
            self.messaging.retry(result["message_id"], "operator message")
        self.assertEqual(1, self.submit.call_count)

    def test_status_and_cooperative_cancel_work_after_disabling_sends(self) -> None:
        result = self.messaging.send("coder", "hello")
        self._write_environment(enabled=False)
        self.policy_loader.side_effect = MessagePolicyError("messages_disabled")
        self.health.return_value = "degraded", {"pid": 4321, "version": "0.21.0"}
        self.remote_status.return_value = {
            "run_id": self.run_id,
            "status": "running",
            "output": "explicitly requested output",
        }
        status = self.messaging.status(result["message_id"])
        self.assertEqual("explicitly requested output", status["run"]["output"])
        self.assertTrue(self.remote_status.call_args.kwargs["include_output"])
        self.now += timedelta(seconds=1)
        cancelled = self.messaging.cancel(result["message_id"])
        self.assertEqual("stopping", cancelled["run_status"])
        self.assertIsNotNone(cancelled["cancel_requested_at"])
        self.assertEqual(self.run_id, self.stop.call_args.args[2])

    def test_status_rejects_recreated_bot_and_rotated_key_without_http(self) -> None:
        result = self.messaging.send("coder", "hello")
        self.health.reset_mock()
        with closing(sqlite3.connect(self.state.database_path)) as conn:
            conn.execute(
                "UPDATE bots SET created_at = ? WHERE bot_id = 'coder'", (self.now.isoformat(),)
            )
            conn.commit()
        with self.assertRaisesRegex(MessagingError, "target_changed"):
            self.messaging.status(result["message_id"])
        with closing(sqlite3.connect(self.state.database_path)) as conn:
            conn.execute(
                "UPDATE bots SET created_at = ? WHERE bot_id = 'coder'",
                (self.record.created_at.isoformat(),),
            )
            conn.commit()
        self.key = "a-different-private-api-key"
        self._write_environment()
        with self.assertRaisesRegex(MessagingError, "target_changed"):
            self.messaging.cancel(result["message_id"])
        self.health.assert_not_called()
        self.remote_status.assert_not_called()
        self.stop.assert_not_called()

    def test_status_and_cancel_races_do_not_persist_remote_success(self) -> None:
        result = self.messaging.send("coder", "hello")
        original = dict(self.marker)

        def race(*_args, **_kwargs):
            self.marker["operation_id"] = "e" * 32
            self._write_marker()
            return {"run_id": self.run_id, "status": "completed", "output": "discard me"}

        for action, mock in (
            (self.messaging.status, self.remote_status),
            (self.messaging.cancel, self.stop),
        ):
            mock.side_effect = race
            with self.assertRaisesRegex(MessagingError, "runtime_changed"):
                action(result["message_id"])
            receipt = self.messaging.store.get(result["message_id"])
            self.assertEqual("running", receipt.run_status)
            self.marker = dict(original)
            self._write_marker()

    def test_unknown_status_is_local_and_cancel_cannot_guess_run(self) -> None:
        result = self._unknown()
        self.health.reset_mock()
        self.assertEqual(result, self.messaging.status(result["message_id"]))
        with self.assertRaisesRegex(MessagingError, "run_unacknowledged"):
            self.messaging.cancel(result["message_id"])
        self.health.assert_not_called()
        self.remote_status.assert_not_called()
        self.stop.assert_not_called()

    def test_receipts_never_persist_input_request_key_credential_or_output(self) -> None:
        result = self.messaging.send(
            "coder", "private input body", request_key="private-request-key"
        )
        self.remote_status.return_value = {
            "run_id": self.run_id,
            "status": "completed",
            "output": "private output body",
        }
        self.messaging.status(result["message_id"])
        serialized = json.dumps(self.messaging.list())
        with closing(sqlite3.connect(self.state.database_path)) as conn:
            dump = "\n".join(conn.iterdump())
        for secret in (
            "private input body",
            "private-request-key",
            self.key,
            "private output body",
        ):
            self.assertNotIn(secret, dump)
            self.assertNotIn(secret, serialized)
        for hidden in ("upstream_key", "request_hash", "endpoint", "credential_fingerprint"):
            self.assertNotIn(hidden, serialized)


if __name__ == "__main__":
    unittest.main()
