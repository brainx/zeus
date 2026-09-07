from __future__ import annotations

import unittest
from datetime import timedelta
from unittest.mock import patch

from tests import test_bot_messaging as fixtures
from zeus.bot_messaging import MessagingError
from zeus.hermes_runs_client import HermesRunsClientError
from zeus.message_store import MessageStoreError


class MessageReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.BotMessagingTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.workflow = self.fixture.messaging

    def _send(self):
        return self.workflow.send("coder", "operator message", request_key="original-request")

    def _release(self, message_id):
        return self.workflow.release(message_id, acknowledge_unknown_outcome=True)

    def test_inaccessible_acknowledged_run_can_be_released_without_claiming_completion(self):
        fixture = self.fixture
        for code in ("not_found", "response_too_large", "timeout"):
            with self.subTest(code=code):
                receipt = self.workflow.send("coder", "operator message")
                message_id = receipt["message_id"]
                fixture.now += timedelta(hours=25)
                fixture.remote_status.side_effect = HermesRunsClientError(code)
                with self.assertRaises(HermesRunsClientError):
                    self.workflow.status(message_id)
                with self.assertRaisesRegex(MessageStoreError, "bot_busy"):
                    self.workflow.send("coder", "next job")
                before = self.workflow.store.get(message_id)
                fixture.submit.reset_mock()
                fixture.health.reset_mock()
                fixture.remote_status.reset_mock()
                released = self._release(message_id)
                after = self.workflow.store.get(message_id)
                self.assertEqual("accepted", released["dispatch_state"])
                self.assertEqual("running", released["run_status"])
                self.assertEqual(fixture.now.isoformat(), released["released_at"])
                self.assertEqual(before.last_checked_at, after.last_checked_at)
                self.assertEqual(before.upstream_key, after.upstream_key)
                self.assertEqual(before.run_id, after.run_id)
                fixture.submit.assert_not_called()
                fixture.health.assert_not_called()
                fixture.remote_status.assert_not_called()
                fixture.stop.assert_not_called()
        self.assertEqual("accepted", self.workflow.send("coder", "next job")["dispatch_state"])

    def test_release_requires_explicit_acknowledgement_and_an_acknowledged_run(self):
        receipt = self.fixture._unknown()
        for acknowledgement in (False, 1, "yes"):
            with self.assertRaisesRegex(MessagingError, "outcome_acknowledgement_required"):
                self.workflow.release(
                    receipt["message_id"], acknowledge_unknown_outcome=acknowledgement
                )
        with self.assertRaisesRegex(MessageStoreError, "run_unacknowledged"):
            self._release(receipt["message_id"])
        self.assertIsNone(self.workflow.store.get(receipt["message_id"]).released_at)
        with self.assertRaisesRegex(MessageStoreError, "bot_busy"):
            self.workflow.send("coder", "next job")

    def test_release_is_idempotent_and_preserves_request_key_and_input_tombstones(self):
        receipt = self._send()
        released = self._release(receipt["message_id"])
        self.fixture.now += timedelta(days=2)
        self.fixture.submit.reset_mock()
        self.assertEqual(released, self._release(receipt["message_id"]))
        self.assertEqual(released, self.workflow.retry(receipt["message_id"], "operator message"))
        self.assertEqual(released, self._send())
        self.fixture.submit.assert_not_called()
        with self.assertRaisesRegex(MessagingError, "request_conflict"):
            self.workflow.retry(receipt["message_id"], "changed input")

    def test_later_status_and_cancel_preserve_release_without_reactivating_blocker(self):
        receipt = self._send()
        released = self._release(receipt["message_id"])
        self.fixture.now += timedelta(seconds=1)
        observed = self.workflow.status(receipt["message_id"])
        self.assertEqual("running", observed["run_status"])
        self.assertEqual(released["released_at"], observed["released_at"])
        # A later observation of the released run must not restore the unique blocker.
        self.workflow.send("coder", "next job")
        self.fixture.now += timedelta(seconds=1)
        self.fixture.stop.return_value = {"run_id": self.fixture.run_id, "status": "cancelled"}
        cancelled = self.workflow.cancel(receipt["message_id"])
        self.assertEqual("cancelled", cancelled["run_status"])
        self.assertEqual(released["released_at"], cancelled["released_at"])
        self.assertEqual(self.fixture.now.isoformat(), cancelled["last_checked_at"])

    def test_release_cas_clock_checks_and_terminal_guard(self):
        receipt = self._send()
        stored = self.workflow.store.get(receipt["message_id"])
        self.fixture.now += timedelta(seconds=1)
        self.workflow.status(receipt["message_id"])
        with self.assertRaisesRegex(MessageStoreError, "receipt_changed"):
            self.workflow.store.release(
                stored.message_id, expected_version=stored.version, now=self.fixture.now
            )
        current = self.workflow.store.get(stored.message_id)
        with self.assertRaisesRegex(MessageStoreError, "clock_rollback"):
            self.workflow.store.release(
                current.message_id, expected_version=current.version, now=stored.created_at
            )
        self.fixture.remote_status.return_value = {
            "run_id": self.fixture.run_id,
            "status": "completed",
        }
        self.workflow.status(stored.message_id)
        with self.assertRaisesRegex(MessageStoreError, "run_already_terminal"):
            self._release(stored.message_id)

    def test_status_racing_release_cannot_overwrite_release(self):
        receipt = self._send()
        with patch.object(
            self.workflow.store,
            "update_run",
            wraps=self.workflow.store.update_run,
        ) as update:

            def response(*args, **kwargs):
                self._release(receipt["message_id"])
                return {"run_id": self.fixture.run_id, "status": "completed"}

            self.fixture.remote_status.side_effect = response
            with self.assertRaisesRegex(MessageStoreError, "receipt_changed"):
                self.workflow.status(receipt["message_id"])
            update.assert_called_once()
        self.assertIsNotNone(self.workflow.store.get(receipt["message_id"]).released_at)
        self.workflow.send("coder", "next job")
