from __future__ import annotations

import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

from zeus.audit_process import (
    AuditProcessError,
    ProcessGroupState,
    _owned_group_state,
    observe_process_exit,
    stop_process_group,
    wait_process_exit,
)


class AuditProcessTests(unittest.TestCase):
    def test_exit_is_observed_without_reaping_until_group_teardown(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        returncode = wait_process_exit(process, deadline=time.monotonic() + 2)

        self.assertEqual(0, returncode)
        self.assertIsNone(process.returncode)
        self.assertTrue(stop_process_group(process))
        self.assertEqual(0, process.returncode)

    def test_reaped_or_rebound_leader_is_never_signalled(self) -> None:
        reaped = mock.Mock(pid=424242, returncode=0)
        with mock.patch("zeus.audit_process.os.killpg") as kill_group:
            self.assertFalse(stop_process_group(reaped))
        kill_group.assert_not_called()

        process = mock.Mock(pid=424242, returncode=None)
        with (
            mock.patch("zeus.audit_process.observe_process_exit", return_value=None),
            mock.patch("zeus.audit_process.os.getpgid", return_value=424243),
            mock.patch("zeus.audit_process.os.killpg") as kill_group,
        ):
            self.assertFalse(stop_process_group(process))
        kill_group.assert_not_called()

    def test_signal_is_sent_only_while_original_leader_pins_the_group(self) -> None:
        process = mock.Mock(pid=424242, returncode=None)

        def reap(*, timeout):
            process.returncode = -signal.SIGKILL
            return process.returncode

        process.wait.side_effect = reap
        observations = 0

        def observe(_process):
            nonlocal observations
            observations += 1
            return None if observations == 1 else -signal.SIGKILL

        with (
            mock.patch(
                "zeus.audit_process.observe_process_exit",
                side_effect=observe,
            ),
            mock.patch(
                "zeus.audit_process._owned_group_state",
                return_value=ProcessGroupState.present,
            ),
            mock.patch(
                "zeus.audit_process.os.killpg",
                side_effect=(None, None, ProcessLookupError),
            ) as kill_group,
        ):
            self.assertTrue(stop_process_group(process, term_seconds=0, kill_seconds=0))
        self.assertEqual(
            [
                mock.call(process.pid, signal.SIGTERM),
                mock.call(process.pid, signal.SIGKILL),
                mock.call(process.pid, 0),
            ],
            kill_group.call_args_list,
        )

    def test_live_leader_exiting_after_sigterm_is_reaped(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        self.assertTrue(stop_process_group(process, term_seconds=1, kill_seconds=1))
        self.assertIsNotNone(process.returncode)
        self.assertEqual(process.returncode, process.wait(timeout=0))

    def test_terminal_leader_is_reaped_when_group_signal_returns_eperm(self) -> None:
        process = mock.Mock(pid=424242, returncode=None)

        def reap(*, timeout):
            process.returncode = -signal.SIGTERM
            return process.returncode

        process.wait.side_effect = reap
        observations = 0

        def observe(_process):
            nonlocal observations
            observations += 1
            return None if observations == 1 else -signal.SIGTERM

        with (
            mock.patch(
                "zeus.audit_process.observe_process_exit",
                side_effect=observe,
            ),
            mock.patch(
                "zeus.audit_process._owned_group_state",
                return_value=ProcessGroupState.present,
            ),
            mock.patch(
                "zeus.audit_process.os.killpg",
                side_effect=(
                    None,
                    PermissionError(1, "operation not permitted"),
                    ProcessLookupError,
                ),
            ),
        ):
            self.assertTrue(stop_process_group(process, term_seconds=0, kill_seconds=0))
        self.assertEqual(-signal.SIGTERM, process.returncode)

    def test_observe_rejects_an_already_reaped_process(self) -> None:
        with self.assertRaises(AuditProcessError):
            observe_process_exit(mock.Mock(pid=1, returncode=0))

    def test_missing_group_with_live_leader_is_unknown_until_exit_is_observed(self) -> None:
        process = mock.Mock(pid=424242, returncode=None)
        with (
            mock.patch(
                "zeus.audit_process.os.getpgid",
                side_effect=ProcessLookupError,
            ),
            mock.patch(
                "zeus.audit_process.observe_process_exit",
                return_value=None,
            ),
            mock.patch("zeus.audit_process.os.killpg") as kill_group,
        ):
            self.assertIs(ProcessGroupState.unknown, _owned_group_state(process))
        kill_group.assert_not_called()


if __name__ == "__main__":
    unittest.main()
