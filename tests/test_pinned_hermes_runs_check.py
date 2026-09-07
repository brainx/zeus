from __future__ import annotations

import importlib.metadata
import io
import os
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.verify_pinned_hermes_runs import _block_external_connections, main


class PinnedHermesRunsCheckTests(unittest.TestCase):
    def test_missing_or_wrong_pinned_backend_fails_without_skipping(self) -> None:
        for version in (None, "0.20.0", "0.21.1"):
            with (
                self.subTest(version=version),
                patch(
                    "importlib.metadata.version",
                    return_value=version,
                    side_effect=importlib.metadata.PackageNotFoundError
                    if version is None
                    else None,
                ),
                patch("subprocess.run") as run,
                redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(2, main())
                self.assertIn("cannot skip", stderr.getvalue())
                run.assert_not_called()

    def test_workers_are_separate_sanitized_processes_and_scratch_is_cleaned(self) -> None:
        with (
            patch("importlib.metadata.version", return_value="0.21.0"),
            patch("sys.argv", ["verify_pinned_hermes_runs.py"]),
            patch.dict(os.environ, {"OPENAI_API_KEY": "must-not-be-inherited"}),
            patch("subprocess.run", return_value=SimpleNamespace(returncode=0)) as run,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(0, main())
        self.assertEqual(2, run.call_count)
        self.assertEqual("exercise", run.call_args_list[0].args[0][-1])
        self.assertEqual("restart", run.call_args_list[1].args[0][-1])
        for call in run.call_args_list:
            self.assertNotIn("OPENAI_API_KEY", call.kwargs["env"])
            self.assertEqual("1", call.kwargs["env"]["HERMES_SAFE_MODE"])
            self.assertEqual(60, call.kwargs["timeout"])
            self.assertFalse(Path(call.kwargs["cwd"]).exists())

    def test_worker_failure_is_not_reported_as_a_success(self) -> None:
        with (
            patch("importlib.metadata.version", return_value="0.21.0"),
            patch("sys.argv", ["verify_pinned_hermes_runs.py"]),
            patch("subprocess.run", return_value=SimpleNamespace(returncode=7)) as run,
        ):
            self.assertEqual(7, main())
        run.assert_called_once()

    def test_connection_guard_rejects_external_addresses_before_socket_calls(self) -> None:
        with (
            patch.object(socket.socket, "connect", return_value=None) as connect,
            patch.object(socket.socket, "connect_ex", return_value=0) as connect_ex,
        ):
            _block_external_connections()
            with socket.socket() as sock:
                for address in (("203.0.113.1", 443), ("example.invalid", 443), "/tmp/socket"):
                    for method in (sock.connect, sock.connect_ex):
                        with self.assertRaisesRegex(RuntimeError, "non-loopback"):
                            method(address)
                connect.assert_not_called()
                connect_ex.assert_not_called()
                sock.connect(("127.0.0.1", 4312))
                self.assertEqual(0, sock.connect_ex(("127.0.0.1", 4312)))
                connect.assert_called_once()
                connect_ex.assert_called_once()


if __name__ == "__main__":
    unittest.main()
