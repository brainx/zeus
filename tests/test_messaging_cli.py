from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from zeus.bot_messaging import MessagingError
from zeus.cli import main
from zeus.message_store import MessageStoreError
from zeus.messaging_cli import _read_input


class MessagingCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.enterContext(
            patch.dict(os.environ, {"ZEUS_STATE_DIR": str(self.root / "state")}, clear=True)
        )
        self.enterContext(patch("zeus.cli._services", side_effect=AssertionError("initialization")))

    def cli(self, *args: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            result = main(["message", *args, "--json"])
        return result, json.loads(output.getvalue())

    def test_listing_missing_state_does_not_initialize(self) -> None:
        code, payload = self.cli("list")
        self.assertEqual(1, code)
        self.assertIn(payload["error"]["code"], {"not_ready", "state_unavailable"})
        self.assertFalse((self.root / "state").exists())

    def test_send_and_retry_read_exact_file_content(self) -> None:
        source = self.root / "message.txt"
        source.write_text("  operator text\n雪\n", encoding="utf-8")
        with patch("zeus.messaging_cli.BotMessaging") as workflow:
            workflow.return_value.send.return_value = {
                "dispatch_state": "accepted",
                "message_id": "a" * 32,
            }
            self.assertEqual(
                0, self.cli("send", "coder", "--file", str(source), "--request-key", "job1")[0]
            )
            workflow.return_value.send.assert_called_once_with(
                "coder", source.read_text(), request_key="job1"
            )
            workflow.return_value.retry.return_value = {"dispatch_state": "unknown"}
            self.assertEqual(1, self.cli("retry", "a" * 32, "--file", str(source))[0])
            workflow.return_value.retry.assert_called_once_with("a" * 32, source.read_text())

    def test_bounded_regular_utf8_input_and_explicit_stdin(self) -> None:
        source = self.root / "input"
        for data in (b"x" * 65537, b"\xff"):
            source.write_bytes(data)
            with self.assertRaises(MessagingError):
                _read_input(str(source))
        source.unlink()
        os.mkfifo(source)
        with self.assertRaises(MessagingError):
            _read_input(str(source))
        source.unlink()
        source.symlink_to(self.root / "absent")
        with self.assertRaises(MessagingError):
            _read_input(str(source))
        with patch("sys.stdin", io.TextIOWrapper(io.BytesIO(b"from stdin\n"))):
            self.assertEqual("from stdin\n", _read_input("-"))

    def test_list_cursor_and_safe_errors(self) -> None:
        with patch("zeus.messaging_cli.BotMessaging") as workflow:
            workflow.return_value.list.return_value = {"items": [], "next_before": None}
            self.assertEqual(
                0, self.cli("list", "--bot-id", "coder", "--limit", "5", "--before", "a" * 32)[0]
            )
            workflow.return_value.list.assert_called_once_with(
                bot_id="coder", limit=5, before="a" * 32
            )
            workflow.return_value.status.side_effect = MessageStoreError("bot_busy")
            code, payload = self.cli("status", "a" * 32)
            self.assertEqual(1, code)
            self.assertEqual("bot_busy", payload["error"]["code"])

    def test_invalid_input_returns_safe_json_without_dispatching(self) -> None:
        source = self.root / "private-input.txt"
        source.write_bytes(b"\xff")
        with patch("zeus.messaging_cli.BotMessaging") as workflow:
            code, payload = self.cli("send", "coder", "--file", str(source))
            self.assertEqual(1, code)
            self.assertEqual("invalid_input_file", payload["error"]["code"])
            self.assertNotIn(str(source), json.dumps(payload))
            workflow.return_value.send.assert_not_called()
        self.assertFalse((self.root / "state").exists())

    def test_cancel_and_output_escape_terminal_control_characters(self) -> None:
        with patch("zeus.messaging_cli.BotMessaging") as workflow:
            workflow.return_value.cancel.return_value = {
                "dispatch_state": "accepted",
                "run_status": "stopping",
            }
            self.assertEqual(0, self.cli("cancel", "a" * 32)[0])
            workflow.return_value.cancel.assert_called_once_with("a" * 32)
            workflow.return_value.status.return_value = {"run": {"output": "\x1b[2J"}}
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["message", "status", "a" * 32]))
            self.assertNotIn("\x1b", output.getvalue())


if __name__ == "__main__":
    unittest.main()
