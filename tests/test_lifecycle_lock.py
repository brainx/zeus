from __future__ import annotations

import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from zeus.models import TemplateError
from zeus.process_lock import BotProcessLock, LockTimeoutError
from zeus.state import StateStore
from zeus.supervisor import Supervisor


class LifecycleLockTests(unittest.TestCase):
    def test_bot_process_lock_releases_after_context_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "locks" / "bots" / "coder.lock"

            with BotProcessLock(lock_path, timeout_seconds=0.2):
                self.assertTrue(lock_path.exists())

            with BotProcessLock(lock_path, timeout_seconds=0.2):
                self.assertTrue(lock_path.exists())

    def test_bot_process_lock_timeout_raises(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "locks" / "bots" / "coder.lock"

            def holder() -> None:
                with BotProcessLock(lock_path, timeout_seconds=0.2):
                    entered.set()
                    release.wait(timeout=5)

            thread = threading.Thread(target=holder)
            thread.start()
            self.assertTrue(entered.wait(timeout=2))
            start = time.monotonic()
            try:
                with (
                    self.assertRaises(LockTimeoutError),
                    BotProcessLock(lock_path, timeout_seconds=0.1),
                ):
                    pass
                self.assertGreaterEqual(time.monotonic() - start, 0.1)
            finally:
                release.set()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_bot_process_lock_rejects_symlink_leaf_and_keeps_private_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.touch()
            lock_path = root / "locks" / "bots" / "coder.lock"
            lock_path.parent.mkdir(parents=True)
            lock_path.symlink_to(target)

            with self.assertRaises(OSError), BotProcessLock(lock_path, timeout_seconds=0):
                pass

            lock_path.unlink()
            with BotProcessLock(lock_path, timeout_seconds=0):
                self.assertEqual(0o700, stat.S_IMODE(lock_path.parent.stat().st_mode))
                self.assertEqual(0o600, stat.S_IMODE(lock_path.stat().st_mode))

    def test_bot_process_lock_is_immediately_contended(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "locks" / "bots" / "coder.lock"
            with (
                BotProcessLock(lock_path, timeout_seconds=0.2),
                self.assertRaises(LockTimeoutError),
                BotProcessLock(lock_path, timeout_seconds=0),
            ):
                pass

    def test_bot_process_lock_rejects_leaf_replacement_after_acquisition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "locks" / "bots" / "coder.lock"
            original_lock = BotProcessLock._lock

            def replace_then_lock(lock: BotProcessLock, handle) -> None:
                replacement = lock._private_lock_path.with_name("replacement")
                lock._private_lock_path.replace(replacement)
                lock._private_lock_path.touch()
                lock._private_lock_path.chmod(0o600)
                original_lock(lock, handle)

            with (
                mock.patch.object(BotProcessLock, "_lock", replace_then_lock),
                self.assertRaises(OSError),
                BotProcessLock(lock_path, timeout_seconds=0),
            ):
                pass

    def test_bot_process_lock_closes_immediately_on_binding_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "locks" / "bots" / "coder.lock"
            handle_path = Path(tmp) / "opened"
            handle = handle_path.open("a+b")
            private_handle = mock.MagicMock()
            private_handle.__enter__.return_value = handle
            private_handle.__exit__.side_effect = lambda *_args: handle.close()
            started = time.monotonic()
            with (
                mock.patch(
                    "zeus.process_lock.open_private_append",
                    return_value=private_handle,
                ),
                mock.patch.object(BotProcessLock, "_lock"),
                mock.patch.object(
                    BotProcessLock,
                    "_validate_lock_binding",
                    side_effect=OSError("binding mismatch"),
                ),
                self.assertRaisesRegex(OSError, "binding mismatch"),
                BotProcessLock(lock_path, timeout_seconds=10),
            ):
                pass
            self.assertLess(time.monotonic() - started, 0.1)
            private_handle.__exit__.assert_called_once()
            self.assertTrue(handle.closed)

    def test_supervisor_rejects_invalid_bot_id_before_lock_path_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "zeus.db")
            store.init()
            supervisor = Supervisor(store, "hermes", root / "hermes")

            with self.assertRaisesRegex(TemplateError, "bot_id must match"):
                supervisor.status("../../bad")

            self.assertFalse((root / "locks" / "bots").exists())


if __name__ == "__main__":
    unittest.main()
