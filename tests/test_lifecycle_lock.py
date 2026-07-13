from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

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
