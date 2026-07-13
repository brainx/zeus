from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path
from types import TracebackType
from typing import Any, TextIO

if os.name == "posix":
    import fcntl

    _msvcrt: Any = None
else:
    import msvcrt as _msvcrt


class LockTimeoutError(TimeoutError):
    def __init__(self, lock_path: Path, timeout_seconds: float) -> None:
        self.lock_path = lock_path
        self.timeout_seconds = timeout_seconds
        super().__init__(f"timed out waiting for lock: {lock_path}")


class BotProcessLock:
    def __init__(self, lock_path: Path, timeout_seconds: float = 30.0) -> None:
        self.lock_path = lock_path
        self.timeout_seconds = timeout_seconds
        self._handle: TextIO | None = None

    def __enter__(self) -> BotProcessLock:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            self.lock_path.parent.chmod(0o700)
        handle = self.lock_path.open("a+", encoding="utf-8")
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self._lock(handle)
                self._handle = handle
                return self
            except OSError as exc:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise LockTimeoutError(self.lock_path, self.timeout_seconds) from exc
                time.sleep(0.05)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._handle is None:
            return
        try:
            self._unlock(self._handle)
        finally:
            self._handle.close()
            self._handle = None

    def _lock(self, handle: TextIO) -> None:
        if os.name == "posix":
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_NBLCK, 1)

    def _unlock(self, handle: TextIO) -> None:
        if os.name == "posix":
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return
        handle.seek(0)
        with contextlib.suppress(OSError):
            _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)
