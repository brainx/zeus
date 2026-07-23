from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO

from zeus.private_io import nofollow_absolute_path, open_private_append

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
        self.lock_path = nofollow_absolute_path(lock_path)
        self.timeout_seconds = timeout_seconds
        self._handle: BinaryIO | None = None
        self._private_handle: contextlib.AbstractContextManager[BinaryIO] | None = None

    def __enter__(self) -> BotProcessLock:
        private_handle = open_private_append(self.lock_path)
        handle = private_handle.__enter__()
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self._lock(handle)
                self._handle = handle
                self._private_handle = private_handle
                return self
            except OSError as exc:
                if time.monotonic() >= deadline:
                    private_handle.__exit__(None, None, None)
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
            private_handle = self._private_handle
            self._handle = None
            self._private_handle = None
            if private_handle is not None:
                private_handle.__exit__(exc_type, exc, tb)

    def _lock(self, handle: BinaryIO) -> None:
        if os.name == "posix":
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_NBLCK, 1)

    def _unlock(self, handle: BinaryIO) -> None:
        if os.name == "posix":
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return
        handle.seek(0)
        with contextlib.suppress(OSError):
            _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)
