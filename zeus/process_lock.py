from __future__ import annotations

import contextlib
import os
import stat
import sys
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
        self.lock_path = lock_path
        self._private_lock_path = nofollow_absolute_path(lock_path)
        self.timeout_seconds = timeout_seconds
        self._handle: BinaryIO | None = None
        self._private_handle: contextlib.AbstractContextManager[BinaryIO] | None = None

    def __enter__(self) -> BotProcessLock:
        private_handle = open_private_append(self._private_lock_path)
        handle = private_handle.__enter__()
        deadline = time.monotonic() + self.timeout_seconds
        try:
            while True:
                try:
                    self._lock(handle)
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise LockTimeoutError(self.lock_path, self.timeout_seconds) from exc
                    time.sleep(0.05)
                else:
                    self._validate_lock_binding(handle)
                    self._handle = handle
                    self._private_handle = private_handle
                    return self
        except BaseException:
            private_handle.__exit__(*sys.exc_info())
            raise

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

    def _validate_lock_binding(self, handle: BinaryIO) -> None:
        opened = os.fstat(handle.fileno())
        current = os.lstat(self._private_lock_path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
            or opened.st_uid != os.geteuid()
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(current.st_mode) != 0o600
            or opened.st_nlink != 1
            or current.st_nlink != 1
        ):
            raise OSError("lock path binding changed while it was acquired")

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
