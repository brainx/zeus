from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import time
import unittest
from collections.abc import Callable
from pathlib import Path

from zeus.process_identity import read_process_cmdline, read_process_start_fingerprint


def child_process_identity_available(
    *,
    cmdline_reader: Callable[[int], list[str] | None] = read_process_cmdline,
    fingerprint_reader: Callable[[int], str | None] = read_process_start_fingerprint,
) -> bool:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            command = cmdline_reader(process.pid)
            fingerprint = fingerprint_reader(process.pid)
            if command and fingerprint:
                return True
            if process.poll() is not None:
                return False
            time.sleep(0.02)
        return False
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)


def copy_single_link_git(root: Path) -> Path:
    source = shutil.which("git")
    if source is None:
        raise unittest.SkipTest("git is not installed")
    source_path = Path(source).resolve(strict=True)
    tool_dir = root / "host-tools"
    tool_dir.mkdir(mode=0o700)
    target = tool_dir / "git"
    shutil.copyfile(source_path, target)
    target.chmod(0o700)
    metadata = target.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("failed to create a single-link Git executable")
    return target


def path_with_tool(tool: Path) -> str:
    return os.pathsep.join((str(tool.parent), os.environ.get("PATH", os.defpath)))
