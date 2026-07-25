from __future__ import annotations

import os
import shutil
import stat
import unittest
from pathlib import Path


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
