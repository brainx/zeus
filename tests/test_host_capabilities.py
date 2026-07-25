from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from tests.host_capabilities import copy_single_link_git, path_with_tool


class HostCapabilitiesTests(unittest.TestCase):
    def test_copy_single_link_git_creates_private_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            git = copy_single_link_git(Path(temporary))

            metadata = git.stat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(1, metadata.st_nlink)
            self.assertTrue(os.access(git, os.X_OK))
            self.assertEqual(git.parent, Path(path_with_tool(git).split(os.pathsep)[0]))
