from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from tests.host_capabilities import (
    child_process_identity_available,
    copy_single_link_git,
    path_with_tool,
)


class HostCapabilitiesTests(unittest.TestCase):
    def test_child_identity_requires_command_and_start_fingerprint(self) -> None:
        self.assertFalse(
            child_process_identity_available(
                cmdline_reader=lambda _pid: ["/usr/bin/python"],
                fingerprint_reader=lambda _pid: None,
            )
        )
        self.assertFalse(
            child_process_identity_available(
                cmdline_reader=lambda _pid: None,
                fingerprint_reader=lambda _pid: "linux:/proc-starttime:1",
            )
        )
        self.assertTrue(
            child_process_identity_available(
                cmdline_reader=lambda _pid: ["/usr/bin/python"],
                fingerprint_reader=lambda _pid: "linux:/proc-starttime:1",
            )
        )

    def test_copy_single_link_git_creates_private_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            git = copy_single_link_git(Path(temporary))

            metadata = git.stat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(1, metadata.st_nlink)
            self.assertTrue(os.access(git, os.X_OK))
            self.assertEqual(git.parent, Path(path_with_tool(git).split(os.pathsep)[0]))
