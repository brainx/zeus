from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CheckVersionTagTests(unittest.TestCase):
    def _run_checker(self, changelog: str) -> subprocess.CompletedProcess[str]:
        checker = Path("scripts/check_version_tag.py").resolve()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "zeus").mkdir()
            (root / "zeus" / "__init__.py").write_text(
                '__version__ = "0.4.0"\n',
                encoding="utf-8",
            )
            (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(checker), "v0.4.0", "--require-changelog"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_accepts_exact_package_version_heading(self) -> None:
        completed = self._run_checker("# Changelog\n\n## 0.4.0\n\n- Stable release.\n")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)

    def test_rejects_development_heading_for_stable_package_version(self) -> None:
        completed = self._run_checker("# Changelog\n\n## 0.4.0.dev0\n\n- Development.\n")

        self.assertEqual(1, completed.returncode)
        self.assertEqual(
            "CHANGELOG.md is missing a section for 0.4.0\n",
            completed.stderr,
        )

    def test_rejects_release_candidate_heading_for_stable_package_version(self) -> None:
        completed = self._run_checker("# Changelog\n\n## 0.4.0-rc1\n\n- Candidate.\n")

        self.assertEqual(1, completed.returncode)
        self.assertEqual(
            "CHANGELOG.md is missing a section for 0.4.0\n",
            completed.stderr,
        )


if __name__ == "__main__":
    unittest.main()
