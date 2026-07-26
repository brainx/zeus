from __future__ import annotations

import unittest
from pathlib import Path


class ProductionModuleSizeContractTests(unittest.TestCase):
    def test_top_level_production_modules_stay_below_size_ratchet(self) -> None:
        maximum_lines = 1_200
        oversized: dict[str, int] = {}
        for module in sorted(Path("zeus").glob("*.py")):
            line_count = len(module.read_text(encoding="utf-8").splitlines())
            if line_count > maximum_lines:
                oversized[str(module)] = line_count

        self.assertEqual(
            {},
            oversized,
            f"split production modules that exceed {maximum_lines} lines",
        )


if __name__ == "__main__":
    unittest.main()
