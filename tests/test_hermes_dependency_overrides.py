from __future__ import annotations

import unittest

from scripts.check_hermes_dependency_overrides import (
    EXPECTED_DEPENDENCY_OVERRIDES,
    DependencyConflict,
    DependencyValidationError,
    validate_conflicts,
)


class HermesDependencyOverrideTests(unittest.TestCase):
    def test_exact_dependency_overrides_are_accepted(self) -> None:
        validate_conflicts(EXPECTED_DEPENDENCY_OVERRIDES)

    def test_missing_dependency_override_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            DependencyValidationError,
            "missing expected dependency overrides",
        ):
            validate_conflicts(frozenset())

    def test_unexpected_dependency_conflict_fails_closed(self) -> None:
        unexpected = DependencyConflict(
            dependent="example",
            dependent_version="1.0",
            requirement="other-package>=2",
            installed_version="1.0",
        )

        with self.assertRaisesRegex(DependencyValidationError, "unexpected conflicts"):
            validate_conflicts(EXPECTED_DEPENDENCY_OVERRIDES | {unexpected})


if __name__ == "__main__":
    unittest.main()
