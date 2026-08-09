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
        self.assertEqual(
            frozenset(
                {
                    DependencyConflict(
                        dependent="hermes-agent",
                        dependent_version="0.20.0",
                        requirement="cryptography==48.0.1",
                        installed_version="50.0.0",
                    ),
                    DependencyConflict(
                        dependent="hermes-agent",
                        dependent_version="0.20.0",
                        requirement="requests==2.33.0",
                        installed_version="2.34.2",
                    ),
                    DependencyConflict(
                        dependent="hermes-agent",
                        dependent_version="0.20.0",
                        requirement="rich==14.3.3",
                        installed_version="15.0.0",
                    ),
                }
            ),
            EXPECTED_DEPENDENCY_OVERRIDES,
        )
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
