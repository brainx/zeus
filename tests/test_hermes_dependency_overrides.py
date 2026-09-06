from __future__ import annotations

import unittest
from importlib import metadata
from unittest.mock import Mock

from scripts.check_hermes_dependency_overrides import (
    EXPECTED_DEPENDENCY_OVERRIDES,
    DependencyConflict,
    DependencyValidationError,
    collect_conflicts,
    validate_conflicts,
)


class HermesDependencyOverrideTests(unittest.TestCase):
    def test_exact_dependency_overrides_are_accepted(self) -> None:
        self.assertEqual(
            frozenset(
                {
                    DependencyConflict(
                        dependent="hermes-agent",
                        dependent_version="0.21.0",
                        requirement="requests==2.33.0",
                        installed_version="2.34.2",
                    ),
                    DependencyConflict(
                        dependent="hermes-agent",
                        dependent_version="0.21.0",
                        requirement="rich==14.3.3",
                        installed_version="15.0.0",
                    ),
                }
            ),
            EXPECTED_DEPENDENCY_OVERRIDES,
        )
        validate_conflicts(EXPECTED_DEPENDENCY_OVERRIDES)

    def test_upstream_cryptography_pin_requires_no_override(self) -> None:
        distributions = [
            Mock(
                spec=metadata.Distribution,
                metadata={"Name": "hermes-agent"},
                version="0.21.0",
                requires=["cryptography==50.0.0", "requests==2.33.0", "rich==14.3.3"],
            ),
            Mock(
                spec=metadata.Distribution,
                metadata={"Name": "cryptography"},
                version="50.0.0",
                requires=[],
            ),
            Mock(
                spec=metadata.Distribution,
                metadata={"Name": "requests"},
                version="2.34.2",
                requires=[],
            ),
            Mock(
                spec=metadata.Distribution,
                metadata={"Name": "rich"},
                version="15.0.0",
                requires=[],
            ),
        ]

        validate_conflicts(collect_conflicts(distributions))
        distributions[1].version = "48.0.1"
        with self.assertRaisesRegex(DependencyValidationError, "cryptography==50.0.0"):
            validate_conflicts(collect_conflicts(distributions))

    def test_missing_new_core_dependency_is_not_an_override(self) -> None:
        hermes = Mock(
            spec=metadata.Distribution,
            metadata={"Name": "hermes-agent"},
            version="0.21.0",
            requires=["firecrawl-anydoc==0.2.4"],
        )

        conflicts = collect_conflicts([hermes])
        self.assertEqual(
            conflicts,
            {DependencyConflict("hermes-agent", "0.21.0", "firecrawl-anydoc==0.2.4", "<missing>")},
        )
        with self.assertRaisesRegex(DependencyValidationError, "unexpected conflicts"):
            validate_conflicts(conflicts | EXPECTED_DEPENDENCY_OVERRIDES)

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
