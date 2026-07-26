#!/usr/bin/env python3
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


@dataclass(frozen=True, order=True)
class DependencyConflict:
    dependent: str
    dependent_version: str
    requirement: str
    installed_version: str

    def describe(self) -> str:
        return (
            f"{self.dependent} {self.dependent_version} requires "
            f"{self.requirement}, installed version is {self.installed_version}"
        )


EXPECTED_DEPENDENCY_OVERRIDES = frozenset(
    {
        DependencyConflict(
            dependent="hermes-agent",
            dependent_version="0.19.0",
            requirement="cryptography==46.0.7",
            installed_version="48.0.1",
        ),
        DependencyConflict(
            dependent="hermes-agent",
            dependent_version="0.19.0",
            requirement="pillow==12.2.0",
            installed_version="12.3.0",
        ),
        DependencyConflict(
            dependent="hermes-agent",
            dependent_version="0.19.0",
            requirement="requests==2.33.0",
            installed_version="2.34.2",
        ),
        DependencyConflict(
            dependent="hermes-agent",
            dependent_version="0.19.0",
            requirement="rich==14.3.3",
            installed_version="15.0.0",
        ),
    }
)


class DependencyValidationError(RuntimeError):
    pass


def collect_conflicts(
    distributions: Iterable[metadata.Distribution],
) -> frozenset[DependencyConflict]:
    installed = tuple(distributions)
    versions: dict[str, str] = {}
    for distribution in installed:
        name = distribution.metadata.get("Name")
        if name:
            versions[canonicalize_name(name)] = distribution.version

    conflicts: set[DependencyConflict] = set()
    for distribution in installed:
        dependent_name = distribution.metadata.get("Name")
        if not dependent_name:
            continue
        dependent = canonicalize_name(dependent_name)
        for raw_requirement in distribution.requires or ():
            requirement = Requirement(raw_requirement)
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            requirement_name = canonicalize_name(requirement.name)
            installed_version = versions.get(requirement_name, "<missing>")
            if installed_version != "<missing>" and (
                not requirement.specifier
                or requirement.specifier.contains(installed_version, prereleases=True)
            ):
                continue
            conflicts.add(
                DependencyConflict(
                    dependent=dependent,
                    dependent_version=distribution.version,
                    requirement=f"{requirement_name}{requirement.specifier}",
                    installed_version=installed_version,
                )
            )
    return frozenset(conflicts)


def validate_conflicts(conflicts: frozenset[DependencyConflict]) -> None:
    unexpected = conflicts - EXPECTED_DEPENDENCY_OVERRIDES
    missing = EXPECTED_DEPENDENCY_OVERRIDES - conflicts
    if not unexpected and not missing:
        return

    details: list[str] = []
    if unexpected:
        details.append(
            "unexpected conflicts: "
            + "; ".join(conflict.describe() for conflict in sorted(unexpected))
        )
    if missing:
        details.append(
            "missing expected dependency overrides: "
            + "; ".join(conflict.describe() for conflict in sorted(missing))
        )
    raise DependencyValidationError(" | ".join(details))


def main() -> int:
    try:
        validate_conflicts(collect_conflicts(metadata.distributions()))
    except DependencyValidationError as exc:
        print(f"Hermes dependency validation failed: {exc}")
        return 1
    print(
        "Hermes dependency overrides verified: cryptography 48.0.1, "
        "pillow 12.3.0, requests 2.34.2, and rich 15.0.0; "
        "no other installed dependency conflicts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
