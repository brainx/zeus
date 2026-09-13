#!/usr/bin/env python3
"""Fail closed unless every required CI dependency completed successfully."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import Any, TextIO

ENVIRONMENT_VARIABLE = "ZEUS_CI_NEEDS_JSON"
MAX_INPUT_CHARACTERS = 64 * 1024
REQUIRED_DEPENDENCIES = frozenset(
    {
        "test",
        "lifecycle-subprocess",
        "package",
        "real-hermes",
        "audit-docker-isolation",
        "macos-process-lifecycle",
    }
)


class CIRequiredError(RuntimeError):
    """A required CI result is absent, malformed, or unsuccessful."""


def _reject_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def evaluate_needs(raw: str) -> None:
    if not raw or len(raw) > MAX_INPUT_CHARACTERS:
        raise CIRequiredError("invalid_needs")
    try:
        needs = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        raise CIRequiredError("invalid_needs") from None
    if not isinstance(needs, dict) or set(needs) != REQUIRED_DEPENDENCIES:
        raise CIRequiredError("invalid_needs")
    for dependency in REQUIRED_DEPENDENCIES:
        result = needs[dependency]
        if not isinstance(result, dict) or result.get("result") != "success":
            raise CIRequiredError("required_job_not_successful")


def main(
    *,
    environ: Mapping[str, str] | None = None,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    active_environment = os.environ if environ is None else environ
    raw = active_environment.get(ENVIRONMENT_VARIABLE)
    if raw is None:
        raw = stdin.read(MAX_INPUT_CHARACTERS + 1)
    try:
        evaluate_needs(raw)
    except CIRequiredError as error:
        print(f"required CI verification failed: {error}", file=stderr)
        return 1
    print("Verified all required CI dependencies succeeded.", file=stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
