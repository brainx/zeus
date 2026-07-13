#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate release tag against package version.")
    parser.add_argument("tag", help="Git tag, for example v0.1.4")
    parser.add_argument(
        "--require-changelog",
        action="store_true",
        help="Require CHANGELOG.md to contain a section for the package version.",
    )
    args = parser.parse_args()

    version = _read_version(Path("zeus/__init__.py"))
    expected_tag = f"v{version}"
    if args.tag != expected_tag:
        print(
            f"release tag {args.tag!r} does not match package version {version!r} "
            f"(expected {expected_tag!r})",
            file=sys.stderr,
        )
        return 1

    if args.require_changelog:
        changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
        if f"## {version}" not in changelog:
            print(f"CHANGELOG.md is missing a section for {version}", file=sys.stderr)
            return 1
    return 0


def _read_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return node.value.value
    raise RuntimeError(f"could not find __version__ in {path}")


if __name__ == "__main__":
    raise SystemExit(main())
