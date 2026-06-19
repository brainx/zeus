# Release Process

Zeus releases are built from signed version tags. Keep releases small, verify
the repository locally first, and publish GitHub artifacts before considering
package-index distribution.

1. Ensure CI is green on the commit to release.
2. Run the full local release gate:

   ```bash
   make release-check
   ```

   This runs tests, repository checks, formatting/lint/type/security checks,
   ShellCheck, package build, wheel smoke verification, package metadata checks,
   and checksum generation.

   Reference command sequence:

   ```bash
   sh scripts/test.sh
   sh scripts/repo_check.sh
   ruff format --check .
   ruff check .
   mypy zeus
   bandit -r zeus
   shellcheck scripts/*.sh
   rm -rf dist
   python -m build
   ZEUS_WHEEL_SMOKE_BUILD=0 sh scripts/wheel_smoke.sh
   twine check dist/*
   cd dist && sha256sum * > SHA256SUMS.txt
   ```

3. Update `CHANGELOG.md`.
4. Bump `zeus/__init__.py` version. Package metadata reads the version from
   `zeus.__version__`.
5. Create and push a signed tag:

   ```bash
   git tag -s v0.1.1 -m "Zeus v0.1.1"
   git push origin v0.1.1
   ```

6. Create the GitHub release from the tag and attach the generated `dist/*`
   artifacts plus `dist/SHA256SUMS.txt`.

## GitHub Release Workflow

`.github/workflows/release.yml` builds and checks distribution artifacts for
`v*.*.*` tags, runs the wheel smoke test, and writes `SHA256SUMS.txt`. It
intentionally does not publish to PyPI; release artifacts are uploaded to GitHub
Actions for review and attachment to a GitHub release.
