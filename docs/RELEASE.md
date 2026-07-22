# Release Process

Zeus releases are built from annotated version tags. Keep releases small, verify
the repository locally first, and publish GitHub artifacts before considering
package-index distribution. Future releases require both the annotated tag and
its referenced commit to carry signatures that GitHub marks verified. The
historical v0.3.0 release predates this policy and remains unchanged.

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
   coverage erase
   coverage run -m unittest discover -s tests
   coverage report
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
   sh scripts/generate_checksums.sh dist
   ```

3. Update `CHANGELOG.md`.
4. Bump `zeus/__init__.py` version. Package metadata reads the version from
   `zeus.__version__`.
5. Verify the tag that will be pushed matches the package version and changelog:

   ```bash
   python scripts/check_version_tag.py vX.Y.Z --require-changelog
   ```

6. Confirm the release commit is signed and GitHub-verified, then create and push
   a signed annotated tag:

   ```bash
   git log --show-signature -1
   git tag -s vX.Y.Z -m "Zeus vX.Y.Z"
   git push origin vX.Y.Z
   ```

   A merely annotated or locally valid signature is insufficient: GitHub must
   report both the tag and commit verification objects as `verified` with reason
   `valid`. Configure the signing identity with GitHub before pushing the tag.

7. Confirm the GitHub release workflow completed and attached the generated
   `dist/*` artifacts plus `dist/SHA256SUMS.txt` to the GitHub Release.

## GitHub Release Workflow

`.github/workflows/release.yml` builds and checks distribution artifacts for
`v*.*.*` tags, rejects lightweight tags and tags that do not match
`zeus.__version__`, requires a matching changelog section, and calls GitHub's API
to require a GitHub-verified annotated tag and referenced commit. The checker
binds the tag target to the workflow's `GITHUB_SHA`, reads `GITHUB_TOKEN` only
from the environment, rejects redirects and malformed responses, and never logs
the token or raw response bodies. Its read-only build job runs
`make release-check`, including tests, source-and-branch coverage, repository
contracts, formatting, lint, type checks, Bandit, ShellCheck, package build,
wheel smoke verification, metadata checks, and checksum generation. Only after
that job succeeds does a separate privileged job download the checked artifacts,
verify their checksums, create GitHub artifact attestations, and attach the assets
to the GitHub Release. It intentionally does not publish to PyPI.

Coverage configuration lives in `.coveragerc`, measures only the `zeus` package,
and includes branch coverage. The threshold records the honest current baseline;
raise it when coverage improves, and do not lower it to accommodate new uncovered
production code.

## Artifact Verification

After downloading release assets into one directory, verify checksums before
installing:

```bash
sha256sum -c SHA256SUMS.txt
```

On macOS, use:

```bash
shasum -a 256 -c SHA256SUMS.txt
```

Verify GitHub artifact attestations for each downloaded asset:

```bash
gh attestation verify zeus_hermes_orchestrator-X.Y.Z-py3-none-any.whl --repo brainx/zeus
gh attestation verify zeus_hermes_orchestrator-X.Y.Z.tar.gz --repo brainx/zeus
gh attestation verify SHA256SUMS.txt --repo brainx/zeus
```

The attestation should resolve to `.github/workflows/release.yml` on the
matching `refs/tags/v*.*.*` tag. Treat checksum or attestation failures as a
release-blocking provenance failure.
