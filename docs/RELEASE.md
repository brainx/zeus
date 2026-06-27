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
   git tag -s vX.Y.Z -m "Zeus vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. Create the GitHub release from the tag and attach the generated `dist/*`
   artifacts plus `dist/SHA256SUMS.txt`.

## GitHub Release Workflow

`.github/workflows/release.yml` builds and checks distribution artifacts for
`v*.*.*` tags, runs the wheel smoke test, writes `SHA256SUMS.txt`, and creates
GitHub artifact attestations for the wheel, source distribution, and checksum
file. It intentionally does not publish to PyPI; release artifacts are uploaded
to GitHub Actions for review and attachment to a GitHub release.

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
