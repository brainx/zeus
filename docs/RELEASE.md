# Release Process

Zeus releases are built from signed version tags. Keep releases small, verify
the repository locally first, and publish GitHub artifacts before considering
package-index distribution.

1. Ensure CI is green on the commit to release.
2. Run the local gates:

   ```bash
   sh scripts/test.sh
   sh scripts/repo_check.sh
   python -m build
   twine check dist/*
   ```

3. Update `CHANGELOG.md`.
4. Bump `pyproject.toml` version.
5. Create and push a signed tag:

   ```bash
   git tag -s v0.1.1 -m "Zeus v0.1.1"
   git push origin v0.1.1
   ```

6. Create the GitHub release from the tag and attach the generated `dist/*`
   artifacts.

## GitHub Release Workflow

`.github/workflows/release.yml` builds and checks distribution artifacts for
`v*.*.*` tags. It intentionally does not publish to PyPI; release artifacts are
uploaded to GitHub Actions for review and attachment to a GitHub release.
