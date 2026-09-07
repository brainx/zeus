# Release Process

Zeus releases are built from annotated version tags. Keep releases small, verify
the repository locally first, and publish GitHub artifacts before considering
package-index distribution. Future releases require both the annotated tag and
its referenced commit to carry signatures that GitHub marks verified. The
historical v0.3.0 release predates this policy and remains unchanged.

1. Ensure CI is green on the commit to release.
2. Prepare the stable release:

   - Replace the current `.dev0` version with the intended stable `X.Y.Z`
     version in `zeus/__init__.py` and `docs/openapi.json`.
   - Update `docs/ROADMAP.md` so its latest-stable statement identifies
     `vX.Y.Z` and it no longer describes that version as the current
     development line.
   - Move `CHANGELOG.md`'s `Unreleased` entries into a matching `## X.Y.Z`
     section.
   - Run `python scripts/check_version_tag.py vX.Y.Z --require-changelog`.
   - After the release, advance `main` in a separate commit: set the next
     `X.Y.Z.dev0` version in `zeus/__init__.py` and `docs/openapi.json`, and
     update `docs/ROADMAP.md` to name that version as the current development
     line while retaining the release as latest stable.

3. Install the pinned CI and release toolchain, then run the full local release gate:

   ```bash
   python -m pip install -e . -r requirements-dev-ci.txt
   make release-check
   ```

   The `requirements-dev-ci.txt` pins define the reproducible CI and release
   toolchain; the lower bounds in the `dev` extra remain for developer environments.

   The release gates must run after this install. It provides the exact tool
   versions that CI verifies.

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

4. Before creating a tag, inspect Dependabot alerts through an authenticated
   GitHub CLI session:

   ```bash
   gh auth status
   gh api --paginate --method GET \
     -H "Accept: application/vnd.github+json" \
     "repos/brainx/zeus/dependabot/alerts?state=open&per_page=100" \
     --jq '.[] | {number, dependency: .dependency.package.name, manifest: .dependency.manifest_path, severity: .security_advisory.severity, summary: .security_advisory.summary}'
   ```

   These commands use the existing authenticated session and do not print its
   credential; do not run `gh auth token` or echo an access token. Treat every
   open alert affecting a runtime, development/release, build, CI, or GitHub
   Actions dependency as release-relevant. Before tagging, fix every
   release-relevant alert or record an explicit mitigation in the release PR:
   the alert number, affected dependency and exposure, compensating control,
   owner, and a review or removal deadline. Tagging is blocked while a
   release-relevant open alert lacks that documented mitigation.

5. Confirm the release commit is signed and GitHub-verified, then create and push
   a signed annotated tag:

   ```bash
   git log --show-signature -1
   git tag -s vX.Y.Z -m "Zeus vX.Y.Z"
   git push origin vX.Y.Z
   ```

   A merely annotated or locally valid signature is insufficient: GitHub must
   report both the tag and commit verification objects as `verified` with reason
   `valid`. Configure the signing identity with GitHub before pushing the tag.

6. Confirm the GitHub release workflow completed and attached the generated
   `dist/*` artifacts plus `dist/SHA256SUMS.txt` to the GitHub Release.

## GitHub Release Workflow

`.github/workflows/release.yml` builds and checks distribution artifacts for
`v*.*.*` tags, rejects lightweight tags and tags that do not match
`zeus.__version__`, requires a matching changelog section, and calls GitHub's API
to require a GitHub-verified annotated tag and referenced commit. The checker
binds the tag target to the workflow's `GITHUB_SHA`, reads `GITHUB_TOKEN` only
from the environment, rejects redirects and malformed responses, and never logs
the token or raw response bodies. Both jobs use the explicit `ubuntu-24.04`
runner; the read-only build job is bounded to 20 minutes and the privileged
publish job to 10 minutes. The build job runs
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

## CI Preview Builds

The CI `package` job uploads the wheel, source archive, and `SHA256SUMS.txt`
after dependency checks, package build, installed-wheel smoke verification,
and metadata checks succeed. These artifacts are available for seven days from
push, pull-request, and manually dispatched runs. Their name is
`zeus-preview-<commit>-<run-id>-<attempt>`; the commit is the checked-out
`github.sha`, which is the tested merge commit for pull-request runs. The run
records the source ref, and the package filenames and metadata record the version.

Use an authenticated GitHub CLI session to select a run and inspect its result:

```bash
gh run list --repo brainx/zeus --workflow ci.yml --limit 10
run_id=123456789 # Replace with the selected CI run ID.
gh run view "$run_id" --repo brainx/zeus
gh api "repos/brainx/zeus/actions/runs/$run_id/artifacts" \
  --jq '.artifacts[] | select(.name | startswith("zeus-preview-")) | {name, expired}'
```

Copy the exact unexpired artifact name from that run, then download and verify
it in its own directory:

```bash
artifact_name="zeus-preview-COMMIT-RUN_ID-ATTEMPT" # Replace with the listed name.
preview_dir=".tmp/$artifact_name"
gh run download "$run_id" --repo brainx/zeus \
  --name "$artifact_name" --dir "$preview_dir"
(cd "$preview_dir" && sha256sum -c SHA256SUMS.txt)
```

On macOS, use `(cd "$preview_dir" && shasum -a 256 -c SHA256SUMS.txt)`.
The upload establishes that the package job passed; other jobs may still be
running or may have failed, so check the complete run before evaluating a
preview. Checksums detect changed downloads. Preview packages are unsigned,
have no release provenance attestation, and do not establish the signed-tag and
verified-commit evidence required for tagged releases.

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

## v0.6 Development Upgrade

The development package identifies itself as `0.6.0.dev0`; the latest stable
release remains v0.5.0. Existing lifecycle route shapes are retained, with
additional read-only operator endpoints. `/ready` reports schema version 9
after the additive index, message-receipt, and release-timestamp migrations.
Normal service/CLI initialization performs the migration; inspection and message
commands require the current schema and do not migrate it as a side effect.

Before upgrading an existing host, quiesce Zeus writers and take the database
and private profiles backup described in [Operations](OPERATIONS.md). Restart
with one version of Zeus managing the state directory. Do not run a v0.5 process
against an upgraded v9 database. A rollback requires the matching pre-upgrade
backup and old package; Zeus does not downgrade databases.

Olymp must explicitly support the `0.6.0.dev0` version and schema-v9 readiness
contract before registering a node with that expected version. Preserve exact
version checks and the existing v0.5/schema-v6 contract for stable nodes. The
new fleet freshness field is evidence age, not a substitute for application
health or cross-host rollout approval.

The CI package job runs `scripts/verify_service_recovery.sh` only on a disposable
Ubuntu 24.04 GitHub-hosted runner, using the built wheel and private copied
systemd units. Preview checksums and upload follow successful recovery checks.
The script refuses ordinary developer hosts; it is not an installer or a
production restore command.
