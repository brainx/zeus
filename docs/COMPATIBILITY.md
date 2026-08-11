# Compatibility Policy

This document records compatibility evidence produced by the current committed
automation. It distinguishes repeatable CI from manual checks and does not turn
an untested platform or external Hermes release into a support claim.

## Automated matrix

| Gate | Committed runner | Python | Scope |
| --- | --- | --- | --- |
| Main CI matrix | Linux `ubuntu-24.04` | Python 3.11, 3.12, and 3.13 | Unit and integration tests, repository contracts, source-and-branch coverage, formatting, lint, typing, Bandit, and ShellCheck |
| Provisional Python compatibility | Linux `ubuntu-24.04` | Python 3.14 | Full Zeus test suite; non-required and Zeus-only because the pinned Hermes baseline requires Python below 3.14 |
| Subprocess lifecycle | Linux `ubuntu-24.04` | Python 3.11 | Focused multi-process lifecycle and locking behavior |
| Audit Docker isolation | Linux `ubuntu-24.04` | Python 3.11 | Real Docker containment, including network denial, host-secret exclusion, read-only root, and cleanup |
| macOS process lifecycle | macOS `macos-26` | Python 3.13 | Focused process, fake-Hermes integration, and gateway-launcher recovery tests |
| Real Hermes compatibility | Linux `ubuntu-24.04` | Python 3.11 | Hash-locked Hermes Agent 0.20.0 source install, profile rendering, strict diagnostics, sealed audit-broker transcript, loopback gateway readiness, process ownership, and clean shutdown without a model-provider credential |
| Package build | Linux `ubuntu-24.04` | Python 3.11 | Wheel and source build, installed-wheel smoke test, dependency consistency, and metadata checks |
| Tagged release build | Linux `ubuntu-24.04` | Python 3.11 | Full release gate, artifact checksums, and GitHub release artifacts |

In short, the focused Linux lifecycle, audit-isolation, and package jobs use
Python 3.11. Main CI and both tagged-release jobs use the explicit
`ubuntu-24.04` image. The release build is bounded to 20 minutes and the
privileged publish job to 10 minutes. The focused macOS lane uses `macos-26` and
Python 3.13. Windows is not currently automated. GitHub manages the contents of
all hosted runner images and may update them over time; results from an
individual developer machine remain local evidence rather than an automated
platform guarantee.

Python 3.14 is a provisional Zeus-only lane with `continue-on-error` behavior.
It does not promote Python 3.14 to required Hermes compatibility: the repository
pins Hermes Agent 0.20.0, whose package metadata requires Python 3.11 through
3.13, and runs that compatibility gate only on Python 3.11.

The package metadata declares `requires-python = ">=3.11"`, while committed CI
currently tests the versions listed above. A version absent from that matrix is
not covered by the current automated compatibility claim.

## SQLite durability compatibility

Unset or empty `ZEUS_SQLITE_SYNCHRONOUS` configuration remains NORMAL, as do
direct `StateStore(path)` and `SQLiteDatabase(path)` calls. Upgrading therefore
does not silently change local commit latency. FULL is an explicit
higher-durability option for deployments that accept its additional commit
latency.

This policy does not change database structure or require a migration: the
schema remains schema v6 and every existing v6 database stays compatible.

## Manual clean-host evidence

[`scripts/fresh_vps_verify.sh`](../scripts/fresh_vps_verify.sh) provides a manual
clean-host runbook for Debian and Ubuntu. It can bootstrap OS packages, install
Zeus into a virtual environment, run local gates, render multiple profiles, and
exercise the loopback API. Optional Hermes installation and live probes cross an
external network and credential boundary, so their logs are evidence for that
specific host and invocation rather than the committed CI environment.

Local development checks such as `make check` and `sh scripts/wheel_smoke.sh`
remain useful evidence, but they do not add the developer's operating system to
the automated matrix.

## Hermes boundary

The deterministic CI baseline is Hermes Agent 0.20.0 on Ubuntu 24.04 with Python
3.11. CI obtains Hermes from the official signed `v2026.8.3` source tag at
commit `3c27eb6234bf91b8ceee9e9071591b31e9b148cb` and verifies archive SHA-256
`370542c7219faba6300905c3b419e14e6508a31ac698a1a5174e0386990834be`
before installation. [`requirements-hermes-ci.txt`](../requirements-hermes-ci.txt)
pins the complete 61-package Linux x86_64 runtime and build closure and its
selected SHA-256 hashes. CI installs that closure with dependency resolution
disabled, pip hash checking, and binary-only artifacts, then extracts the
verified archive into a retained CI source checkout and installs it editable
with dependencies and build isolation disabled. This follows Hermes 0.20's
supported source-install path and preserves the runtime assets its build guard
excludes from non-Nix wheels. CI never runs the remote Hermes installer.

Hermes Agent 0.20.0 metadata still pins `cryptography==48.0.1`,
`requests==2.33.0`, and `rich==14.3.3`. The lock substitutes the reviewed
`cryptography==50.0.0`, Requests 2.34.2, and Rich 15.0.0 releases. Pillow,
FastAPI, pydantic-core, and tqdm remain compatible with upstream metadata.
Pydantic's exact pydantic-core pin is retained because mismatching those
releases causes Pydantic to reject the environment at import time.
`scripts/check_hermes_dependency_overrides.py` permits exactly the three Hermes
metadata conflicts and fails for every other unsatisfied requirement. Remove
each override when compatible upstream metadata lands.

The gate uses no model-provider credential or paid request. It renders a
profile, runs strict Zeus and Hermes diagnostics in the patched dependency
environment, starts the loopback gateway with `--wait`, checks Zeus process
ownership and Hermes `/health`, then stops the bot and removes runtime state.
On failure it uploads only a two-line sanitized stage summary, never the
rendered profile, environment, logs, or process arguments.

The manual [`scripts/verify_real_hermes.sh`](../scripts/verify_real_hermes.sh)
check still uses whichever `hermes` executable is installed on `PATH` unless
`ZEUS_VERIFY_EXPECTED_HERMES_VERSION` is set. Record `hermes version` with manual
evidence. Passing the pinned baseline does not establish compatibility with every
Hermes release or optional integration.

Hermes Agent 0.20.0 remains affected by `GHSA-pmqc-57g8-c22c` when Feishu uses
webhook connection mode. Zeus therefore supports Feishu WebSocket mode only for
this baseline. Every Zeus-managed profile renderer rejects either
`FEISHU_CONNECTION_MODE=webhook` or
`platforms.feishu.extra.connection_mode: webhook`, comparing the value
case-insensitively after trimming whitespace. Absent values and WebSocket values
remain supported and are rendered unchanged. Remove the setting or select
WebSocket before creating or replacing a profile; the restriction can be
revisited only after the pinned upstream baseline contains a reviewed fix.

## Repository audit boundary

Every audit command discovers a Git repository and its Zeus state context.
`zeus audit run` additionally requires the exact Hermes Agent 0.20.0 release,
Docker, configured provider credentials, and a preloaded digest-qualified audit
image. `zeus audit doctor` checks that readiness and reports the selected
provider and model. `zeus audit list` and `zeus audit show` read stored reports
without invoking those runtime checks. `zeus audit gate` also reads a stored
report only; it evaluates the fixed `release-v1` policy and does not invoke
Docker, Hermes, provider credentials, or image readiness. A run may send
selected committed `HEAD` source excerpts and bounded terminal output to the
provider; it does not establish provider retention guarantees or network
isolation for the host Hermes process.

The primary repository-command container is admitted only after Zeus validates
network mode `none`, no host bind mounts, an unprivileged UID, dropped
capabilities, read-only root, bounded tmpfs, and the pinned image. Configured
coverage commands use a second pre-created container whose committed snapshot
bind is read-only and whose effective controls and mounted digest are attested
inside the container before each command. Its processes and writable `/tmp`
state are force-reset before an isolated receipt is accepted. CI runs the real
Linux Docker isolation gate on Ubuntu 24.04 with the exact default image digest
preloaded. Local runs remain deliberately opt-in: set
`ZEUS_RUN_DOCKER_ISOLATION=1` and `ZEUS_AUDIT_TEST_IMAGE` on a Linux Docker host
to execute it. A skipped local gate, including when Docker is unavailable,
does not establish runtime isolation.

Audit always examines the exact committed `HEAD`, not dirty or untracked
content. It is report-only: it does not remediate, schedule work, or coordinate
cross-host work.

New reports use schema version 2. They include a deterministic committed-surface
inventory and digest, explicit required-control coverage, terminal receipts
bound in private broker state to the target commit and snapshot digest, source
blob SHA-256 values, stable finding fingerprints, and the explicit versioned
`isolated-read-only-snapshot-v1` trusted-receipt execution boundary. Receipt
command tags are opaque and also bind the run, image, sequence, exact command
digest, and result metadata; receipt objects contain neither raw commands nor
raw command output.
Legacy suggested-command arrays remain accepted, while the structured
`{"argv": [...], "control_ids": [...]}` form adds explicit security-control
authorization. A legacy or ad-hoc command cannot satisfy security coverage.
The report reader retains exact schema-v1 JSON/Markdown compatibility, but
`release-v1` requires schema v2 and the current trusted-receipt execution
boundary, and therefore rejects legacy reports.

The fixed scanner-adapter registry is a compatibility seam, not a runtime
claim. Its entries are non-executable and dynamically loaded plugins are not
supported. External deterministic SAST and advisory engines are not bundled or
executed by this release.

## Updating this policy

Update this file in the same change that adds or removes a CI runner, Python
version, package gate, or reproducible Hermes baseline. Aspirational platforms
belong in the [roadmap](ROADMAP.md), not in the automated matrix.
