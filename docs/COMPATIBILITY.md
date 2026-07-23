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
| macOS process lifecycle | macOS `macos-26` | Python 3.13 | Focused process, fake-Hermes integration, and gateway-launcher recovery tests |
| Real Hermes compatibility | Linux `ubuntu-24.04` | Python 3.11 | Hash-locked Hermes Agent 0.19.0 profile rendering, strict diagnostics, loopback gateway readiness, process ownership, and clean shutdown without a model-provider credential |
| Package build | Linux `ubuntu-24.04` | Python 3.11 | Wheel and source build, installed-wheel smoke test, dependency consistency, and metadata checks |
| Tagged release build | Linux `ubuntu-latest` | Python 3.11 | Full release gate, artifact checksums, and GitHub release artifacts |

In short, the focused Linux lifecycle and package jobs use Python 3.11. Main CI
uses the explicit `ubuntu-24.04` image, while the separate tagged-release
workflow still uses `ubuntu-latest`. The focused macOS lane uses `macos-26` and
Python 3.13. Windows is not currently automated. GitHub manages the contents of
all hosted runner images and may update them over time; results from an
individual developer machine remain local evidence rather than an automated
platform guarantee.

Python 3.14 is a provisional Zeus-only lane with `continue-on-error` behavior.
It does not promote Python 3.14 to required Hermes compatibility: the repository
pins Hermes Agent 0.19.0, whose package metadata requires Python 3.11 through
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

The deterministic CI baseline is Hermes Agent 0.19.0 on Ubuntu 24.04 with Python
3.11. [`requirements-hermes-ci.txt`](../requirements-hermes-ci.txt) pins the
complete 60-package wheel closure and its selected SHA-256 hashes. CI installs it
with pip hash checking and binary-only resolution; it never runs the remote
Hermes installer. The lock also carries Linux arm64 hashes for native local
container verification without changing the CI package versions.

The gate uses no model-provider credential or paid request. It renders a profile,
runs strict Zeus and Hermes diagnostics, starts the loopback gateway with
`--wait`, checks Zeus process ownership and Hermes `/health`, then stops the bot
and removes runtime state. On failure it uploads only a two-line sanitized stage
summary, never the rendered profile, environment, logs, or process arguments.

The manual [`scripts/verify_real_hermes.sh`](../scripts/verify_real_hermes.sh)
check still uses whichever `hermes` executable is installed on `PATH` unless
`ZEUS_VERIFY_EXPECTED_HERMES_VERSION` is set. Record `hermes version` with manual
evidence. Passing the pinned baseline does not establish compatibility with every
Hermes release or optional integration.

## Repository audit boundary

Every audit command discovers a Git repository and its Zeus state context.
`zeus audit run` additionally requires the exact Hermes Agent 0.19.0 release,
Docker, configured provider credentials, and a preloaded digest-qualified audit
image. `zeus audit doctor` checks that readiness and reports the selected
provider and model. `zeus audit list` and `zeus audit show` read stored reports
without invoking those runtime checks. A run may send selected committed
`HEAD` source excerpts and bounded terminal output to the provider; it does not
establish provider retention guarantees or network isolation for the host
Hermes process.

The repository-command container is admitted only after Zeus validates network
mode `none`, no host bind mounts, an unprivileged UID, dropped capabilities,
read-only root, bounded tmpfs, and the pinned image. The real Linux Docker
isolation gate is deliberately opt-in: set `ZEUS_RUN_DOCKER_ISOLATION=1` and
`ZEUS_AUDIT_TEST_IMAGE` on a Linux Docker host to execute it. A skipped gate,
including when Docker is unavailable, does not establish runtime isolation.

Audit always examines the exact committed `HEAD`, not dirty or untracked
content. It is report-only: it does not remediate, schedule work, or coordinate
cross-host work.

## Updating this policy

Update this file in the same change that adds or removes a CI runner, Python
version, package gate, or reproducible Hermes baseline. Aspirational platforms
belong in the [roadmap](ROADMAP.md), not in the automated matrix.
