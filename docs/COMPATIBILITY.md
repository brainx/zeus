# Compatibility Policy

This document records compatibility evidence produced by the current committed
automation. It distinguishes repeatable CI from manual checks and does not turn
an untested platform or external Hermes release into a support claim.

## Automated matrix

| Gate | Committed runner | Python | Scope |
| --- | --- | --- | --- |
| Main CI matrix | Linux `ubuntu-24.04` | Python 3.11, 3.12, and 3.13 | Unit and integration tests, repository contracts, source-and-branch coverage, formatting, lint, typing, Bandit, and ShellCheck |
| Provisional Python compatibility | Linux `ubuntu-24.04` | Python 3.14 | Full Zeus test suite; non-required and Zeus-only because no Hermes baseline is pinned |
| Subprocess lifecycle | Linux `ubuntu-24.04` | Python 3.11 | Focused multi-process lifecycle and locking behavior |
| macOS process lifecycle | macOS `macos-26` | Python 3.13 | Focused process, fake-Hermes integration, and gateway-launcher recovery tests |
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
has not yet pinned and passed a Hermes baseline on that interpreter.

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
specific host and invocation rather than deterministic CI.

Local development checks such as `make check` and `sh scripts/wheel_smoke.sh`
remain useful evidence, but they do not add the developer's operating system to
the automated matrix.

## Hermes boundary

No Hermes version is pinned by this repository. There is no deterministic
real-Hermes CI gate today. The manual
[`scripts/verify_real_hermes.sh`](../scripts/verify_real_hermes.sh) check uses
whichever `hermes` executable is installed on `PATH`: it runs strict diagnostics,
renders a profile, invokes Hermes doctor, and can optionally start a loopback
gateway and probe its health.

Record `hermes version` with manual verification evidence. Passing against one
installed version does not establish compatibility with every Hermes release.
Before a Hermes baseline becomes required automation, the repository must name
the exact verified version or immutable source, install it reproducibly, and run
the real-Hermes gate without provider secrets in logs or command arguments.

## Updating this policy

Update this file in the same change that adds or removes a CI runner, Python
version, package gate, or reproducible Hermes baseline. Aspirational platforms
belong in the [roadmap](ROADMAP.md), not in the automated matrix.
