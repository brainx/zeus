# Roadmap

## Current status

The latest stable release is Zeus v0.6.0. The `main` branch is the
v0.6.1.dev0 development line. Zeus remains alpha software with a local-first,
host-local scope. It owns profiles, processes, lifecycle safety, and
reconciliation evidence on one host.

## Shipped

- Workspace-local CLI and loopback API.
- Bundled and custom Hermes template validation and rendering.
- PID ownership checks, lifecycle locking, crash recovery, and restart policy.
- SQLite lifecycle and reconciliation evidence with indexed, paginated run
  history and a read-only fleet overview exposing freshness and attention reasons.
- Credential-free fake-Hermes demo, hash-locked real-Hermes CI, and manual
  real-Hermes verification scripts.
- Wheel builds, installed-wheel smoke checks, and GitHub release artifacts.
- Installed-wheel service interruption, pending-intent recovery, and quiesced
  backup/restore verification on disposable Ubuntu CI before preview distribution.
- Authenticated live diagnostics for owned Hermes gateways and opt-in operator
  messaging with durable receipts, bounded retries, cancellation and explicit
  recovery for acknowledged jobs whose outcomes are unavailable.
- Release publication tied to successful CI on the tagged main-branch commit.
- Host-local repository audits of committed `HEAD` with a packaged skill,
  Hermes Agent 0.21.0 compatibility gate, preloaded Docker image, bounded
  private reports, cleanup, and fail-closed isolation controls. Audits are
  report-only: they do not remediate or schedule work.
- Focused internal lifecycle, gateway-runtime, private-I/O, and audit modules
  behind compatibility facades, with a 1,200-line production-module size
  ratchet.

## Near term

- Keep local and CI quality gates aligned with the measured coverage baseline.
- Strengthen installed-package behavior and compatibility evidence.
- Keep the pinned Olymp compatibility contract aligned with Zeus development
  versions while preserving fail-closed mutation version checks.
- Add streamed operator-job output and explicit approval handling while retaining
  bounded responses, cancellation and durable delivery evidence.

## Under evaluation

- Workspace-local configuration export and import that never exports secrets.
- A local TUI for lifecycle status and reconciliation history.
- Local plugin discovery with explicit trust and compatibility boundaries.
- Bot-to-bot messaging with explicit peer permissions and bounded execution.
- A harness-neutral Agent Client Protocol layer for startup, sessions,
  prompt/event streaming, cancellation, inspection, permissions, and shutdown.
  Grok Build is the proposed first adapter; this is an evaluation item, not a
  Zeus 0.5.0 implementation commitment.

## Out of scope

The out-of-scope responsibilities are cross-host placement, distributed
approvals, fleet rollout policy, audit scheduling or remediation, and
control-plane ownership. They belong to
[Olymp](https://github.com/brainx/olymp), not Zeus. Zeus will keep a narrow
host-local API and durable evidence boundary that Olymp can consume.
