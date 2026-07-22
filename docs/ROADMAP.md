# Roadmap

## Current status

Zeus v0.3.0 is alpha software with a local-first, host-local scope. It owns
profiles, processes, lifecycle safety, and reconciliation evidence on one host.

## Shipped

- Workspace-local CLI and loopback API.
- Bundled and custom Hermes template validation and rendering.
- PID ownership checks, lifecycle locking, crash recovery, and restart policy.
- SQLite lifecycle and reconciliation evidence.
- Credential-free fake-Hermes demo, hash-locked real-Hermes CI, and manual
  real-Hermes verification scripts.
- Wheel builds, installed-wheel smoke checks, and GitHub release artifacts.

## Near term

- Keep local and CI quality gates aligned with the measured coverage baseline.
- Strengthen installed-package behavior and compatibility evidence.
- Decompose large internal modules without changing the public CLI, API, or
  persisted schemas.
- Improve local operational readiness, backup guidance, and health evidence.

## Under evaluation

- Workspace-local configuration export and import that never exports secrets.
- A local TUI for lifecycle status and reconciliation history.
- Local plugin discovery with explicit trust and compatibility boundaries.

## Out of scope

The out-of-scope responsibilities are cross-host placement, distributed
approvals, fleet rollout policy, and control-plane ownership. They belong to
[Olymp](https://github.com/brainx/olymp), not Zeus. Zeus will keep a narrow
host-local API and durable evidence boundary that Olymp can consume.
