# Changelog

## 0.1.1

- Required API keys for all non-health local API endpoints.
- Added `ZEUS_ALLOW_UNAUTH_READS=1` for local unauthenticated GET endpoints.
- Added robust quoted `.env` serialization and parsing for rendered profiles.
- Added Linux live command-line checks to PID ownership verification.
- Added bot restart policy state, exponential backoff, and `zeus bot reconcile`.
- Added API reconcile endpoints and updated operator documentation.

## 0.1.0

- Added stdlib-only Zeus MVP.
- Added TOML template loading and validation.
- Added Hermes profile rendering with async delegation caps.
- Added SQLite bot registry.
- Added Hermes CLI adapter and gateway supervisor.
- Added PID ownership markers, graceful SIGTERM, and child process reaping.
- Added CLI and localhost HTTP API.
- Added normal and strict doctor checks.
- Added fake-Hermes lifecycle integration tests.
- Added CI, local test script, and real-Hermes verification handoff script.
- Added README hero assets, demo recording, roadmap, and release badges.
- Added `zeus bot restart` and `POST /bots/<bot-id>/restart`.
- Added ruff, mypy, Bandit, ShellCheck, package build, and twine CI gates.
- Added systemd deployment and operations documentation.
