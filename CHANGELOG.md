# Changelog

## 0.1.3

- Added startup grace polling so gateways that exit immediately are reported as failed instead of running.
- Rejected unknown template env keys before rendering profiles or writing files.
- Strengthened PID ownership verification on Linux and macOS, including fail-closed handling when live command lines cannot be verified.
- Added opt-in `ZEUS_STOP_KILL_AFTER_TIMEOUT` escalation for unattended shutdowns.
- Hardened `scripts/stop.sh` against malformed, stale, or cross-workspace PID files.
- Expanded API behavior coverage for authentication, malformed JSON, content length, content type, method, bot, and template error paths.
- Added `zeus bot inspect --json` with redacted logs, profile-file presence, PID marker metadata, and live command verification status.
- Added release artifact provenance attestations plus verification documentation.
- Added operations runbooks for log rotation, SQLite backups, restores, and migration rollback.
- Documented Zeus' local-process safety model and current known limitations.

## 0.1.2

- Polished release validation so CI and local release checks build once, smoke-test the exact wheel artifact, verify package metadata, and checksum the same distribution files.
- Added reusable `wheel-smoke` and `release-check` Make targets.
- Updated release documentation and repository contract tests for the artifact validation flow.
- Fixed README grammar in the project summary.

## 0.1.1

- Required API keys for all non-health local API endpoints.
- Added `ZEUS_ALLOW_UNAUTH_READS=1` for local unauthenticated GET endpoints while keeping mutations locked.
- Added robust quoted `.env` serialization and parsing for rendered profiles.
- Isolated Hermes child process environments by default and added explicit `ZEUS_ENV_PASSTHROUGH`.
- Added Linux live command-line checks to PID ownership verification.
- Added bot restart policy state, exponential backoff, and `zeus bot reconcile`.
- Added API reconcile endpoints and reused one API supervisor instance for lifecycle operations.
- Added bundled package templates and fallback loading for installed wheel environments.
- Added wheel smoke testing to verify installed package behavior outside a git checkout.
- Strengthened template secret validation and log redaction for lowercase keys, JSON-like fields, and bearer tokens.
- Hardened API responses with constant-time API-key comparison, `cache-control: no-store`, JSON `415`, and JSON `405` errors.
- Added OpenAPI contract coverage for lifecycle endpoints and error codes.
- Added release workflow artifacts, wheel smoke validation, and `SHA256SUMS.txt` generation.
- Added systemd, operations, reconcile, and release documentation.
- Added GitHub issue templates and pull request template.

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
