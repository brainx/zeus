# Changelog

## Unreleased

## 0.3.0

- Relaunched the public repository from an audited, single-root history on the `main` branch while
  retaining the previous history in a private archived repository.
- Removed obsolete repository-generation scaffolding from the published project.
- Added a public code of conduct and complete package links for documentation, issues, source, and
  changelog discovery.
- Strengthened repository contracts and ignore rules for a clean-checkout publication standard.

## 0.2.1

- Removed internal development planning documents from the published repository and GitHub source
  archives.

## 0.2.0

- Added process-local authentication-failure and authenticated-mutation token buckets with
  deterministic `429` responses and `Retry-After` guidance.
- Added schema-v6 reconciliation runs and per-bot results, with fleet locking and bot-scoped
  fault isolation that preserves earlier successful work.
- Added opt-in `zeus bot reconcile --summary` and `?summary=1` API responses while preserving
  the existing reconcile array output by default.
- Added optional durable `Idempotency-Key` replay with conflict, in-progress,
  indeterminate, and storage-unavailable outcomes.
- Added schema-v5 desired state and pending lifecycle intent for crash-safe recovery.
- Added the marker-before-exec launcher handshake and additive `desired_state` and
  `converged` bot JSON fields.
- Added locally generated `X-Request-ID` response correlation and a secret-safe,
  permission-enforced, fail-open structured API log.
- Added the immutable SQLite schema-v3 lifecycle ledger with atomic projection/event mutations
  and best-effort `audit.jsonl` compatibility mirroring.
- Added bounded, newest-first lifecycle history through `zeus bot history` and the strictly
  authenticated `GET /bots/<bot-id>/history` endpoint.
- Required an exact `application/json` media type for API request bodies, rejecting missing and
  look-alike content types.
- Rejected duplicate JSON object fields instead of silently accepting the last value.
- Rejected non-standard JSON constants such as `NaN` and `Infinity` during request parsing.
- Rejected unknown bot-create fields so misspelled inputs cannot be silently ignored.
- Rejected duplicate and unknown query parameters and limited requests to 16 query fields.
- Rejected request-target fragments instead of silently discarding them.
- Rejected request bodies on lifecycle endpoints that do not accept payloads.
- Rejected encoded JSON request bodies and required explicit content lengths.
- Limited JSON request nesting to 64 levels.
- Returned structured JSON `405` responses with an `Allow` header for `OPTIONS` requests.
- Bounded concurrent API request workers, added slow-client timeouts, and returned structured
  `503 server_busy` responses with `Retry-After` when capacity is exhausted.
- Drained active API requests during orderly shutdown and returned retryable
  `503 server_draining` responses for new work while stopping.

## 0.1.5

- Added process-locked bot create/replace semantics with explicit `--replace` and `--stop` safeguards.
- Added lifecycle metadata columns for bot start, readiness, stop, exit, and transition reasons.
- Added safe `zeus bot delete` and `zeus bot archive` commands.
- Added subprocess lifecycle concurrency tests and CI release workflow hardening.
- Preserved failed lifecycle state across status checks so on-failure reconcile remains eligible.
- Persisted readiness-probe provenance across CLI/API processes and added rollback for post-spawn registration failures.
- Distinguished dead, inaccessible, and racing PIDs before lifecycle signals.
- Made profile creation and replacement staged, validated, rollback-safe, and log-preserving.
- Added meaningful lifecycle CLI exit codes and hardened API PID, singleton, custom-state, and public-bind behavior.
- Preserved unmanaged profile content, rejected implicit replacement of retained profiles, and restarted previously active bots after failed mutations.
- Added process-group cleanup for failed start registration, strict readiness timeout validation, and portable release checksums.
- Changed coverage to an honest production-source branch gate and split least-privilege release verification from publishing with immutable Node 24 action pins.

## 0.1.4

- Handled Hermes launch `OSError` failures such as missing or non-executable Hermes binaries with structured `failed` bot status instead of uncaught exceptions.
- Added unit coverage for `FileNotFoundError` and `PermissionError` during gateway launch.
- Added real fake-Hermes crash integration coverage for gateways that exit during startup.
- Added authenticated `GET /bots/<bot-id>/inspect` diagnostics endpoint with redacted logs and no `.env` content exposure.
- Required authentication for sensitive `GET /bots/<bot-id>/logs` diagnostics even when unauthenticated low-risk reads are enabled.
- Documented diagnostic API auth behavior and updated OpenAPI contract.

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
