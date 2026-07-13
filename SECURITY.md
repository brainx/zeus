# Security Policy

## Supported Versions

Zeus is pre-1.0. Security fixes should target the repository default branch unless a maintained release branch is documented.

## Reporting a Vulnerability

Do not open public issues for vulnerabilities involving secrets, process control, profile isolation, API authorization, or command execution. Use the repository security advisory workflow once the repository is published, or contact the maintainers through the private channel documented there.

## Security Model

- Zeus is a local orchestrator for Hermes profiles, not a sandbox.
- The HTTP API binds to `127.0.0.1` by default.
- Non-loopback API binds require an API key of at least 16 characters and reject
  unauthenticated reads; external access also requires a separately hardened TLS
  reverse proxy and firewall.
- Mutating API endpoints require `ZEUS_API_KEY` to be configured and `x-zeus-api-key` to match it.
- Runtime state belongs under `.zeus/` or a configured `ZEUS_STATE_DIR`.
- Templates must reference secrets by environment variable name, not inline secret values.
- Hermes profiles isolate Hermes state. Tool execution isolation depends on the selected Hermes terminal backend.
- Gateway marker publication and lifecycle cleanup are serialized by a per-profile
  advisory lock shared by the Zeus supervisor and schema-v3 launcher. This lock is
  a protocol boundary, not isolation from arbitrary processes running as the same
  operating-system user: same-UID writers that modify marker or lock files without
  honoring the protocol are outside the supported trust model.

## Operational Guidance

- Use `zeus doctor --strict` before deployment.
- Use sandboxed Hermes terminal backends for untrusted bot tasks.
- Rotate any credential that was accidentally committed, printed in logs, or rendered into a shared artifact.
- Treat logs as sensitive because Hermes providers, messaging platforms, and bot tools may include user or operational data.
- Keep `ZEUS_STATE_DIR` ignored when it is inside a workspace and remove
  permissions for unrelated local users; `zeus doctor` checks both conditions.
