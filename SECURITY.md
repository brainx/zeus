# Security Policy

## Supported Versions

Zeus is pre-1.0. Security fixes should target the current `main` branch until a version support policy is published.

## Reporting a Vulnerability

Do not open public issues for vulnerabilities involving secrets, process control, profile isolation, API authorization, or command execution. Use the repository security advisory workflow once the repository is published, or contact the maintainers through the private channel documented there.

## Security Model

- Zeus is a local orchestrator for Hermes profiles, not a sandbox.
- The HTTP API binds to `127.0.0.1` by default.
- Mutating API endpoints require `ZEUS_API_KEY` to be configured and `x-zeus-api-key` to match it.
- Runtime state belongs under `.zeus/` or a configured `ZEUS_STATE_DIR`.
- Templates must reference secrets by environment variable name, not inline secret values.
- Hermes profiles isolate Hermes state. Tool execution isolation depends on the selected Hermes terminal backend.

## Operational Guidance

- Use `zeus doctor --strict` before deployment.
- Use sandboxed Hermes terminal backends for untrusted bot tasks.
- Rotate any credential that was accidentally committed, printed in logs, or rendered into a shared artifact.
- Treat logs as sensitive because Hermes providers, messaging platforms, and bot tools may include user or operational data.
