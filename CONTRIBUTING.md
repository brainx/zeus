# Contributing

Zeus is intentionally small and workspace-local. Changes should keep the project easy to audit, run, and publish.

## Development Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
make check
```

See the [compatibility policy](docs/COMPATIBILITY.md) for the operating systems,
Python versions, and Hermes boundary covered by committed automation. The
real-Hermes check below is a separate release gate because it depends on the
operator's installed Hermes version.

## Quality Bar

- Keep the core runtime dependency-free unless there is a clear operational reason.
- Keep state under `.zeus/` or another explicit `ZEUS_STATE_DIR`.
- Do not commit real secrets, rendered `.env` files, bot runtime state, or local Hermes profile data.
- Add tests for template validation, rendering, state changes, API behavior, and process lifecycle changes.
- Update README or docs when commands, templates, API routes, security behavior, or verification steps change.
- Run `make check` before opening a pull request. Coverage is configured in
  `.coveragerc`, measures only production code under `zeus`, and includes branch
  coverage. Treat its current `fail_under` value as a ratchet: raise it when the
  suite improves and do not lower it for new uncovered code.

## Real Hermes Verification

The default test suite uses a fake Hermes executable to verify Zeus process handling.
Before release, separately run:

```bash
sh scripts/verify_real_hermes.sh
```

To include gateway startup:

```bash
ZEUS_VERIFY_START_GATEWAY=1 sh scripts/verify_real_hermes.sh
```

## Pull Request Checklist

- `make check` passes, including tests, production source/branch coverage,
  repository contracts, formatting, lint, type checks, and Bandit.
- `shellcheck scripts/*.sh` passes when shell scripts change.
- `zeus doctor --strict` passes in an environment with Hermes installed.
- No generated `.zeus/`, `.tmp/`, `.zeus-real-hermes-check/`, or bytecode cache files are included.
- Documentation reflects the behavior being shipped.
