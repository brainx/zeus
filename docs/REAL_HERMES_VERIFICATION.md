# Real Hermes Verification

The normal test suite uses a fake Hermes executable so the repository can be
tested without external credentials or a Hermes install. CI separately installs
the fully hash-locked Hermes Agent 0.20.0 environment from
`requirements-hermes-ci.txt` on Ubuntu/Python 3.11. CI verifies and installs the
official signed `v2026.8.3` source archive at commit
`3c27eb6234bf91b8ceee9e9071591b31e9b148cb`, with archive SHA-256
`370542c7219faba6300905c3b419e14e6508a31ac698a1a5174e0386990834be`.
The lock contains the complete Linux x86_64 runtime and build closure and uses
the reviewed `cryptography==50.0.0`, Requests, and Rich overrides while
retaining upstream-compatible Pillow, FastAPI, pydantic-core, and tqdm pins. CI
installs the lock with dependency resolution disabled, then permits only the
three exact Hermes metadata conflicts introduced by the reviewed overrides.
The verified archive is retained as an editable source checkout because Hermes
0.20 rejects non-Nix wheel builds and requires its source-layout runtime assets.
Both gateway compatibility and the sealed audit-broker transcript must pass in
that environment. The gate does not run the remote installer or make a
model-provider request.

Before a release, verify against a real Hermes install:

```bash
sh scripts/verify_real_hermes.sh
```

The script:

1. Confirms `hermes` is available on `PATH`.
2. Uses an isolated `.zeus-real-hermes-check/` runtime directory.
3. Runs `zeus doctor --strict` with a local verification-only `ZEUS_API_KEY`.
4. Renders a bot from `coding-bot`.
5. Runs `hermes -p <bot-id> doctor`.
6. Confirms the rendered config contains `max_async_children`.

Gateway startup is opt-in. When enabled, the script starts the real Hermes
gateway with the local `api_server` platform, binds it to loopback, passes a
random per-run `API_SERVER_KEY`, verifies Zeus still reports the bot as running,
asserts `inspect --json` ownership diagnostics, and probes Hermes `/health`
before stopping the bot:

```bash
ZEUS_VERIFY_START_GATEWAY=1 sh scripts/verify_real_hermes.sh
```

When gateway startup verification is enabled, the script starts Zeus with
`--wait`, confirms Zeus reports the bot as running, then polls Hermes `/health`
until the local `api_server`
reports `{"status":"ok","platform":"hermes-agent"}` or the health timeout
expires. This avoids false negatives when Hermes binds the loopback API shortly
after the process becomes visible to Zeus.

Successful and failed runs stop the bot and remove the isolated runtime tree.
Failures retain only a sanitized `summary.txt` containing the fixed result and
failure-stage labels. Raw logs, rendered profiles, environments, and command
arguments are never copied into that evidence directory.

Useful overrides:

```bash
ZEUS_VERIFY_BOT_ID=my-check-bot
ZEUS_VERIFY_TEMPLATE=research-bot
ZEUS_VERIFY_STATE_DIR=.zeus-real-hermes-check
ZEUS_VERIFY_EVIDENCE_DIR=.tmp/real-hermes-evidence
ZEUS_VERIFY_EXPECTED_HERMES_VERSION=0.20.0
ZEUS_VERIFY_API_KEY=real-hermes-local-check
ZEUS_VERIFY_API_SERVER_HOST=127.0.0.1
ZEUS_VERIFY_API_SERVER_PORT=4312
ZEUS_VERIFY_HEALTH_TIMEOUT_SECONDS=30
ZEUS_VERIFY_HEALTH_INTERVAL_SECONDS=0.5
```

Leave `ZEUS_VERIFY_EXPECTED_HERMES_VERSION` unset for an intentional manual
compatibility check against another installed version. Such a run is local
evidence, not an update to the committed baseline.

Expected failure when Hermes is not installed:

```text
hermes executable not found on PATH
```
