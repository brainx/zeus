# Real Hermes Verification

The normal test suite uses a fake Hermes executable so the repository can be
tested without external credentials or a Hermes install. CI separately installs
the fully hash-locked Hermes Agent 0.21.0 environment from
`requirements-hermes-ci.txt` on Ubuntu/Python 3.11. CI verifies and installs the
official `v2026.8.31` release through the commit-addressed archive for
`29112bef099274229cadff79cdff7bf7b99c4b77`, with archive SHA-256
`76b99a8be9b77d66833c3cfe2b35c6d6f6a58e4ff9637ef8effcfc1f420ab35a`.
The release tag is unsigned; this is a source pin and digest check.
The lock contains the complete Linux x86_64 runtime and build closure and uses
the upstream `cryptography==50.0.0` pin and reviewed Requests and Rich overrides while
retaining upstream-compatible Pillow, FastAPI, pydantic-core, and tqdm pins. CI
installs the lock with dependency resolution disabled, then permits only the
two exact Hermes metadata conflicts introduced by the reviewed overrides.
The verified archive is retained as an editable source checkout because Hermes
0.21 rejects non-Nix wheel builds and requires its source-layout runtime assets.
Both gateway compatibility and the sealed audit-broker transcript must pass in
that environment. The transcript step sets `ZEUS_REQUIRE_PINNED_HERMES=1`, so
a missing or mismatched Hermes installation fails instead of skipping the test.
The gate does not run the remote installer or make a
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
asserts `inspect --json` ownership diagnostics, verifies authenticated
`bot diagnostics --json` against Hermes 0.21's detailed health and PID, and
probes Hermes `/health` before stopping the bot:

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
ZEUS_VERIFY_EXPECTED_HERMES_VERSION=0.21.0
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
