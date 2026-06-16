# Real Hermes Verification

The normal test suite uses a fake Hermes executable so the repository can be tested without external credentials or a Hermes install.

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

Gateway startup is opt-in because it can require messaging tokens and provider credentials:

```bash
ZEUS_VERIFY_START_GATEWAY=1 sh scripts/verify_real_hermes.sh
```

Useful overrides:

```bash
ZEUS_VERIFY_BOT_ID=my-check-bot
ZEUS_VERIFY_TEMPLATE=research-bot
ZEUS_VERIFY_STATE_DIR=.zeus-real-hermes-check
ZEUS_VERIFY_GATEWAY_SECONDS=5
ZEUS_VERIFY_API_KEY=real-hermes-local-check
```

Expected failure when Hermes is not installed:

```text
hermes executable not found on PATH
```
