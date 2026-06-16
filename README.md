# Zeus Hermes Orchestrator

Many Hermes bots, one local supervisor.

Zeus is a [BrainX](https://github.com/brainx)-maintained orchestration layer for running many Hermes Agent bots from reusable templates. It renders each bot as an isolated Hermes profile under `.zeus/`, starts and stops gateway processes, tracks PID ownership, and exposes a small loopback CLI/API for operators.

## Why Zeus

- Run multiple Hermes bots from one workspace without hand-copying profile directories.
- Stamp out repeatable bot shapes from TOML templates: coding, research, support, DeepSeek, and custom profiles.
- Keep secrets out of templates by rendering per-profile `.env` files that stay ignored by git.
- Supervise gateway processes with ownership markers before stop/status actions trust a PID.
- Account for Hermes async delegation with explicit `max_async_children` caps in every built-in template.
- Verify locally, against a real Hermes install, or on a clean Debian/Ubuntu VPS using included scripts.

## How It Works

```mermaid
flowchart LR
  T["templates/*.toml"] --> Z["Zeus renderer"]
  Z --> P[".zeus/hermes/profiles/<bot-id>"]
  P --> H["hermes -p <bot-id> gateway run"]
  Z --> S["SQLite bot registry"]
  S --> C["CLI and loopback API"]
  C --> H
```

Each rendered profile contains `config.yaml`, `.env`, `SOUL.md`, `mcp.json`, `cron/jobs.json`, and logs. Hermes remains the agent runtime; Zeus owns profile generation, local orchestration, lifecycle checks, and handoff verification.

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
cp .env.example .env

zeus doctor
zeus template list
zeus bot create coder --template coding-bot
zeus bot doctor coder
```

Start the local API with an explicit key:

```bash
ZEUS_API_KEY=change-me sh scripts/start.sh
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API reference](docs/API.md)
- [Template authoring](docs/TEMPLATE_AUTHORING.md)
- [Real Hermes verification](docs/REAL_HERMES_VERIFICATION.md)
- [Fresh VPS test](docs/FRESH_VPS_TEST.md)
- [Repository generation checklist](docs/REPO_GENERATION.md)
- [Contributing](CONTRIBUTING.md)
- [Credits](CREDITS.md)
- [Security policy](SECURITY.md)

## Requirements

- Python 3.11 or newer
- Hermes Agent installed as `hermes` for real bot startup
- Optional Docker or another Hermes terminal backend for stronger execution isolation

No Python package dependencies are required for the current MVP.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
cp .env.example .env
```

## Commands

```bash
zeus doctor
zeus template list
zeus bot create coder --template coding-bot
zeus bot doctor coder
zeus bot start coder
zeus bot status coder
zeus bot logs coder
zeus bot stop coder
```

## Verification

Run the local checks:

```bash
sh scripts/test.sh
sh scripts/repo_check.sh
```

Run deployment-style diagnostics:

```bash
zeus doctor --strict
```

Strict mode requires a real `hermes` executable on `PATH`.

When Hermes is installed, run the real-Hermes compatibility check:

```bash
sh scripts/verify_real_hermes.sh
```

That script creates an isolated `.zeus-real-hermes-check/` runtime, renders a bot profile, runs `hermes -p <bot> doctor`, and verifies the generated profile contains the async delegation cap. It does not start a gateway by default. To exercise `hermes gateway run`, set:

```bash
ZEUS_VERIFY_START_GATEWAY=1 sh scripts/verify_real_hermes.sh
```

For a clean Debian/Ubuntu host, use the fresh VPS harness:

```bash
ZEUS_VPS_INSTALL_PACKAGES=1 ZEUS_VPS_INSTALL_HERMES=1 bash scripts/fresh_vps_verify.sh
```

See [Fresh VPS test](docs/FRESH_VPS_TEST.md) for gateway and async-delegation probes.

## API

```bash
ZEUS_API_KEY=change-me sh scripts/start.sh
```

The API binds to `127.0.0.1:4311` by default. Mutating endpoints require `x-zeus-api-key`.
If `ZEUS_API_KEY` is not configured, mutating endpoints reject requests instead of running anonymously.

Useful endpoints:

- `GET /health`
- `GET /doctor`
- `GET /templates`
- `GET /bots`
- `POST /bots`
- `POST /bots/<bot-id>/start`
- `POST /bots/<bot-id>/stop`

## Templates

Templates live in `templates/*.toml`. They render Hermes `config.yaml`, `.env`, `SOUL.md`, `mcp.json`, and `cron/jobs.json` files under `.zeus/hermes/profiles/<bot-id>/`.

Built-in templates include OpenRouter-backed bots and `deepseek-coding-bot`, which uses Hermes' native DeepSeek provider with `DEEPSEEK_API_KEY`.

Each template should set a bounded async delegation cap:

```toml
[hermes.delegation]
max_async_children = 3
max_concurrent_children = 3
child_timeout_seconds = 0
```

Hermes `delegate_task(background=true)` runs child agents in the background and reinjects results into the originating conversation. Zeus configures capacity and supervises the gateway process; it does not poll Hermes background subagents directly.

## Operational Checks

Run:

```bash
zeus doctor
zeus doctor --json
zeus doctor --strict
```

The doctor validates Python support, Hermes binary availability, template validity, runtime ignore rules, script executability, API bind safety, and rendered bot profile files. Missing Hermes is reported as a warning in normal mode because templates and profile generation can still be developed without a local Hermes install. Use `--strict` for deployment gates where warnings should fail the command.

## Process Safety

When Zeus starts a gateway, it writes a PID ownership marker under the bot profile logs directory. `zeus bot stop` sends SIGTERM only when that marker matches the bot and PID, then waits for graceful gateway shutdown so Hermes can interrupt any running background delegations.

The test suite includes a fake Hermes executable that exercises the real Zeus subprocess path: render profile, start gateway, verify `HERMES_HOME`, stop gateway, reap the child process, and confirm logs are captured.

## Security Notes

Templates must not contain real secrets. Use environment variables or rendered per-profile `.env` files excluded from git. Hermes profiles isolate Hermes state, not host filesystem access. Use a sandboxed Hermes terminal backend when a bot should not execute tools directly on the host.
