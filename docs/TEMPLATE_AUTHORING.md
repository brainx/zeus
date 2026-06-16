# Template Authoring

Templates are TOML files under `templates/*.toml`. A template renders one Hermes profile.

## Minimal Shape

```toml
id = "coding-bot"
name = "Coding Bot"
description = "Repository maintenance bot."
version = "0.1.0"
soul = "You are a focused coding agent."

[hermes]
required_env = ["OPENROUTER_API_KEY"]

[hermes.model]
provider = "openrouter"
default = "anthropic/claude-sonnet-4"

[hermes.terminal]
backend = "docker"
cwd = "."
home_mode = "profile"
timeout = 300

[hermes.gateway]
enabled = true

[hermes.delegation]
max_iterations = 50
max_concurrent_children = 3
max_async_children = 3
child_timeout_seconds = 0
subagent_auto_approve = false
```

## Validation Rules

- `id` must match `^[a-z][a-z0-9-]{1,62}$`.
- `version` must use `MAJOR.MINOR.PATCH`.
- `soul` must be non-empty.
- `hermes.terminal.cwd` must be relative.
- `required_env` entries must be environment variable names.
- `max_async_children` must be between `1` and `32`.
- `child_timeout_seconds` must be `0` or at least `30`.
- Fields ending in `KEY`, `TOKEN`, `SECRET`, or `PASSWORD` must use placeholders such as `${OPENROUTER_API_KEY}` rather than inline secrets.

## Rendering

`zeus bot create <bot-id> --template <template-id>` renders:

- `config.yaml`
- `.env`
- `SOUL.md`
- `mcp.json`
- `cron/jobs.json`
- `logs/`

Rendered `.env` files are runtime artifacts and must not be committed.

## DeepSeek

Hermes has a native DeepSeek provider. Use the built-in `deepseek-coding-bot` template or author a template like:

```toml
[hermes]
required_env = ["DEEPSEEK_API_KEY"]

[hermes.model]
provider = "deepseek"
default = "deepseek-v4-pro"
```

Pass the key at render time:

```bash
zeus bot create deepseek-coder --template deepseek-coding-bot --env DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY}"
```

Do not commit rendered profile `.env` files.
