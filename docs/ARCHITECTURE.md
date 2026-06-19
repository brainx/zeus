# Architecture

Zeus is a thin orchestration layer over Hermes Agent profiles. It is maintained by [BrainX](https://github.com/brainx) and interacts with Hermes through documented CLI/profile boundaries.

## Runtime Layout

By default Zeus writes runtime state under `.zeus/`:

```text
.zeus/
  zeus.db
  zeus.pid
  hermes/
    profiles/
      <bot-id>/
        config.yaml
        .env
        SOUL.md
        mcp.json
        cron/jobs.json
        logs/
```

Set `ZEUS_STATE_DIR` to use a different runtime root.

## Modules

- `zeus.models`: Template, bot, and status validation.
- `zeus.templates`: Local-first and bundled-fallback TOML template discovery.
- `zeus.renderer`: Hermes profile rendering.
- `zeus.state`: SQLite bot registry.
- `zeus.hermes_adapter`: Subprocess command construction for Hermes.
- `zeus.supervisor`: Gateway lifecycle, PID ownership markers, logs, and status.
- `zeus.api`: Local HTTP API.
- `zeus.cli`: Operator CLI.
- `zeus.doctor`: Readiness diagnostics.

## Process Lifecycle

1. `zeus bot create` renders a Hermes profile under `.zeus/hermes/profiles/<bot-id>/`.
2. `zeus bot start` launches `hermes -p <bot-id> gateway run` with `HERMES_HOME=.zeus/hermes`.
3. Zeus writes a PID marker in the bot profile logs directory.
4. `zeus bot stop` verifies the PID marker before signaling the process.
5. Zeus sends SIGTERM and waits for graceful exit so Hermes can interrupt background delegations.

Hermes child processes receive a minimal host environment plus profile `.env`
values. Operators can allow specific host variables with `ZEUS_ENV_PASSTHROUGH`.

## Async Delegation

Hermes supports `delegate_task(background=true)` and manages those subagents inside the Hermes process. Zeus configures the cap through rendered profile config:

```yaml
delegation:
  max_async_children: 3
```

Zeus does not poll Hermes background subagents directly. Hermes reinjects completed background delegation results into the originating conversation.
