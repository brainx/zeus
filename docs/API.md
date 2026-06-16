# API Reference

The Zeus API is a local JSON API. It binds to `127.0.0.1:4311` by default.

Mutating endpoints always require `ZEUS_API_KEY` to be configured and `x-zeus-api-key` to match it. If `ZEUS_API_KEY` is not configured, mutating endpoints reject requests.

## Endpoints

### `GET /health`

Returns:

```json
{"status":"ok"}
```

### `GET /doctor`

Returns the same readiness report as `zeus doctor --json`.

### `GET /templates`

Lists available templates and their async delegation settings.

### `GET /bots`

Lists registered bots.

### `POST /bots`

Creates and renders a bot profile.

Request:

```json
{
  "bot_id": "coder",
  "template_id": "coding-bot",
  "display_name": "Coder",
  "env": {
    "OPENROUTER_API_KEY": "${OPENROUTER_API_KEY}"
  }
}
```

### `GET /bots/<bot-id>/status`

Returns Zeus status for a bot. If a PID is alive but the ownership marker does not match, Zeus reports a failed state instead of trusting the process.

### `GET /bots/<bot-id>/logs`

Returns redacted gateway logs for a bot.

### `POST /bots/<bot-id>/start`

Starts the Hermes gateway process for the bot.

### `POST /bots/<bot-id>/restart`

Stops the Hermes gateway process if it is running, waits for clean shutdown, and starts it again.

### `POST /bots/<bot-id>/stop`

Stops the Hermes gateway process after verifying PID ownership.
