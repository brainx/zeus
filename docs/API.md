# API Reference

The Zeus API is a local JSON API. It binds to `127.0.0.1:4311` by default.

The machine-readable OpenAPI contract is maintained in `docs/openapi.json`.

All non-health endpoints require `ZEUS_API_KEY` to be configured and `x-zeus-api-key` to match it. If `ZEUS_API_KEY` is not configured, non-health endpoints reject requests. For local-only development, `ZEUS_ALLOW_UNAUTH_READS=1` allows unauthenticated low-risk `GET` endpoints while mutating endpoints remain locked behind `ZEUS_API_KEY`. Diagnostic endpoints that expose runtime state or logs, including `GET /bots/<bot-id>/logs` and `GET /bots/<bot-id>/inspect`, always require `x-zeus-api-key`.

## Error Model

Errors use a stable object shape:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "request body must be a JSON object",
    "status": 400
  }
}
```

Known error codes are `invalid_request`, `invalid_bot_id`, `unknown_bot`,
`unknown_template`, `missing_api_key`, `invalid_api_key`,
`unsupported_media_type`, `method_not_allowed`, and `internal_error`.

JSON responses include `cache-control: no-store`. Mutating endpoints that accept
request bodies reject non-JSON content types with `unsupported_media_type`.

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
  "restart_policy": "on-failure",
  "restart_backoff_seconds": 5,
  "restart_max_attempts": 5,
  "env": {
    "OPENROUTER_API_KEY": "${OPENROUTER_API_KEY}"
  }
}
```

### `GET /bots/<bot-id>/status`

Returns Zeus status for a bot. If a PID is alive but the ownership marker does not match, Zeus reports a failed state instead of trusting the process.

### `GET /bots/<bot-id>/logs`

Returns redacted gateway logs for a bot. This endpoint always requires `x-zeus-api-key`.

### `GET /bots/<bot-id>/inspect`

Returns the same runtime diagnostics as `zeus bot inspect <bot-id> --json`, including profile file presence, PID marker metadata, live command-line verification, and recent redacted logs. This endpoint always requires `x-zeus-api-key`.

### `POST /bots/<bot-id>/start`

Starts the Hermes gateway process for the bot.

### `POST /bots/<bot-id>/restart`

Stops the Hermes gateway process if it is running, waits for clean shutdown, and starts it again.

### `POST /bots/<bot-id>/reconcile`

Checks the recorded gateway PID. If a bot with `restart_policy` set to `on-failure` is no longer running, Zeus schedules or performs a restart using exponential backoff.

### `POST /bots/reconcile`

Runs reconcile across all registered bots.

### `POST /bots/<bot-id>/stop`

Stops the Hermes gateway process after verifying PID ownership.
