# API Reference

The Zeus API is a local JSON API. It binds to `127.0.0.1:4311` by default.
Routes accept an optional `/v1` prefix; for example, `/bots` and `/v1/bots`
address the same endpoint.

The machine-readable OpenAPI contract is maintained in `docs/openapi.json`.

All non-health endpoints require `ZEUS_API_KEY` to be configured and `x-zeus-api-key` to match it. If `ZEUS_API_KEY` is not configured, non-health endpoints reject requests. For local-only development, `ZEUS_ALLOW_UNAUTH_READS=1` allows unauthenticated low-risk `GET` endpoints while mutating endpoints remain locked behind `ZEUS_API_KEY`. Diagnostic endpoints that expose runtime state or logs, including `GET /bots/<bot-id>/logs`, `GET /bots/<bot-id>/inspect`, and `GET /bots/<bot-id>/history`, always require `x-zeus-api-key`.

At startup Zeus rejects a non-loopback bind without an API key of at least 16
characters, and rejects `ZEUS_ALLOW_UNAUTH_READS=1` on every non-loopback bind.
External access must use a separately hardened TLS reverse proxy and firewall.

Delete and archive are intentionally CLI-only in the current alpha because they
remove or move local profile directories. Use `zeus bot delete` or
`zeus bot archive` from a trusted local shell.

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
`unsupported_media_type`, `method_not_allowed`, `bot_locked`, `bot_exists`,
`bot_running`, `bot_replace_failed`, `bot_delete_failed`, `bot_archive_failed`,
`auth_rate_limited`, `mutation_rate_limited`, `reconcile_locked`,
`idempotency_key_conflict`, `idempotency_in_progress`,
`idempotency_indeterminate`, `idempotency_response_too_large`,
`idempotency_store_unavailable`,
`server_busy`, `server_draining`, `not_ready`, and `internal_error`.

JSON responses include `cache-control: no-store`. Mutating endpoints that accept
request bodies require an `application/json` content type and reject missing or invalid media
types with `unsupported_media_type`. Request bodies use strict JSON: duplicate object fields and
non-standard constants such as `NaN` or `Infinity` return `invalid_request`.

Request parsing is bounded and explicit:

- `POST /bots` accepts only the documented request fields, requires `Content-Length`, rejects
  content encodings, and limits JSON nesting to 64 levels.
- Query parameters must be documented for the endpoint, appear at most once, and total no more
  than 16 fields per request.
- Lifecycle endpoints without request schemas reject non-empty bodies.
- Request targets containing URL fragments are rejected rather than normalized silently.
- Unsupported `OPTIONS`, `PUT`, `PATCH`, and `DELETE` requests return JSON `405` errors with
  `Allow: GET, POST`.
- Zeus serves at most `ZEUS_API_MAX_CONCURRENT_REQUESTS` active requests and disconnects clients
  that do not complete a request within `ZEUS_API_REQUEST_TIMEOUT_SECONDS`. Saturated servers
  return `503` with `error.code=server_busy` and `Retry-After: 1`.
- During orderly shutdown, Zeus rejects new work with `503`,
  `error.code=server_draining`, and `Retry-After: 1`, while active requests receive up to
  `ZEUS_API_SHUTDOWN_DRAIN_SECONDS` to finish.

## Request Rate Limits

Zeus applies two process-local token buckets:

```dotenv
ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE=30
ZEUS_API_AUTH_FAILURE_BURST=10
ZEUS_API_MUTATION_RATE_PER_MINUTE=120
ZEUS_API_MUTATION_BURST=30
```

Rates accept 1-6000 requests per minute and bursts accept 1-1000. The buckets are
global to the one running API process, reset on restart, and are not keyed by client
IP or forwarded headers. `/v1` aliases share the same buckets as unprefixed routes.

Credentials are compared before failed-auth capacity is checked, so a valid key
always bypasses an exhausted invalid-auth bucket. Invalid credentials consume that
bucket; once exhausted they return `429 auth_rate_limited`. A missing server API key
remains `503 missing_api_key` and consumes nothing.

A validly authenticated recognized mutation consumes mutation capacity before body
parsing and before an idempotency claim. Malformed mutations, domain conflicts, and
idempotency replays therefore consume capacity; GETs, unsupported methods, and unknown
POST routes do not. Exhaustion returns `429 mutation_rate_limited` and creates no
idempotency record. Every `429` includes `X-Request-ID` and an integer `Retry-After`
rounded up to the next available token.

## Idempotent Mutations

The six mutating route forms (`POST /bots`, both reconcile routes, and the
start, stop, and restart routes) and their `/v1` aliases accept an optional
`Idempotency-Key` header matching
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. Authentication plus route, query, header,
and body validation completes before Zeus claims the key. Canonical route
aliases, JSON object ordering, and query ordering produce the same request
fingerprint. Zeus stores only hashes, never raw keys or request bodies.

A matching completed request replays its exact status and JSON and adds
`Idempotency-Replayed: true`. Reusing a key for different input returns
`409 idempotency_key_conflict`; an active claim returns
`409 idempotency_in_progress` with `Retry-After: 1`; a claim left unresolved by
an earlier process returns `409 idempotency_indeterminate` until expiry.
Storage or capacity failure before execution returns
`503 idempotency_store_unavailable`. The short claim transaction ends before
Supervisor work begins. Post-claim results, including domain `409` and internal
`500` results, are stored before the socket write. If completion cannot be
persisted, Zeus returns `503` and leaves the claim unresolved. GETs, invalid or
unknown routes, requests rejected before claim, and requests without the header
create no record.

For keyed fleet reconcile, Zeus captures the sorted bot IDs and profile paths
after validation and calculates a conservative replay-response ceiling before
claiming the key. A fleet that cannot fit the response budget returns
`422 idempotency_response_too_large` without running Supervisor work or creating
an idempotency record. Reconcile executes only that captured fleet; bots added
concurrently wait for the next pass, while bots removed before execution are
skipped. Dynamic response messages use a bounded JSON-encoded budget so escaped
control characters and Unicode cannot exceed the stored-response allowance.

The replay guarantee is limited to the retention window. Configure it with
`ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS` (60-604800, default 86400) and
`ZEUS_API_IDEMPOTENCY_MAX_RECORDS` (100-1000000, default 10000).

## Request Correlation and API Log

Every Zeus-generated response includes an `X-Request-ID` header containing a
new 32-character lowercase UUID hex value. This includes authentication and
validation failures, unsupported methods, unexpected errors, capacity
rejections, and shutdown-drain rejections. Incoming `X-Request-ID` values are
ignored. The `/v1` aliases and their unprefixed routes use the same normalized
route templates for logging.

When `ZEUS_API_LOG_ENABLED=1` (the default), handled application requests append
one JSON object per line to `$ZEUS_STATE_DIR/logs/api.jsonl`. Every `api.access`
record contains `schema_version` (currently `1`), `ts`, `level` (`info`), `event`,
`request_id`, `method`, `route`, `status`, `error_code`, `duration_ms`,
`auth_outcome`, and `idempotency_outcome`. Authentication outcomes are the
bounded values `not_checked`, `not_required`, `authenticated`, `missing`,
`rejected`, `unconfigured`, and `allowed_unauthenticated`. Idempotency outcomes
are bounded to `not_applicable`, `claimed`, `replayed`, `conflict`,
`in_progress`, `indeterminate`, and `unavailable`. An unexpected exception also emits a correlated `api.error`
record with `schema_version` `1`, `level` `error`, a bounded generic
`error_type`, and a generic `message`; it never includes a traceback or raw
exception text.

The logger accepts only normalized route templates. It does not record API keys,
authorization headers, request or response bodies, raw query strings, bot IDs,
client addresses or ports, forwarded-for values, idempotency keys, environment
maps, or raw tracebacks. It enforces mode `0700` on the log directory and `0600`
on `api.jsonl`. Writes are locked per process and fail open: filesystem,
permission, or serialization failures never change the HTTP response. Setting
`ZEUS_API_LOG_ENABLED=0` disables the file sink but not response request IDs.

## Endpoints

### `GET /health`

Public process-liveness check. It does not access SQLite or authenticate the
caller, so a successful response does not mean the state store is ready.

Returns:

```json
{"status":"ok"}
```

### `GET /ready`

Authenticated state-store readiness check, also available as `GET /v1/ready`.
It opens the existing SQLite database in read-only mode, requires schema version
6, and executes `SELECT 1`; it does not inspect or start bots. A stopped bot does
not make Zeus unready.

The route uses the normal read-endpoint authentication policy. It requires
`x-zeus-api-key` unless loopback-only development explicitly enables
`ZEUS_ALLOW_UNAUTH_READS=1`. Query parameters are rejected before the database
probe.

Success returns:

```json
{"schema_version":6,"status":"ready"}
```

An unavailable, missing, malformed, older, or newer state database returns
`503` with `error.code=not_ready`. Failure to initialize the state store before
the API binds remains a startup failure rather than an HTTP readiness response.

### `GET /doctor`

Returns the same readiness report as `zeus doctor --json`.

### `GET /templates`

Lists available templates and their async delegation settings.

### `GET /bots`

Lists registered bots. Each bot includes persisted `desired_state` and
`converged`, which is true only when observed running/stopped state matches the
desired state.

### `POST /bots`

Creates and renders a bot profile. The returned bot has the same additive
`desired_state` and `converged` fields as `GET /bots`.

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

By default, creating a bot with an existing `bot_id` returns `409` with
`error.code=bot_exists`. Use `POST /bots?replace=1` to replace a stopped bot.
If the existing bot is `running` or `starting`, Zeus returns `409` with
`error.code=bot_running` unless the request also includes `stop=1`, for example
`POST /bots?replace=1&stop=1`.

### `GET /bots/<bot-id>/status`

Returns Zeus status for a bot. If a PID is alive but the ownership marker does
not match, Zeus reports a failed state instead of trusting the process. When a
bot is `starting`, status performs one fast readiness probe and promotes it to
`running` only after the Hermes `/health` response is ready.

### `GET /bots/<bot-id>/logs`

Returns redacted gateway logs for a bot. This endpoint always requires `x-zeus-api-key`.

### `GET /bots/<bot-id>/inspect`

Returns the same runtime diagnostics as `zeus bot inspect <bot-id> --json`,
including profile file presence, safe PID marker metadata, live command-line
verification, structured ownership diagnostics, lifecycle transition metadata,
and recent redacted logs. This endpoint always requires `x-zeus-api-key`.

### `GET /bots/<bot-id>/history`

Returns authoritative lifecycle events newest first. This endpoint always
requires `x-zeus-api-key`, even when `ZEUS_ALLOW_UNAUTH_READS=1` permits other
low-risk reads. `limit` defaults to 50 and accepts values from 1 through 1000.
`before` is an optional positive event ID and is exclusive: only events with a
smaller ID are returned.

```http
GET /bots/coder/history?limit=50&before=123
x-zeus-api-key: ...
```

The response contains `bot_id`, `events`, and `next_before`. Events are ordered
by descending event ID. When another page exists, pass the non-null
`next_before` value as the next request's `before`; otherwise `next_before` is
`null`. History remains available after deletion or archive. A bot ID with
neither a current registry entry nor lifecycle events returns `unknown_bot`.
The machine-readable request, response, cursor, and strict-auth contract is in
`docs/openapi.json` under `/bots/{bot_id}/history`.

### `POST /bots/<bot-id>/start`

Starts the Hermes gateway process for the bot. Use
`POST /bots/<bot-id>/start?wait=1&timeout=30` to wait for the Hermes local
gateway health endpoint. Without `wait=1`, a bot with a configured readiness
probe returns `starting` until `GET /bots/<bot-id>/status` observes readiness.
Zeus persists the start intent before spawning. Its descriptor-only launcher
publishes and acknowledges an ownership marker before executing Hermes.

### `POST /bots/<bot-id>/restart`

Stops the Hermes gateway process if it is running, waits for clean shutdown, and
starts it again. It accepts the same `wait=1&timeout=30` query parameters as
start. A schema-v2 or legacy marker produces an action-required result before
any signal: Zeus leaves the marker, recorded PID, and pending intent unchanged
for manual process resolution.

### `POST /bots/<bot-id>/reconcile`

Checks the recorded gateway PID. If a bot with `restart_policy` set to `on-failure` is no longer running, Zeus schedules or performs a restart using exponential backoff.
Reconcile also owns recovery of pending durable lifecycle intents. It performs
at most one recovery effect per bot per pass; status remains observation-only
and never launches or signals to enforce desired state. Pending restarts backed
by schema-v2 or legacy markers fail closed and require manual process resolution.

The default response remains the existing one-element status array. Add exactly
`?summary=1` to receive the persisted run summary instead. A missing explicit bot
still returns `404 unknown_bot` and creates no run.

### `POST /bots/reconcile`

Runs reconcile across a sorted snapshot of registered bots. A bot-scoped failure is
recorded and later bots continue; earlier lifecycle changes are not rolled back.
Concurrent fleet passes return `409 reconcile_locked`.

The default response remains the existing status array. Add exactly `?summary=1` to
receive the persisted run ID, scope, timestamps, outcome, exact counters, and ordered
results. A completed run returns HTTP 200 even when its body reports
`completed_with_errors`; callers must inspect the summary outcome and counts.
`summary` is part of an idempotent request's canonical input, so default and summary
requests cannot reuse one key interchangeably.

### `POST /bots/<bot-id>/stop`

Stops the Hermes gateway process after verifying PID ownership. Use
`?kill_after_timeout=1` to override the default graceful-timeout behavior for a
single request. Stop signaling and marker cleanup require an exact, single-link
schema-v3 marker. Schema-v2 or legacy markers fail closed and remain untouched
with the recorded PID and pending stop intent.
