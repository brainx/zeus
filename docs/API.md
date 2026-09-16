# API Reference

The Zeus API is a local JSON API. It binds to `127.0.0.1:4311` by default.
Routes accept an optional `/v1` prefix; for example, `/bots` and `/v1/bots`
address the same endpoint.

The machine-readable OpenAPI contract is maintained in `docs/openapi.json`.

All non-health endpoints require an authenticated credential by default, sent in
`x-zeus-api-key`. Existing `ZEUS_API_KEY` installations remain compatible: that
key is the administrator credential and retains access to all existing routes.
Keys must contain ASCII characters only. Without any configured credential,
protected requests return `503 missing_api_key`; missing or invalid client keys
return `401 invalid_api_key`. A valid named credential without the required
permission returns `403 permission_denied` before endpoint work begins.

Zeus remains loopback-first. At startup it rejects a non-loopback bind without a
`ZEUS_API_KEY` of at least 16 characters, and rejects
`ZEUS_ALLOW_UNAUTH_READS=1` on every non-loopback bind. Named credentials do not
relax that exposure check. External access must use a separately hardened TLS
reverse proxy and firewall. Keep every Zeus credential in the dashboard's
server-side adapter or secret environment; never embed it in browser code,
client storage, URLs, or dashboard responses.

## Named Integration Credentials

Set `ZEUS_API_INTEGRATIONS_FILE` to a private JSON file with this shape:

```json
{
  "version": 1,
  "integrations": [
    {"id": "olymp", "key_env": "OLYMP_ZEUS_API_KEY", "permissions": ["observer"]}
  ]
}
```

Use a directory owned by the Zeus process user with mode `0700` and a regular
file owned by that user with mode `0600`, for example
`.zeus/integrations/credentials.json`. Symlinks, unsafe ownership or permissions,
invalid JSON, and files larger than 64 KiB are rejected. The file contains
references to environment variable names, never literal credentials. Provision
`OLYMP_ZEUS_API_KEY` with a distinct secret in the Zeus service environment and in
Olymp's server-side credential store; configure Olymp's node `api_key_env` to
that variable name. The existing trusted `.env` loading is also supported, with
process environment values taking precedence. Restart Zeus after changing the
file or secret environment; configuration is loaded once at startup.

A file contains 1–32 integrations. IDs match `[a-z][a-z0-9_-]{0,63}`; `admin`
is reserved for the legacy administrator. Environment references match
`[A-Z_][A-Z0-9_]{0,127}`. Each named key must contain 32–512 non-space printable
ASCII characters. IDs, environment references, and key values must be unique;
named keys cannot equal `ZEUS_API_KEY`. Unknown fields, duplicate JSON fields,
missing secrets, and empty, repeated, or unknown permissions fail startup.
These stricter named-key rules do not change existing administrator-key length
requirements for loopback use.

Permissions are independent: grant only the entries an integration needs.
`operator` does not imply `observer` or `diagnostics`, and `diagnostics` does not
imply `observer`. Administrator access remains unrestricted.

| Permission | Routes | Access |
| --- | --- | --- |
| `observer` | `GET /ready`, `/fleet`, `/reconcile/runs`, `/reconcile/runs/<run-id>`, `/messages`, `/messages/<message-id>`, `/messages/capacity` | Readiness and bounded persisted fleet, reconciliation, and message evidence. |
| `diagnostics` | `GET /templates`, `/bots`, `/bots/<bot-id>/logs`, `/bots/<bot-id>/inspect`, `/bots/<bot-id>/diagnostics`, `/bots/<bot-id>/history` | Local paths, configuration metadata, live diagnostics, and redacted logs or lifecycle details. |
| `operator` | `GET /doctor`, `/bots/<bot-id>/status`; `POST /bots`, `/bots/reconcile`, `/bots/<bot-id>/start`, `/bots/<bot-id>/stop`, `/bots/<bot-id>/restart`, `/bots/<bot-id>/reconcile` | Lifecycle controls and status observation that can update state or recover pending intent. |

The same permissions apply to `/v1` aliases. Permissions follow endpoint effects,
not HTTP methods: `GET /bots/<bot-id>/status` can update durable lifecycle state
and remove stale runtime markers, so dashboard observers should use `/fleet`.
`GET /doctor` also requires `operator`: its registry check initializes state and
can migrate an older database.
Unknown route forms are denied to named credentials.

Zeus derives the integration identity from the matching configured credential.
Caller-supplied integration or actor headers cannot choose an identity or grant
permissions. Use a dedicated integration ID and key for each dashboard.

`ZEUS_ALLOW_UNAUTH_READS=1` remains a loopback-only development escape hatch.
Without named credentials it preserves legacy read access, except that
`GET /doctor` and `/bots/<bot-id>/status` now require operator authentication. With
named credentials configured, only `/ready` can use this exception. Fleet and
reconciliation evidence, message receipts and capacity, logs, inspect, live
diagnostics, and lifecycle history always require authentication. Supplying an
invalid or restricted key never falls back to anonymous access. Keep the flag disabled for integrations.

Delete and archive are intentionally CLI-only in the current alpha because they
remove or move local profile directories. Use `zeus bot delete` or
`zeus bot archive` from a trusted local shell.

## Capability Discovery

`GET /capabilities` and `/v1/capabilities` require any valid credential, even
when `ZEUS_ALLOW_UNAUTH_READS=1`. They accept no query parameters. Discovery uses
loaded configuration and package constants without accessing the state database
or probing gateways, refreshing execution state, dispatching jobs, or recovering
operations. Normal request logging still applies.

The response contains:

| Field | Meaning |
| --- | --- |
| `capabilities_version` | Discovery payload version, currently `1`. |
| `api_version` | Route contract family, currently `v1`. |
| `zeus_version` | Running Zeus package version. |
| `schema_version` | Database schema supported by this package, currently `10`; this is not a database readiness result. |
| `integration_id`, `administrator` | Credential-derived caller identity and administrator status. |
| `permissions` | The caller's independent scopes, sorted by name. |
| `endpoints` | Accessible protected routes, sorted by method then path. Public `/health` is omitted. |

Each endpoint contains `method`, canonical unprefixed `path`, required
`permission`, and `mutates_state`. `authenticated` denotes access for any valid
credential; it is not a configurable permission. An observer can discover its
own access but cannot enumerate other integrations or their keys.

`mutates_state=true` identifies possible domain or lifecycle changes, including
`GET /bots/<bot-id>/status` and the initialization/migration performed by
`GET /doctor`. A false value does not promise zero filesystem writes: request
logs and runtime lock bookkeeping can still occur. The endpoint list describes
available access, not current bot health or successful execution of an operation.
The OpenAPI contract supplies stable `operationId` values, permissions, request
and response schemas, and authentication, validation, rate-limit, and service
failure responses. Both advertised server URLs share those definitions.

Dashboard adapters should first retain their supported Zeus version and schema
checks through `/ready`, then use discovery to select features and hide
unavailable controls. Treat unknown discovery versions, fields, or endpoint
entries conservatively; discovery must not bypass a consumer compatibility gate.
For Olymp, update its reviewed OpenAPI fixture from a pinned Zeus commit and
record the fixture checksum before enabling new routes. Keep historical fixtures
and the exact readiness response unchanged, and update fixture comparison tests
to account for additive discovery and permission contracts. Zeus contains no
copy of Olymp's contract fixtures. Olymp's adapter also needs to map
`403 permission_denied` explicitly and keep separate server-side credentials for
monitoring and controls when both are enabled.

## Persisted Operator Evidence

The following observer endpoints always require `x-zeus-api-key`, including
when `ZEUS_ALLOW_UNAUTH_READS=1`. They accept `/v1` aliases. They read existing
state without probing gateways or triggering a reconciliation pass.

| Route | Query parameters | Response |
| --- | --- | --- |
| `GET /reconcile/runs` | `limit`, `before`, `outcome`, `bot_id` | `runs`, `next_before` |
| `GET /reconcile/runs/<run-id>` | `limit`, `after` | `run`, `results`, `next_after` |
| `GET /fleet` | `limit`, `after`, `attention_only`, `stale_after_seconds` | `items`, `next_after`, generation time and freshness settings |

`limit` defaults to 50 and accepts 1–100. Run lists are newest first with run ID
as the tie breaker; `before` is the opaque cursor from `next_before` (at most
2048 characters). `outcome` accepts `running`, `succeeded`,
`completed_with_errors`, or `interrupted`. `bot_id` includes matching single-bot
requests and fleet runs containing the bot. Preserve filters across pages.

Run detail results use ascending zero-based ordinals. Omit `after` for the first
page, then pass the nonnegative integer `next_after` (maximum 2^63−1). Encode
the run identifier as one URL path segment. Unknown runs return
`404 unknown_reconcile_run`. Metadata contains persisted counters and scope;
individual pages validate the selected evidence, not the entire history.

Fleet pages are ordered by bot ID, with `after` an exclusive bot ID. The
`attention_only` filter accepts `true`, `false`, `1`, or `0` and applies before
pagination. `stale_after_seconds` defaults to 120 and accepts 0–86400. Items
include desired/stored state, remaining restart budget, pending intent, the
latest observation, its age and `freshness`, and explicit `attention_reasons`.
Observations from an earlier incarnation of a recreated bot are excluded.
`freshness_source=persisted_reconciliation` and `live_probe=false` explicitly
identify cached evidence; `fresh` does not establish current application health.
See [reconciliation](RECONCILE.md) for attention and clock-skew semantics.

All three routes return `400 invalid_request` for invalid parameters and
`503 not_ready` for unavailable or incompatible stored evidence. Every request
reads one SQLite snapshot; pages requested later may reflect new runs or state.

## Persisted Message Receipts and Capacity

These routes require `observer` permission or the administrator key, including
when `ZEUS_ALLOW_UNAUTH_READS=1`. The `/v1` aliases have the same behavior.
Observer access covers all stored receipts; `bot_id` is a filter, not a separate
authorization boundary.

| Route | Query parameters | Response |
| --- | --- | --- |
| `GET /messages` | `bot_id`, `limit`, `before` | `items`, `next_before` |
| `GET /messages/<message-id>` | None | One public receipt |
| `GET /messages/capacity` | None | Receipt admission capacity and storage observations |

Every request opens existing schema-10 storage read-only and reads one SQLite
snapshot. Reads do not initialize or migrate missing/incompatible storage,
dispatch or retry jobs, refresh Hermes execution status, cancel runs, recover
operations, or change stored receipts. Normal API access logging still applies;
API startup retains its existing initialization behavior.

`limit` defaults to 50 and accepts 1–100. Results are newest first by `created_at`,
then `message_id` descending. Pass a non-null `next_before` unchanged as the next
page's `before`, preserving `bot_id`; the cursor is an existing 32-character
lowercase hexadecimal message ID and is exclusive. An unknown cursor or one
outside the selected bot filter returns `400 invalid_cursor`. Malformed cursor
syntax returns `400 invalid_request`. Pages use separate snapshots, so later
pages may reflect intervening writes. Archived receipts remain listed and
addressable by ID. A valid missing detail ID returns `404 unknown_message`.

A public receipt has exactly these fields: `message_id`, `bot_id`,
`dispatch_state`, `run_id`, `run_status`, `created_at`, `updated_at`,
`retry_before`, `last_checked_at`, `cancel_requested_at`, `released_at`,
`archived_at`, and `error_code`. All timestamps are ISO 8601 UTC values; optional
observations and intents are `null` when absent. `dispatch_state` is `unknown`,
`accepted`, or `rejected`. A stored `prepared` receipt is reported as `unknown`
without modifying it. Run IDs and statuses are absent until acceptance, and
accepted run status is the last persisted observation, not a live check.

`retry_before` is informational; it conveys no retry authority.
`cancel_requested_at` records intent and `released_at` records a local admission
decision; neither proves that upstream execution stopped. Responses exclude
prompts, outputs, gateway endpoints, credentials, fingerprints, upstream keys,
idempotency keys, attempt leases, and storage versions. Stored error codes use
a fixed allowlist; free-form execution errors are not exposed. The complete
field types, nullable values, and status enums are in `docs/openapi.json`.

Capacity returns `limit` (currently 10000), `used` (unarchived receipts),
`remaining` (`max(0, limit - used)`), `total`, `archived`, `blocking`, `status`,
`database_bytes`, `wal_bytes`, and `filesystem_free_bytes`. Completed and rejected
receipts still count as used until archived. `blocking` counts unreleased
unknown/prepared receipts and accepted runs whose stored status is nonterminal.
The capacity status is `ok` below 80% used, `warning` at 80%, `critical` at 95%,
and `full` at or above the limit. Reading capacity does not reserve it.

Counts cover all retained history and are exact within the SQLite snapshot.
Capacity uses a cooperative two-second budget for SQLite work, lock waiting,
and receipt validation; expiration returns `503 message_read_budget_exceeded`
without partial totals. Filesystem observations are separate from the snapshot,
can change concurrently, and are `null` if unavailable; absent WAL files report
zero bytes. This budget is not a hard deadline for filesystem calls.

Unavailable, corrupt, or incompatible receipt storage returns
`503 message_store_unavailable`. Invalid or repeated query parameters return
`400 invalid_request`. Error messages never echo raw query values, database
paths, or stored exception text. These endpoints observe the existing durable
storage; they add no message mutation API or schema migration.

Olymp's follow-up is to add these routes to its server-side allowlist and
refresh its reviewed contract fixture, then render cached status and nullable
capacity values explicitly. Preserve its readiness/version checks and expose
permission denials without falling back to an administrator credential.

## Live Gateway Diagnostics

`GET /bots/<bot-id>/diagnostics` (also `/v1/bots/<bot-id>/diagnostics`) always
requires `x-zeus-api-key` with `diagnostics` permission (or the administrator
key) and accepts no query parameters. It performs one
bounded request to the launch-recorded Hermes 0.21 loopback API. The response
contains `bot_id`, `observed_at`, `status`, `reason`, `process` (`pid`, `verified`),
and `health` (a validated subset of Hermes's detailed readiness and counters,
or `null`). It does not reconcile, recover pending operations, initialize
state, signal processes, or update stored lifecycle observations.

| `status` | Meaning |
| --- | --- |
| `ok` | The same owned gateway generation returned healthy detailed checks. |
| `degraded` | The same gateway responded, but Hermes reports degraded readiness. |
| `unavailable` | Credentials, runtime compatibility, or the health request prevented a valid observation. |
| `not_running` | No recorded live gateway was observed. |
| `unverified` | Ownership is unproven, an operation is pending, or state changed during the probe. |
| `not_configured` | The recorded launch has no supported readiness endpoint. |

An observed bot returns HTTP `200` even when its diagnostic status is not `ok`;
clients must inspect `status` and `reason`. Invalid parameters return `400`,
unknown bots `404 unknown_bot`, and unavailable state `503 not_ready`.
`observed_at` timestamps this check; a later request can observe different state.
No raw Hermes logs, configuration, free-form error details, or API credentials
are returned. See [operations](OPERATIONS.md#live-gateway-diagnostics) for
configuration and the limits of upstream readiness checks.

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
`unknown_template`, `unknown_reconcile_run`, `missing_api_key`, `invalid_api_key`,
`permission_denied`, `invalid_cursor`, `unknown_message`,
`message_store_unavailable`, `message_read_budget_exceeded`,
`unsupported_media_type`, `method_not_allowed`, `bot_locked`, `bot_exists`,
`bot_running`, `bot_replace_failed`, `bot_delete_failed`, `bot_archive_failed`,
`auth_rate_limited`, `mutation_rate_limited`, `reconcile_locked`,
`idempotency_key_conflict`, `idempotency_in_progress`,
`idempotency_indeterminate`, `idempotency_response_too_large`,
`idempotency_store_unavailable`,
`server_busy`, `client_connection_limited`, `server_draining`, `not_ready`, and
`internal_error`.

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
- Zeus serves at most `ZEUS_API_MAX_CONCURRENT_REQUESTS` active requests, at most
  `ZEUS_API_MAX_CONNECTIONS_PER_CLIENT` connections per immediate TCP peer address, and disconnects clients
  that do not complete a request within `ZEUS_API_REQUEST_TIMEOUT_SECONDS`. Saturated servers
  return `503` with `error.code=server_busy` (or `client_connection_limited` when one peer
  exceeds its share) and `Retry-After: 1`.
- Zeus does not trust forwarded client-address headers. When a reverse proxy connects over
  loopback, all proxied callers share the proxy peer's connection bucket. Enforce source-specific
  limits at the trusted proxy and, when necessary, raise Zeus's peer limit up to the global limit.
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
bucket; once exhausted they return `429 auth_rate_limited`. If no server credential
is configured, requests return `503 missing_api_key` and consume nothing. Valid credentials
with insufficient permissions return `403 permission_denied`, consume neither
authentication nor mutation capacity, and create no idempotency record.

An authorized recognized mutation consumes mutation capacity before body
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

Named integrations have separate replay namespaces derived from their stable
configured IDs. The same `Idempotency-Key` used by two integration IDs, or by an
integration and the administrator, cannot replay or conflict with the other's
record. Rotating a secret while retaining its integration ID preserves its
existing replay records and unresolved-claim guarantees. Never reuse an ID for a
different integration: it inherits that ID's retained records. The administrator
keeps the original key-hash namespace, so pre-existing retries remain valid.
Caller-supplied identity headers cannot alter the namespace.

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
`auth_outcome`, `integration_id`, and `idempotency_outcome`. Authentication outcomes are the
bounded values `not_checked`, `not_required`, `authenticated`, `missing`,
`rejected`, `forbidden`, `unconfigured`, and `allowed_unauthenticated`. Idempotency outcomes
are bounded to `not_applicable`, `claimed`, `replayed`, `conflict`,
`in_progress`, `indeterminate`, and `unavailable`. An unexpected exception also emits a correlated `api.error`
record with `schema_version` `1`, `level` `error`, a bounded generic
`error_type`, and a generic `message`; it never includes a traceback or raw
exception text.

`integration_id` is the credential-derived ID (including `admin`) for both
successful authentication and permission denials, or `null` when no credential
was authenticated. Correlate lifecycle events through the same `request_id`;
this access-log attribution is best effort, not a durable per-integration audit
trail.

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
10, and executes `SELECT 1`; it does not inspect or start bots. A stopped bot does
not make Zeus unready.

The route requires `observer` permission or the administrator key. It requires
`x-zeus-api-key` unless loopback-only development explicitly enables
`ZEUS_ALLOW_UNAUTH_READS=1`. Query parameters are rejected before the database
probe.

Success returns:

```json
{"schema_version":10,"status":"ready"}
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
`running` only after the Hermes `/health` response is ready. This route requires
`operator` permission or the administrator key, including when development
unauthenticated reads are enabled. It can recover pending intent without
launching, update stored lifecycle state, and remove proven stale markers.
Use `/fleet` for read-only persisted observations.

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
at most one recovery effect per bot per pass. Status never launches or signals
to enforce desired state, but can still update records and recover pending
intent, so it also requires operator permission. Pending restarts backed
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
