# Architecture

Zeus is a thin orchestration layer over Hermes Agent profiles. It is maintained by [BrainX](https://github.com/brainx) and interacts with Hermes through documented CLI/profile boundaries.

## Runtime Layout

By default Zeus writes runtime state under `.zeus/`:

```text
.zeus/
  zeus.db
  zeus.pid
  locks/api.lock
  logs/
    api.jsonl
    audit.jsonl
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
- `zeus.templates`: Bundled plus local TOML template discovery with duplicate ID checks.
- `zeus.renderer`: Hermes profile rendering.
- `zeus.state`: SQLite bot projection and authoritative lifecycle ledger.
- `zeus.lifecycle`: Bounded lifecycle event types and recursively redacted details.
- `zeus.request_context`: Locally generated request IDs and normalized route templates.
- `zeus.api_errors`: Transport-neutral API exception classification.
- `zeus.api_request`: Strict path, query, and JSON request parsing.
- `zeus.api_server`: Bounded HTTP concurrency and graceful server lifecycle.
- `zeus.api_logging`: Locked, fail-open, secret-safe API JSONL output.
- `zeus.idempotency`: Key validation and canonical request hashing.
- `zeus.hermes_adapter`: Subprocess command construction for Hermes.
- `zeus.gateway_launcher`: Descriptor-only marker-before-exec helper.
- `zeus.supervisor`: Gateway lifecycle, PID ownership markers, logs, and status.
- `zeus.api`: Local HTTP routes and compatibility facade.
- `zeus.cli`: Operator CLI.
- `zeus.doctor`: Readiness diagnostics.

## Process Lifecycle

1. `zeus bot create` precomputes a profile, stages it under the profiles directory,
   and atomically installs it under `.zeus/hermes/profiles/<bot-id>/`.
2. Zeus takes the per-bot file lock and commits schema-v5 desired state and the
   pending operation before any spawn or signal.
3. Start creates private payload and acknowledgment descriptors and launches
   `zeus.gateway_launcher`; secrets never appear in launcher argv.
4. The launcher atomically writes a schema-v3 marker with operation ID, desired
   revision, command fingerprint, process-start fingerprint, and readiness
   provenance, then acknowledges publication.
5. Only after acknowledgment does the launcher exec
   `hermes -p <bot-id> gateway run` with the same PID and `HERMES_HOME`.
6. Supervisor verifies the marker/process identity and atomically completes the
   intent, projection, and lifecycle ledger event. Marker or acknowledgment
   failure exits before Hermes and leaves recoverable durable state.
7. Stop commits its stopped intent before verifying ownership and signaling;
   SIGTERM/SIGKILL authorization is rechecked against the exact process identity.

Hermes child processes receive a minimal host environment plus profile `.env`
values. Operators can allow specific host variables with `ZEUS_ENV_PASSTHROUGH`.

## Async Delegation

Hermes supports `delegate_task(background=true)` and manages those subagents inside the Hermes process. Zeus configures the cap through rendered profile config:

```yaml
delegation:
  max_async_children: 3
```

Zeus does not poll Hermes background subagents directly. Hermes reinjects completed background delegation results into the originating conversation.

## API Request Observability

Each HTTP request handled by Zeus receives a locally generated request context.
The response exposes its 32-character UUID hex value as `X-Request-ID`; incoming
request IDs are ignored. Only explicit route templates such as `/bots/{bot_id}/start`
are eligible for logging, so raw request targets, queries, and bot IDs never
become route fields.

The optional file sink writes access and unexpected-error records to
`$ZEUS_STATE_DIR/logs/api.jsonl`. It is deliberately fail-open so an unavailable
log path cannot change an API result. Request correlation remains active when
the sink is disabled. Access records use schema version 1 and include bounded
authentication and idempotency outcomes; authentication is classified only at
the API-key boundary and credentials are never copied into the request context.

## Idempotent API Mutations

SQLite schema v4 stores hashed idempotency keys, canonical request hashes,
process-local claim owners, expirations, and bounded serialized responses.
Claims and completions use short `BEGIN IMMEDIATE` transactions; no SQLite
transaction remains open while Supervisor performs lifecycle work. A completed
claim replays the stored result, while an unresolved claim from an earlier
process is `indeterminate` rather than assumed safe to execute again.

## Lifecycle State and Ledger

SQLite schema v5 keeps the current bot row as a projection and the immutable
`lifecycle_events` table as the authoritative lifecycle history. Each event has
an increasing `event_id`, operation and optional API request correlation,
source, action, outcome, before/after status and PID values, bounded error text,
and recursively redacted JSON details. Update and delete triggers make event
rows append-only. Events do not cascade with bot rows, so delete and archive
history remains queryable.

Schema v5 adds `desired_state`, `desired_revision`, and all-or-none pending
operation fields. `converged` is derived: only desired-running/observed-running
or desired-stopped/observed-stopped is converged. Status may repair observation
but never launches or signals; reconcile recovers pending intent and enforces
eligible desired state with at most one effect per bot per pass. Schema-v3
marker operation, revision, PID, command, or process-start mismatch fails closed.

Supervisor lifecycle mutations use the event-aware `StateStore` operations,
which update projection fields and insert the matching event in the same
`BEGIN IMMEDIATE` transaction. The bot row's `last_event_id` points at the event
that produced the current projection. If either the event insert or projection
mutation fails, the entire transaction rolls back; Zeus does not commit one
without the other.

The v2-to-v3 migration is also one transaction. It creates a
`migration.snapshot` event for every existing bot, links `last_event_id`, checks
the projection/event invariant, and advances the schema version only after all
steps succeed. Additive v3-to-v4 and v4-to-v5 upgrades add durable idempotency
and desired/pending intent in forward-only transactions. Databases newer than
schema v6 are rejected rather than downgraded.

`$ZEUS_STATE_DIR/logs/audit.jsonl` remains a best-effort compatibility mirror.
It is written only after the SQLite transaction commits and is not imported into
the v3 ledger. A mirror write failure cannot remove the authoritative event or
fail an already committed transition.
