# Operations

## Backup

Back up `ZEUS_STATE_DIR` regularly. For the sample systemd deployment, that is
`/var/lib/zeus` and includes the SQLite registry, rendered Hermes profiles, PID
markers, audit events, durable idempotency records, reconciliation runs/results,
pending desired-state intent, and profile logs.
Keep the state root owned by `zeus:zeus` with mode `0750` or stricter so users
outside the service group cannot traverse it; `zeus doctor` enforces that boundary.

Use SQLite's backup API for the registry so the database snapshot is consistent
even if Zeus is running:

```bash
sudo install -o zeus -g zeus -m 0750 -d /var/lib/zeus/backups
backup_ts="$(date -u +%Y%m%dT%H%M%SZ)"
sudo -u zeus sqlite3 /var/lib/zeus/zeus.db \
  ".backup '/var/lib/zeus/backups/zeus-${backup_ts}.db'"
```

Archive the rest of the state tree separately:

```bash
sudo tar --exclude='zeus/backups' -C /var/lib \
  -czf "/var/lib/zeus/backups/zeus-state-${backup_ts}.tar.gz" zeus
sudo sha256sum \
  "/var/lib/zeus/backups/zeus-${backup_ts}.db" \
  "/var/lib/zeus/backups/zeus-state-${backup_ts}.tar.gz" \
  | sudo tee "/var/lib/zeus/backups/zeus-backup-${backup_ts}.sha256"
```

Back up `/etc/zeus/zeus.env` separately in a secret store. It may contain `ZEUS_API_KEY` and provider keys such as `DEEPSEEK_API_KEY`.

## Restore

Stop scheduled reconciliation and the API before replacing state:

```bash
restore_ts="$(date -u +%Y%m%dT%H%M%SZ)"
sudo systemctl stop zeus-reconcile.timer zeus-reconcile.service zeus-api
sudo mv /var/lib/zeus "/var/lib/zeus.before-restore-${restore_ts}"
```

Restore the archived state tree, then replace the registry with the SQLite
backup:

```bash
sudo tar -C /var/lib -xzf /secure-backups/zeus-state-20260627T120000Z.tar.gz
sudo install -o zeus -g zeus -m 0640 \
  /secure-backups/zeus-20260627T120000Z.db \
  /var/lib/zeus/zeus.db
sudo chown -R zeus:zeus /var/lib/zeus
sudo chmod 0750 /var/lib/zeus
```

Start services and verify the restored host:

```bash
sudo systemctl start zeus-api
sudo systemctl start zeus-reconcile.timer
sudo -u zeus env ZEUS_STATE_DIR=/var/lib/zeus \
  /opt/zeus/.venv/bin/zeus doctor --strict
```

If verification fails, stop the services again and move the restored directory
aside before putting `/var/lib/zeus.before-restore-${restore_ts}` back.

## Migration Rollback

The v2-to-v3 migration is one-way and creates the immutable lifecycle ledger.
Schema v4 through schema v6 migrations are forward-only. V4 adds durable
idempotency claims and responses; v5 adds desired state, pending lifecycle
intent, and migration snapshots; v6 adds persisted reconciliation runs and
ordered per-bot results. Take a pre-v4/v5/v6 SQLite backup and state-tree
backup before upgrading; this is the required pre-migration database backup.
Older binaries cannot use schema v6, so rolling back
the executable requires restoring that backup. Zeus rejects a newer database
rather than attempting a down migration; never hand-edit schema state.

If a migration or startup fails after an upgrade, leave Zeus stopped, capture
recent logs, and keep the failed state for inspection:

```bash
sudo systemctl stop zeus-reconcile.timer zeus-reconcile.service zeus-api
sudo journalctl -u zeus-api -n 200 --no-pager
failed_ts="$(date -u +%Y%m%dT%H%M%SZ)"
sudo mv /var/lib/zeus "/var/lib/zeus.failed-migration-${failed_ts}"
```

Check out and reinstall the previous known-good Zeus version, restore the
pre-upgrade database and state tarball, then start the services and run
`zeus doctor --strict`. Do not hand-edit `zeus.db` during rollback unless the
backup is unavailable and the recovery plan has been reviewed.

## Logs

Use the API service journal for server startup and request failures:

```bash
sudo journalctl -u zeus-api -f
```

Use Zeus for bot gateway logs:

```bash
zeus bot logs coder
zeus bot inspect coder --json
```

Profile logs are also stored under `$ZEUS_STATE_DIR/hermes/profiles/<bot-id>/logs/`.
`zeus bot inspect` reports bot metadata, expected profile-file presence, safe PID
marker metadata, live command verification status, ownership reason/classification,
and redacted recent logs without printing `.env` contents.

### API request log

`ZEUS_API_LOG_ENABLED=1` is the default and writes structured access records to
`$ZEUS_STATE_DIR/logs/api.jsonl`. Set it to `0` to disable only the file sink;
every response still receives an `X-Request-ID`.

The API logger enforces mode `0700` on `$ZEUS_STATE_DIR/logs` and `0600` on
`api.jsonl`, including an existing file. Each handled application request writes
one schema-v1 `api.access` record containing a UTC timestamp, `info` level,
normalized route template, request ID, method, status, error code, duration,
bounded authentication outcome, and the later-compatible idempotency outcome.
Unexpected exceptions add a correlated schema-v1 `api.error` record at `error`
level with generic bounded error information.

The API log excludes API keys, authorization headers, request and response
bodies, raw queries, raw bot IDs, client addresses and ports, forwarded-for
values, environment maps, idempotency keys, and raw exception tracebacks. File,
permission, and serialization failures are fail-open and do not change the HTTP
response. Monitor filesystem health separately because Zeus does not turn a log
write failure into an API failure.

## Lifecycle Coordination

Zeus serializes lifecycle operations per bot with file locks under
`$ZEUS_STATE_DIR/locks/bots/`. This protects separate CLI and API processes from
starting, stopping, restarting, reconciling, or status-mutating the same bot at
the same time. The default wait is 30 seconds:

```dotenv
ZEUS_LOCK_TIMEOUT_SECONDS=30
```

If the lock cannot be acquired, CLI lifecycle commands return a failed JSON
payload and the API returns `409` with `error.code=bot_locked`.

Fleet reconciliation also takes `$ZEUS_STATE_DIR/locks/reconcile.lock`. A second
fleet pass returns `reconcile_locked`; per-bot lifecycle locks still protect each
individual effect. A prior fleet run left `running` by an interrupted process is
marked `interrupted` when the next fleet runner obtains the lock.

Lifecycle intent is persisted before external effects. Reconcile adopts and
finalizes an exact owned marker for pending start/restart, or makes at most one
launch attempt per pass when no marker exists. A pending stop continues one
verified stop attempt, while an already-dead process is finalized without a
signal. Operation, revision, PID, command, or process-start mismatch returns an
action-required result; uncertainty never authorizes adoption, signaling, or
marker deletion.

Pending stop and restart recovery is automatic only for schema-v3 ownership
markers. Schema-v2 and legacy markers fail closed even when their recorded PID
is dead: Zeus preserves the marker, PID projection, and pending intent without
signaling, pathname deletion, or launching. An operator must verify and resolve
the prior process before retrying or repairing the pending lifecycle state.

Bot creation also takes the per-bot lifecycle lock. Reusing an existing bot ID is
intentional-only:

| Existing state | Required action |
| --- | --- |
| `stopped` or `failed` | `zeus bot create <bot-id> --template <template-id> --replace` |
| `starting` or `running` | `zeus bot create <bot-id> --template <template-id> --replace --stop` |
| API equivalent | `POST /bots?replace=1&stop=1` |

Without those flags, Zeus returns `bot_exists` or `bot_running` instead of
silently overwriting a profile or racing a live gateway.

## API Resource Limits

Zeus bounds request concurrency and slow clients so incomplete or excessive connections cannot
consume an unbounded number of worker threads:

```dotenv
ZEUS_API_MAX_CONCURRENT_REQUESTS=32
ZEUS_API_REQUEST_TIMEOUT_SECONDS=10
ZEUS_API_SHUTDOWN_DRAIN_SECONDS=20
```

The concurrency limit accepts values from 1 to 256. The request timeout accepts 0.1 to 300
seconds. When every request slot is occupied, Zeus closes the excess connection after returning a
JSON `503 server_busy` response with `Retry-After: 1`. Timeouts release their slot automatically.
On orderly shutdown, Zeus keeps the listener available only to reject new work with
`503 server_draining` while active requests finish, then closes it when the drain completes or its
deadline expires. The drain setting accepts 0 to 300 seconds. Keep the service manager's stop
timeout longer than the drain deadline; the provided systemd unit allows 30 seconds for the
default 20-second drain. When the deadline expires, shutdown proceeds even if a handler has not
finished, so configure it to cover the longest expected API operation.

The API also limits invalid authentication attempts and validly authenticated
mutations with process-local token buckets:

```dotenv
ZEUS_API_AUTH_FAILURE_RATE_PER_MINUTE=30
ZEUS_API_AUTH_FAILURE_BURST=10
ZEUS_API_MUTATION_RATE_PER_MINUTE=120
ZEUS_API_MUTATION_BURST=30
```

Rates accept 1-6000 per minute; bursts accept 1-1000. These global buckets reset
when the API process restarts and intentionally ignore client IP and forwarded
headers. Valid credentials bypass the failed-auth bucket. Recognized mutations
consume capacity before parsing and idempotency, while rejected capacity creates
no idempotency claim. Every `429` includes an integer `Retry-After`.

## Durable API Replay

Keyed mutations use a local retention window and bounded record capacity:

```dotenv
ZEUS_API_IDEMPOTENCY_RETENTION_SECONDS=86400
ZEUS_API_IDEMPOTENCY_MAX_RECORDS=10000
```

Retention accepts 60-604800 seconds and capacity accepts 100-1000000 records.
Capacity or store failure before execution returns `503`. Expired keys may be
executed again, so callers must not treat the guarantee as permanent. Backups
also preserve replay knowledge; restoring an older backup changes which keyed
operations Zeus knows are complete.

When a rendered profile enables Hermes' local API server with
`API_SERVER_ENABLED=1` and `API_SERVER_PORT=<port>`, Zeus can verify readiness
through `http://127.0.0.1:<port>/health`. Use:

```bash
zeus bot start coder --wait --timeout 30
zeus bot status coder
```

Tune readiness with:

```dotenv
ZEUS_READINESS_TIMEOUT_SECONDS=30
ZEUS_READINESS_INTERVAL_SECONDS=0.5
```

`running` means readiness was confirmed or no readiness probe exists. `starting`
means the gateway process exists but readiness is still pending.

The SQLite registry tracks lifecycle metadata for operator handoff:

| Field | Meaning |
| --- | --- |
| `started_at` | Last time Zeus spawned the Hermes gateway process. |
| `ready_at` | Last time Zeus observed readiness or promoted a live process to running. |
| `stopped_at` | Last time Zeus observed or completed shutdown. |
| `last_exit_code` | Exit code from startup/readiness failures when available. |
| `last_error` | Last lifecycle failure reason intended for operators. |
| `last_transition_reason` | Short reason for the latest lifecycle state update. |

`zeus bot inspect <bot-id> --json` includes these fields under `lifecycle`.

## Lifecycle History

SQLite schema v3 stores immutable lifecycle events as the authority for bot
history. Projection changes made by supervisor lifecycle operations and their
events commit atomically, and `bots.last_event_id` identifies the event that
produced the current projection. If either side fails, neither is committed.

Inspect history locally with:

```bash
zeus bot history coder
zeus bot history coder --limit 100 --before 123
zeus bot history coder --limit 100 --before 123 --json
```

`limit` defaults to 50 and accepts 1 through 1000. Results are newest first.
`before` is an exclusive positive event-ID cursor. JSON output contains
`next_before` when another page exists; use that value as the next `--before`.
History survives bot deletion and archive. A bot ID with neither a current
projection nor any events returns `unknown_bot`.

The API equivalent is
`GET /bots/<bot-id>/history?limit=50&before=123`. It always requires
`x-zeus-api-key`, even when `ZEUS_ALLOW_UNAUTH_READS=1` is enabled. See
`docs/openapi.json` for the machine-readable response and cursor schema.

Use archive when you want a reversible cleanup of an inactive bot profile:

```bash
zeus bot archive coder
zeus bot archive coder --stop
```

Archive moves the rendered profile under `$ZEUS_STATE_DIR/archive/` and removes
the bot from the registry. Use delete for registry cleanup, and add
`--remove-profile` only when the rendered profile should be removed permanently:

```bash
zeus bot delete coder
zeus bot delete coder --stop --remove-profile
```

For the sample systemd deployment, install a logrotate policy like:

```logrotate
/var/lib/zeus/logs/*.log /var/lib/zeus/logs/*.jsonl {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
    create 0600 zeus zeus
}
```

Use `copytruncate` because Zeus and supervised processes may keep log file
descriptors open. JSONL can contain sensitive operational metadata, so keep
rotated files readable only by the service user.

## Upgrade

Use a tag that is already present on the GitHub Releases page. Fetch and verify
the tag before stopping the host, then keep the API and reconciliation scheduler
stopped for the checkout, installation, and verification steps:

```bash
cd /opt/zeus
release_tag=vX.Y.Z
sudo -u zeus git fetch --tags origin
sudo -u zeus git rev-parse --verify "refs/tags/${release_tag}^{commit}"
sudo systemctl stop zeus-reconcile.timer zeus-reconcile.service zeus-api
sudo -u zeus git checkout --detach "${release_tag}"
sudo -u zeus ./.venv/bin/python -m pip install -e .
sudo -u zeus env PATH="/opt/zeus/.venv/bin:$PATH" sh scripts/test.sh
sudo -u zeus env PATH="/opt/zeus/.venv/bin:$PATH" sh scripts/repo_check.sh
sudo systemctl start zeus-api
sudo systemctl start zeus-reconcile.timer
```

If checkout, installation, or verification fails, leave the units stopped and
follow the migration rollback procedure instead of starting a partially upgraded
installation. Run `zeus doctor --strict` after successful upgrades on hosts
where Hermes is expected to be installed and usable.

## Environment Isolation

Hermes child processes receive a minimal environment by default plus variables
rendered into the bot profile `.env`. Zeus does not pass the full API service or
operator shell environment to child processes.

Import bot secrets without putting their values in command arguments:

```bash
zeus bot create coder \
  --template coding-bot \
  --env-from OPENROUTER_API_KEY
```

For every `--env-from NAME`, Zeus reads the process environment first and then
the trusted workspace `./.env`. A present but empty process value fails closed;
it does not fall back to `.env`. Missing and empty errors identify only the
variable name, and imported values are not printed. Keep the trusted source
private with `chmod 0600 .env`. Zeus persists imported values only in the
selected bot profile's `.env`, which Zeus writes with mode `0600`. The legacy
`--env NAME=VALUE` form remains compatible for non-secret values but is unsafe
for secrets because argv can be visible in shell history and process listings.

To pass selected host variables, set an explicit allowlist:

```dotenv
ZEUS_ENV_PASSTHROUGH=HTTP_PROXY,HTTPS_PROXY,NO_PROXY
```

Keep the allowlist empty unless the Hermes process needs those values.

## Restart Policy

The sample systemd unit restarts the Zeus API with `Restart=on-failure` and `RestartSec=5s`. Bot gateway processes are supervised by Zeus itself; use `zeus bot restart <bot-id>` for a controlled stop, ownership check, and clean start.

Bots default to a manual restart policy. Reconcile may finish an already-persisted
operator start/restart after a crash, but later process death under the manual
restart policy is not relaunched. Status never spawns. For bots that should
recover from unexpected gateway exit, create them with:

```bash
zeus bot create coder \
  --template coding-bot \
  --restart-policy on-failure \
  --restart-backoff-seconds 5 \
  --restart-max-attempts 5
```

Run `zeus bot reconcile [bot-id]` from an operator shell, cron, or systemd timer to health-check recorded PIDs and restart eligible bots with exponential backoff. Manual `zeus bot stop <bot-id>` resets restart state and does not respawn the bot.

Every invocation persists one row in `reconcile_runs` and an ordered row in
`reconcile_results` for each processed bot. Fleet runs continue after bot-scoped
lock, ownership, or unexpected errors, but never catch process-level interrupts.
Use `zeus bot reconcile --summary --json` to display the same run ID, timestamps,
outcome, counters, and results. The default output remains unchanged for the
bundled systemd unit and existing automation.

Zeus owns this host-local process safety and evidence. Cross-host rollout policy,
placement, and approvals belong to [Olymp](https://github.com/brainx/olymp), which
can consume the opt-in summary instead of relying on console text.

For first-class scheduling, install `systemd/zeus-reconcile.service` and
`systemd/zeus-reconcile.timer` as described in `docs/RECONCILE.md`.

## Process Shutdown

Zeus sends SIGTERM to the recorded Hermes gateway PID only after checking an
exact, single-link schema-v3 ownership marker and the live command line on
supported platforms. Hermes owns cleanup of any children it starts. If the
gateway does not exit before the grace period, Zeus marks the bot failed and
does not send SIGKILL by default.

Schema-v2 and legacy markers remain readable for compatibility inspection, but
Zeus never signals a process or deletes a marker pathname while either format is
active. Stop and restart return action-required and preserve the marker, PID
projection, and pending intent for manual process resolution. Inspect reports
legacy markers as deprecated. Set `ZEUS_ALLOW_LEGACY_PID_MARKERS=0` after all
managed bots have migrated away from legacy markers.

For unattended hosts where hard shutdown is acceptable after the graceful timeout,
set:

```dotenv
ZEUS_STOP_KILL_AFTER_TIMEOUT=1
```

Keep the default `0` when operators should inspect stuck gateways before sending
SIGKILL.

## Audit Log

The SQLite `lifecycle_events` table is the immutable authority. After an
authoritative lifecycle transaction commits, Zeus makes a best-effort append to
`$ZEUS_STATE_DIR/logs/audit.jsonl` for compatibility with existing tooling.
Mirror failures do not erase the SQLite event or fail an already committed
transition, and the v2-to-v3 migration does not import this intentionally
incomplete JSONL file. Entries exclude environment maps and redact secret-like
fields before writing.
