# Reconcile Scheduling

`zeus bot reconcile` first recovers any pending desired-state intent under the
per-bot locks, then checks recorded gateway PIDs and enforces desired running
for bots whose `restart_policy` is `on-failure`. It is designed to be run
repeatedly by an operator, cron, or the bundled systemd timer.

Each invocation creates a durable schema-v6 run and persists one ordered result
per processed bot. Fleet passes snapshot bot IDs in sorted order, hold one fleet
lock, and continue after bot-scoped failures. Previously committed bot changes
are not rolled back when a later bot reports an error. Healthy no-op results are
recorded without adding lifecycle-ledger noise.

## Recovery Semantics

Pending start/restart with an exact owned schema-v3 marker is adopted and
finalized without a duplicate launch. When the marker is absent, reconcile
makes at most one launch attempt per bot per pass using the persisted operation
and revision. Pending stop continues one strictly verified schema-v3 stop
attempt; an already-dead schema-v3 process is finalized without signaling.
Restart recovery stops the prior exact schema-v3 generation in one pass and
launches the pending generation on a later pass. A pending stop or restart that
still has a schema-v2 or legacy marker fails closed: reconcile leaves the
marker, recorded PID, and pending intent unchanged and requires an operator to
resolve the prior process manually.

Operation, revision, PID, command, or process-start fingerprint mismatch fails
closed with an action-required result. Zeus does not adopt, signal, kill, or
delete ambiguous evidence. `zeus bot status` is observation-only: it can
finalize safe observations but never launches or signals to enforce desired
state.

Completing an already-persisted operator intent is not a policy restart. After
that intent completes, later process death under the manual restart policy
returns `manual policy: not restarting`; an operator must issue start or
restart explicitly.

## Install The Timer

The sample service assumes the same layout as `systemd/zeus-api.service`:

- repository checkout in `/opt/zeus`
- virtual environment in `/opt/zeus/.venv`
- runtime state in `/var/lib/zeus`
- environment file at `/etc/zeus/zeus.env`

```bash
sudo cp systemd/zeus-reconcile.service /etc/systemd/system/zeus-reconcile.service
sudo cp systemd/zeus-reconcile.timer /etc/systemd/system/zeus-reconcile.timer
sudo systemctl daemon-reload
sudo systemctl enable --now zeus-reconcile.timer
```

Check the timer and recent reconcile runs:

```bash
systemctl list-timers zeus-reconcile.timer
sudo journalctl -u zeus-reconcile.service -n 100
```

## CLI Usage

Run a full reconcile pass:

```bash
zeus bot reconcile
```

Run one bot:

```bash
zeus bot reconcile coder
```

Use JSON output for automation:

```bash
zeus bot reconcile --json
```

Opt in to the persisted run summary:

```bash
zeus bot reconcile --summary
zeus bot reconcile coder --summary --json
```

Summary output includes the run ID, scope, timestamps, final outcome, exact
counts, and ordered per-bot results. Existing output remains the default. The
matching API forms are `POST /bots/reconcile?summary=1` and
`POST /bots/<bot-id>/reconcile?summary=1`; other `summary` values and duplicates
are rejected.

Force an eligible restart now instead of waiting for `next_restart_at`:

```bash
zeus bot reconcile coder --force
```

Reset restart backoff before reconciling:

```bash
zeus bot reconcile coder --reset-restart
```

`--force` still respects `restart_max_attempts`. Use `--reset-restart` only when
an operator has reviewed the failure and wants to allow a new retry budget.

Reconcile exits successfully when every bot is healthy, stopped intentionally,
scheduled for restart, or waiting for its persisted backoff deadline. It exits
nonzero for terminal operational failures such as unverifiable ownership,
exhausted restart attempts, or a failed restart launch, so cron and systemd can
surface action-required states.

Fleet reconciliation is serialized by `$ZEUS_STATE_DIR/locks/reconcile.lock`.
A concurrent fleet invocation returns a controlled lock error. Errors scoped to
one bot are persisted and do not stop later bots; process-level interrupts remain
fatal. Pending-only work is successful, while `action_required` or `error`
results make the summary command exit nonzero. A completed API summary still uses
HTTP 200 and reports `completed_with_errors` in the body.

Zeus is responsible for reconciliation on one host. Cross-host scheduling,
rollout policy, and approvals remain the responsibility of
[Olymp](https://github.com/brainx/olymp).
