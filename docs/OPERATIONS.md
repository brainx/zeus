# Operations

## Backup

Back up `ZEUS_STATE_DIR` regularly. For the sample systemd deployment, that is
`/var/lib/zeus` and includes the SQLite registry, rendered Hermes profiles, PID
markers, audit events, and profile logs.

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

Take the SQLite and state-tree backups above before upgrading. If a migration or
startup fails after an upgrade, leave Zeus stopped, capture recent logs, and keep
the failed state for inspection:

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

For the sample systemd deployment, install a logrotate policy like:

```logrotate
/var/lib/zeus/logs/*.log /var/lib/zeus/logs/*.jsonl {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
    create 0640 zeus zeus
}
```

Use `copytruncate` because Zeus and supervised processes may keep log file
descriptors open. Audit JSONL can contain sensitive operational metadata, so
keep rotated files readable only by the service user and operator group.

## Upgrade

```bash
cd /opt/zeus
sudo -u zeus git fetch --tags origin
sudo -u zeus git checkout v0.1.4
sudo -u zeus ./.venv/bin/python -m pip install -e .
sudo -u zeus env PATH="/opt/zeus/.venv/bin:$PATH" sh scripts/test.sh
sudo -u zeus env PATH="/opt/zeus/.venv/bin:$PATH" sh scripts/repo_check.sh
sudo systemctl restart zeus-api
```

Run `zeus doctor --strict` after upgrades on hosts where Hermes is expected to be installed and usable.

## Environment Isolation

Hermes child processes receive a minimal environment by default plus variables
rendered into the bot profile `.env`. Zeus does not pass the full API service or
operator shell environment to child processes.

To pass selected host variables, set an explicit allowlist:

```dotenv
ZEUS_ENV_PASSTHROUGH=HTTP_PROXY,HTTPS_PROXY,NO_PROXY
```

Keep the allowlist empty unless the Hermes process needs those values.

## Restart Policy

The sample systemd unit restarts the Zeus API with `Restart=on-failure` and `RestartSec=5s`. Bot gateway processes are supervised by Zeus itself; use `zeus bot restart <bot-id>` for a controlled stop, ownership check, and clean start.

Bots default to a manual restart policy. For bots that should recover from unexpected gateway exit, create them with:

```bash
zeus bot create coder \
  --template coding-bot \
  --restart-policy on-failure \
  --restart-backoff-seconds 5 \
  --restart-max-attempts 5
```

Run `zeus bot reconcile [bot-id]` from an operator shell, cron, or systemd timer to health-check recorded PIDs and restart eligible bots with exponential backoff. Manual `zeus bot stop <bot-id>` resets restart state and does not respawn the bot.

For first-class scheduling, install `systemd/zeus-reconcile.service` and
`systemd/zeus-reconcile.timer` as described in `docs/RECONCILE.md`.

## Process Shutdown

Zeus sends SIGTERM to the recorded Hermes gateway PID only after checking the PID
ownership marker and the live command line on supported platforms. Hermes owns
cleanup of any children it starts. If the gateway does not exit before the grace
period, Zeus marks the bot failed and does not send SIGKILL by default.

For unattended hosts where hard shutdown is acceptable after the graceful timeout,
set:

```dotenv
ZEUS_STOP_KILL_AFTER_TIMEOUT=1
```

Keep the default `0` when operators should inspect stuck gateways before sending
SIGKILL.

## Audit Log

Lifecycle mutations append JSONL audit events to
`$ZEUS_STATE_DIR/logs/audit.jsonl`. Events include bot creation, start, stop,
and reconcile restart scheduling or startup. Audit entries intentionally exclude
environment maps and redact secret-like fields before writing.
