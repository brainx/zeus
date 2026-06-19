# Operations

## Backup

Back up `ZEUS_STATE_DIR` regularly. For the sample systemd deployment, that is `/var/lib/zeus` and includes the SQLite registry, rendered Hermes profiles, PID markers, and profile logs.

```bash
sudo tar -czf zeus-state-$(date -u +%Y%m%dT%H%M%SZ).tar.gz -C /var/lib zeus
```

Back up `/etc/zeus/zeus.env` separately in a secret store. It may contain `ZEUS_API_KEY` and provider keys such as `DEEPSEEK_API_KEY`.

## Logs

Use the API service journal for server startup and request failures:

```bash
sudo journalctl -u zeus-api -f
```

Use Zeus for bot gateway logs:

```bash
zeus bot logs coder
```

Profile logs are also stored under `$ZEUS_STATE_DIR/hermes/profiles/<bot-id>/logs/`.

## Upgrade

```bash
cd /opt/zeus
sudo -u zeus git fetch --tags origin
sudo -u zeus git checkout v0.1.1
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
ownership marker and, on Linux, the live command line. Hermes owns cleanup of any
children it starts. If the gateway does not exit before the grace period, Zeus
marks the bot failed and does not send SIGKILL by default.

## Audit Log

Lifecycle mutations append JSONL audit events to
`$ZEUS_STATE_DIR/logs/audit.jsonl`. Events include bot creation, start, stop,
and reconcile restart scheduling or startup. Audit entries intentionally exclude
environment maps and redact secret-like fields before writing.
