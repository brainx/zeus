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
sudo -u zeus git checkout v0.1.0
sudo -u zeus ./.venv/bin/python -m pip install -e .
sudo -u zeus env PATH="/opt/zeus/.venv/bin:$PATH" sh scripts/test.sh
sudo -u zeus env PATH="/opt/zeus/.venv/bin:$PATH" sh scripts/repo_check.sh
sudo systemctl restart zeus-api
```

Run `zeus doctor --strict` after upgrades on hosts where Hermes is expected to be installed and usable.

## Restart Policy

The sample systemd unit restarts the Zeus API with `Restart=on-failure` and `RestartSec=5s`. Bot gateway processes are supervised by Zeus itself; use `zeus bot restart <bot-id>` for a controlled stop, ownership check, and clean start.

Automatic bot respawn policies are intentionally not enabled in v0.1.x. Until restart policies land, use systemd for the API process and explicit Zeus lifecycle commands for bot gateways.
