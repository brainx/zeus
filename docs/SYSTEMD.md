# Systemd Deployment

Use `systemd/zeus-api.service` as a starting point for running the local Zeus API on a Debian or Ubuntu VPS. The sample keeps the API on loopback, stores runtime state in `/var/lib/zeus`, and loads secrets from `/etc/zeus/zeus.env`.

## Install

```bash
sudo useradd --system --home /var/lib/zeus --shell /usr/sbin/nologin zeus
sudo mkdir -p /opt/zeus /etc/zeus
sudo install -o zeus -g zeus -m 0750 -d /var/lib/zeus
sudo git clone https://github.com/brainx/zeus.git /opt/zeus
sudo chown -R zeus:zeus /opt/zeus

cd /opt/zeus
sudo -u zeus python3 -m venv .venv
sudo -u zeus ./.venv/bin/python -m pip install -e .
```

Install Hermes separately and set `ZEUS_HERMES_BIN` to its absolute path.

## Environment

Create `/etc/zeus/zeus.env`:

```dotenv
ZEUS_API_KEY=replace-with-a-long-random-value
ZEUS_HERMES_BIN=/usr/local/bin/hermes
ZEUS_HOST=127.0.0.1
ZEUS_PORT=4311
ZEUS_STATE_DIR=/var/lib/zeus
ZEUS_SQLITE_SYNCHRONOUS=FULL
```

Protect the file:

```bash
sudo chown root:zeus /etc/zeus/zeus.env
sudo chmod 0640 /etc/zeus/zeus.env
```

Provider keys such as `DEEPSEEK_API_KEY` can also live in this env file. Do not commit real keys.

Both bundled writer units, `zeus-api.service` and
`zeus-reconcile.service`, select `ZEUS_SQLITE_SYNCHRONOUS=FULL`. Keep the
setting consistent for every process that writes `/var/lib/zeus/zeus.db`,
including manual CLI and doctor commands. After changing the mode, restart both
writer units so newly opened connections receive it:

```bash
sudo systemctl restart zeus-api zeus-reconcile.service
```

FULL applies to SQLite commits only and can add commit latency. It does not make
rendered profiles, PID markers, locks, or audit JSONL writes power-loss atomic;
retain the backup plan in [Operations](OPERATIONS.md).

Leave `ZEUS_ENV_PASSTHROUGH` unset unless Hermes needs selected proxy or
certificate variables from the service environment. Profile `.env` files remain
the preferred place for provider keys used by a bot.

## Service

```bash
sudo install -m 0644 systemd/zeus-api.service /etc/systemd/system/zeus-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now zeus-api
sudo systemctl status zeus-api
curl -fsS http://127.0.0.1:4311/health
```

Use `journalctl -u zeus-api -f` for API logs. Keep the service loopback-only unless it is placed behind a TLS-terminating reverse proxy with authentication and tight firewall rules.

## Reconcile Timer

Install the reconcile timer when bots use `restart_policy = "on-failure"` and
should be recovered without manual operator commands:

```bash
sudo install -m 0644 systemd/zeus-reconcile.service /etc/systemd/system/zeus-reconcile.service
sudo install -m 0644 systemd/zeus-reconcile.timer /etc/systemd/system/zeus-reconcile.timer
sudo systemctl daemon-reload
sudo systemctl enable --now zeus-reconcile.timer
```

See `docs/RECONCILE.md` for reconcile semantics and timer operations.

## Hardening Notes

The sample unit enables `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`, and writes only to `/var/lib/zeus`. If a Hermes terminal backend needs extra host access, loosen the smallest required directive and document why.

Zeus stops bot gateways by sending SIGTERM to verified gateway PIDs. Hermes is
responsible for cleaning up its own child processes; Zeus marks a gateway failed
instead of force-killing it when graceful shutdown times out.
