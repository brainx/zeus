# Systemd Deployment

Use `systemd/zeus-api.service` as a starting point for running the local Zeus API on a Debian or Ubuntu VPS. The sample keeps the API on loopback, stores runtime state in `/var/lib/zeus`, and loads secrets from `/etc/zeus/zeus.env`.

## Install

```bash
sudo useradd --system --home /var/lib/zeus --shell /usr/sbin/nologin zeus
sudo mkdir -p /opt/zeus /etc/zeus /var/lib/zeus
sudo git clone https://github.com/brainx/zeus.git /opt/zeus
sudo chown -R zeus:zeus /opt/zeus /var/lib/zeus

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
```

Protect the file:

```bash
sudo chown root:zeus /etc/zeus/zeus.env
sudo chmod 0640 /etc/zeus/zeus.env
```

Provider keys such as `DEEPSEEK_API_KEY` can also live in this env file. Do not commit real keys.

## Service

```bash
sudo install -m 0644 systemd/zeus-api.service /etc/systemd/system/zeus-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now zeus-api
sudo systemctl status zeus-api
curl -fsS http://127.0.0.1:4311/health
```

Use `journalctl -u zeus-api -f` for API logs. Keep the service loopback-only unless it is placed behind a TLS-terminating reverse proxy with authentication and tight firewall rules.

## Hardening Notes

The sample unit enables `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`, and writes only to `/var/lib/zeus`. If a Hermes terminal backend needs extra host access, loosen the smallest required directive and document why.
