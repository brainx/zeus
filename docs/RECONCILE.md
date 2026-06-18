# Reconcile Scheduling

`zeus bot reconcile` checks recorded bot gateway PIDs and restarts bots whose
`restart_policy` is `on-failure`. It is designed to be run repeatedly by an
operator, cron, or the bundled systemd timer.

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
