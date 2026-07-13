# Fresh VPS Test

Use this runbook to verify Zeus on a clean Debian or Ubuntu VPS with a real Hermes Agent install.

## What This Proves

- Zeus installs from a fresh checkout.
- The local Python gates pass on the VPS.
- Hermes is available on `PATH`.
- Zeus can render Hermes profiles for every built-in template.
- `hermes -p <bot-id> doctor` accepts the rendered profiles.
- Optional gateway startup exercises `hermes gateway run` under Zeus supervision.
- Optional oneshot prompting can exercise real async delegation behavior with live model credentials.
- The local Zeus API binds to loopback and handles health, doctor, and bot creation.

## Threat Model

The VPS test downloads and executes the official Hermes installer only when `ZEUS_VPS_INSTALL_HERMES=1` is set. That crosses the network boundary and trusts the Hermes installer HTTPS endpoint. Run it only on a disposable host or after reviewing the downloaded installer saved in the evidence directory.

Do not put provider tokens in command history. Configure Hermes credentials through Hermes' own setup flow or a secure environment mechanism. Review `.tmp/fresh-vps-verify/.../run.log` before sharing it, because Hermes tools may print environment-specific diagnostics.

## Fresh Host Flow

Clone or copy this repository onto the VPS, then run from the repository root:

```bash
ZEUS_VPS_INSTALL_PACKAGES=1 \
ZEUS_VPS_INSTALL_HERMES=1 \
bash scripts/fresh_vps_verify.sh
```

This installs basic Debian/Ubuntu packages, creates `.venv/`, installs Zeus editable, installs Hermes if missing, runs the local gates, checks Hermes, renders all templates, and runs an API smoke test.

To also start a real Hermes gateway for the default real-Hermes bot:

```bash
ZEUS_VPS_INSTALL_PACKAGES=1 \
ZEUS_VPS_INSTALL_HERMES=1 \
ZEUS_VPS_START_GATEWAY=1 \
bash scripts/fresh_vps_verify.sh
```

Gateway startup may require provider and messaging credentials, depending on the selected Hermes profile and enabled integrations.

## Async Delegation Probe

After configuring Hermes credentials, pass a prompt that asks Hermes to delegate background work:

```bash
ZEUS_VPS_ASYNC_PROMPT='Spawn two background delegate tasks, wait for their results, and summarize both results.' \
bash scripts/fresh_vps_verify.sh
```

This uses the Zeus-rendered `vps-coder` profile:

```bash
HERMES_HOME="$PWD/.zeus-vps-multi/hermes" hermes -p vps-coder -z "$ZEUS_VPS_ASYNC_PROMPT"
```

The pass criteria are:

- Hermes accepts the Zeus-rendered profile.
- The prompt completes without a config/schema error.
- The logs show bounded background delegation behavior.
- `zeus bot stop` can still stop a gateway cleanly after async work.

## Evidence

The script writes logs under:

```text
.tmp/fresh-vps-verify/<timestamp>/
```

Important files:

- `run.log`: full command transcript, including `git rev-parse HEAD` and `git status --short` when run from a Git checkout.
- `hermes-install.sh`: downloaded installer, when Hermes installation is enabled.
- `zeus-api.log`: API server log from the loopback smoke test.

Runtime state is created under ignored workspace directories such as `.zeus-real-hermes-check/`, `.zeus-vps-multi/`, and `.zeus-vps-api/`.

Clean up after collecting evidence:

```bash
make clean-vps
```
