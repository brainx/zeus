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

The VPS test downloads the official Hermes installer only when `ZEUS_VPS_INSTALL_HERMES=1` is set. Remote bootstrap also requires `ZEUS_VPS_HERMES_INSTALLER_SHA256` to contain the exact 64-hex-character SHA-256 digest of an installer you reviewed. The script verifies the downloaded bytes with a constant-time comparison and refuses to execute a missing, malformed, or mismatched digest. This still crosses the network boundary, so use a digest obtained through a trusted review process and run the bootstrap only on a disposable host.

Do not put provider tokens in command history. Configure Hermes credentials through Hermes' own setup flow or a secure environment mechanism. The API smoke key is generated ephemerally by default; authenticated curl commands use a redacted transcript label and receive the key through standard input instead of an argument. Review `.tmp/fresh-vps-verify/.../run.log` before sharing it, because Hermes tools may print environment-specific diagnostics.

`ZEUS_VPS_ASYNC_PROMPT` is also replaced by a fixed label in the transcript. Hermes still receives that operator-supplied prompt through its established `-z <prompt>` argument, so it may be visible to local process inspection while that optional probe runs.

## Fresh Host Flow

Clone or copy this repository onto the VPS, then run from the repository root:

```bash
ZEUS_VPS_HERMES_INSTALLER_SHA256='<64-hex SHA-256 of the reviewed installer>' \
ZEUS_VPS_INSTALL_PACKAGES=1 \
ZEUS_VPS_INSTALL_HERMES=1 \
bash scripts/fresh_vps_verify.sh
```

Obtain the pinned digest separately: download the installer without executing it, review the saved file, and calculate its SHA-256 with a trusted local tool such as `sha256sum`. The verifier never learns or trusts a digest from the download endpoint itself.

The command installs basic Debian/Ubuntu packages, creates `.venv/`, installs Zeus editable, installs the digest-verified Hermes payload if missing, runs the local gates, checks Hermes, renders all templates, and runs an API smoke test.

On a minimal supported apt host where `python3` is not yet available, `ZEUS_VPS_INSTALL_PACKAGES=1` permits a minimal Python 3 prerequisite install before the private evidence log can be initialized. That early package-manager output is console-only; the normal package step is still recorded afterward. Without that explicit package-bootstrap opt-in, the verifier fails with a prerequisite error.

To also start a real Hermes gateway for the default real-Hermes bot:

```bash
ZEUS_VPS_HERMES_INSTALLER_SHA256='<64-hex SHA-256 of the reviewed installer>' \
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

The script writes logs under a workspace-relative directory with mode `0700`:

```text
.tmp/fresh-vps-verify/<timestamp>/
```

Important files:

- `run.log`: command transcript, including `git rev-parse HEAD` and `git status --short` when run from a Git checkout; sensitive invocations use fixed redacted labels.
- `hermes-install.sh`: downloaded and digest-verified installer, when Hermes installation is enabled.
- `zeus-api.log`: API server log from the loopback smoke test.

Evidence files use mode `0600`. The verifier rejects absolute, escaping, symlinked, or otherwise unsafe evidence paths instead of changing permissions on their targets. `ZEUS_VPS_LOG_DIR` must remain a workspace-relative scratch directory.

Runtime state is created under ignored workspace directories such as `.zeus-real-hermes-check/`, `.zeus-vps-multi/`, and `.zeus-vps-api/`.

Clean up after collecting evidence:

```bash
make clean-vps
```
