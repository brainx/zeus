# Operator messaging

`zeus message` submits explicit asynchronous jobs to an already running, owned
Hermes Agent 0.21.0 API gateway. It uses authenticated `/v1/runs` submission,
status and stop operations. The operator chooses every destination and message;
Zeus does not forward bot output or impersonate another bot.

## Enable one profile

Use the `message-bot` template with the pinned Hermes 0.21.0 installation,
its API adapter's `aiohttp` dependency, and Docker available for its terminal
tools. The [verified CI lock](REAL_HERMES_VERIFICATION.md) includes the API
dependency; a core-only Hermes install does not. Import profile-local environment values
from your shell or private project `.env`:

```sh
# Supply OPENROUTER_API_KEY and API_SERVER_KEY through your secret mechanism.
export API_SERVER_ENABLED=1
export API_SERVER_PORT=8642
export ZEUS_MESSAGES_ENABLED=1
zeus bot create --help
zeus bot create coder --template message-bot \
  --env-from OPENROUTER_API_KEY --env-from API_SERVER_KEY \
  --env-from API_SERVER_ENABLED --env-from API_SERVER_PORT \
  --env-from ZEUS_MESSAGES_ENABLED
zeus bot start coder --wait --timeout 30
zeus bot diagnostics coder --json
```

Use a unique available API port per profile and a private randomly generated API
key of at least 16 characters. Messaging accepts literal letters, digits and
`._~+/@%=:,-` in that key, up to 4,096 characters. Keep credentials out of command
arguments and source control. The four messaging/API environment assignments
must use the literal format written by Zeus, without duplicates or interpolation.
Ambient opt-in alone is insufficient.

For an existing profile, explicitly set `agent.max_turns` to an integer from 1
through 100 and `gateway.api_server.max_concurrent_runs` to 1 in `config.yaml`.
The template selects 12 turns and one API run. These values are carried through
the typed template renderer. Restart the gateway after changing its configuration,
SOUL, API port or API key: the launch marker binds the policy used at startup,
and send/retry reject a policy mismatch or an older unstamped marker.

Profiles using a legacy `gateway.json`, a configured `HERMES_MANAGED_DIR`, or
an existing `/etc/hermes` managed overlay are not supported for this opt-in.
This avoids assuming profile limits override administrator policy. Zeus assumes
the installed Hermes code and administrator-controlled startup environment are
trusted; it does not attest arbitrary runtime modifications or listening-socket
ownership.

## Submit, inspect and cancel

```sh
zeus message send coder --file request.txt --request-key incident-104 --json
zeus message list --bot-id coder --limit 20 --json
zeus message status <message-id> --json
zeus message cancel <message-id> --json
```

Input must be a regular UTF-8 file containing nonblank text, at most 16,000
characters and 64 KiB. Use `--file -` to read stdin through EOF. Message text is
not accepted as a shell argument. Submission returns a receipt immediately;
`status` explicitly fetches current output. JSON output escapes terminal control
characters. Use a returned `next_before` cursor with `list --before <cursor>`
to inspect older receipts.

`accepted` means Hermes acknowledged the run. It does not mean the job completed
successfully. Status distinguishes queued, running, waiting for approval,
stopping, completed, failed, cancelled and interrupted runs. Zeus reports
`waiting_for_approval` but cannot answer approval requests or expose their details;
use Hermes's own approval interface or cancel the run. Cancellation is
cooperative and cannot reverse completed tool effects. Hermes permissions,
tools, delegation, providers and their costs still apply. Turn/concurrency limits
are not a hard wall-clock deadline, sandbox or token/spending budget; Hermes can
perform a final wrap-up call beyond the normal iteration limit.

Disabling `ZEUS_MESSAGES_ENABLED` prevents new submissions and retries. Status
and cancellation remain available for acknowledged receipts while the same bot
incarnation, profile, endpoint and API key can be verified. Credential rotation
or deleting/recreating the bot deliberately prevents an old receipt from being
used against a different target. An unavailable gateway can leave its last
persisted run status stale; it is not automatically treated as completed.

## Recovery after an uncertain response

Zeus commits a receipt with SQLite `synchronous=FULL` before submitting the job.
The receipt stores hashes and bounded routing/run metadata, never the input,
output or API key. These writes use FULL even when ordinary Zeus state uses
NORMAL. Receipts survive bot deletion; capacity is 10,000 records, with no
automatic pruning. Back up the database together with private profiles.

A lost response or changed gateway generation leaves an `unknown` receipt. An
interrupted submit can retain `prepared` if it stops before recording its outcome.
Either state blocks another job to that bot incarnation. Inspect the receipt and,
when appropriate, retry the exact original input explicitly:

```sh
zeus message retry <message-id> --file request.txt --json
```

Retries reuse the original Hermes idempotency key and require unchanged input,
target, credentials and policy, plus Hermes's advertised durable idempotency
support. A 30-second attempt lease rejects retries while the prior attempt remains
leased. The initial retry window is half the advertised retention period, capped
at one hour from receipt creation; Hermes must advertise more than 60 seconds of
retention. Retry must occur before `retry_before` and within that same formula
using Hermes's current advertisement, so a shorter advertisement can close the
window earlier. Clock rollback fails closed. Once Zeus records Hermes's
acknowledgement, retry returns the existing receipt without submitting again.

An expired unresolved receipt requires operator investigation through Hermes;
Zeus does not clear it or send a replacement automatically. Repeating `send`
with the same optional request key retrieves the same compatible receipt.
Reusing that key for changed input or a different target is a conflict. If the
first CLI response was lost, `list` recovers the message ID. Preserve the original
input yourself if retry may be needed.

These checks avoid automatic duplicate dispatch, but cannot guarantee exactly-once
external tool effects after a crash or an upstream persistence failure. No message
commands initialize/migrate Zeus state or start/reconcile bots. Schema 8 must
already have been initialized by ordinary startup. There are no new Zeus HTTP
messaging routes in this version.

Before dispatch, Zeus rechecks receipt ownership and leaves the complete two-second
HTTP budget inside its lease and retry window. A local process can still be
suspended between that check and sending bytes; the trusted-host boundary and
Hermes's finite idempotency retention remain part of the recovery limits.
