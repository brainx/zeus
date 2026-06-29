#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

bot_id="${ZEUS_VERIFY_BOT_ID:-real-hermes-check}"
template_id="${ZEUS_VERIFY_TEMPLATE:-coding-bot}"
state_dir="${ZEUS_VERIFY_STATE_DIR:-.zeus-real-hermes-check}"
api_server_host="${ZEUS_VERIFY_API_SERVER_HOST:-127.0.0.1}"
api_server_port="${ZEUS_VERIFY_API_SERVER_PORT:-4312}"
health_timeout_seconds="${ZEUS_VERIFY_HEALTH_TIMEOUT_SECONDS:-30}"
health_interval_seconds="${ZEUS_VERIFY_HEALTH_INTERVAL_SECONDS:-0.5}"

case "$state_dir" in
  "" | "/" | "." | ".." | /* | ../* | */../*)
    echo "unsafe ZEUS_VERIFY_STATE_DIR: use a workspace-relative scratch directory" >&2
    exit 2
    ;;
esac

case "$api_server_host" in
  127.0.0.1 | localhost) ;;
  *)
    echo "unsafe ZEUS_VERIFY_API_SERVER_HOST: use 127.0.0.1 or localhost" >&2
    exit 2
    ;;
esac

case "$api_server_port" in
  "" | *[!0-9]*)
    echo "unsafe ZEUS_VERIFY_API_SERVER_PORT: use a numeric localhost port" >&2
    exit 2
    ;;
esac

if [ "$api_server_port" -lt 3000 ] || [ "$api_server_port" -gt 5000 ]; then
  echo "unsafe ZEUS_VERIFY_API_SERVER_PORT: use a localhost port between 3000 and 5000" >&2
  exit 2
fi

if ! command -v hermes >/dev/null 2>&1; then
  echo "hermes executable not found on PATH" >&2
  exit 2
fi

cleanup() {
  if [ -d "$state_dir" ]; then
    ZEUS_STATE_DIR="$state_dir" \
      ZEUS_HERMES_BIN="$(command -v hermes 2>/dev/null || printf '%s' hermes)" \
      python3 -B -m zeus.cli bot stop "$bot_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

rm -rf -- "$state_dir"

ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" ZEUS_API_KEY="${ZEUS_VERIFY_API_KEY:-real-hermes-local-check}" python3 -B -m zeus.cli doctor --strict --json
ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot create "$bot_id" --template "$template_id"
ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot doctor "$bot_id"

config_path="$state_dir/hermes/profiles/$bot_id/config.yaml"
test -f "$config_path"
grep -q "max_async_children" "$config_path"

if [ "${ZEUS_VERIFY_START_GATEWAY:-0}" = "1" ]; then
  api_server_key="${ZEUS_VERIFY_API_SERVER_KEY:-}"
  if [ -z "$api_server_key" ]; then
    api_server_key="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  fi
  api_server_passthrough="API_SERVER_ENABLED,API_SERVER_HOST,API_SERVER_PORT,API_SERVER_KEY"
  if [ -n "${ZEUS_ENV_PASSTHROUGH:-}" ]; then
    api_server_passthrough="$ZEUS_ENV_PASSTHROUGH,$api_server_passthrough"
  fi

  API_SERVER_ENABLED=1 \
    API_SERVER_HOST="$api_server_host" \
    API_SERVER_PORT="$api_server_port" \
    API_SERVER_KEY="$api_server_key" \
    ZEUS_ENV_PASSTHROUGH="$api_server_passthrough" \
    ZEUS_STATE_DIR="$state_dir" \
    ZEUS_HERMES_BIN="$(command -v hermes)" \
    python3 -B -m zeus.cli bot start "$bot_id"
  sleep "${ZEUS_VERIFY_GATEWAY_SECONDS:-3}"
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" \
    python3 -B -m zeus.cli bot status "$bot_id" \
    | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] == "running"'
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" \
    python3 -B -m zeus.cli bot inspect "$bot_id" --json \
    | python3 -c '
import json
import sys

payload = json.load(sys.stdin)
ownership = payload["ownership"]
assert ownership["verified"] is True, ownership
assert ownership["reason"] == "ok", ownership
assert ownership["classification"] in {
    "direct-hermes",
    "python-script-wrapper",
    "legacy-marker-valid",
}, ownership
'
  python3 - "$api_server_host" "$api_server_port" "$health_timeout_seconds" "$health_interval_seconds" <<'PY'
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

host = sys.argv[1]
port = int(sys.argv[2])
timeout_seconds = float(sys.argv[3])
interval_seconds = float(sys.argv[4])
if timeout_seconds <= 0:
    raise SystemExit("health timeout must be positive")
if interval_seconds <= 0:
    raise SystemExit("health interval must be positive")

url = f"http://{host}:{port}/health"
deadline = time.monotonic() + timeout_seconds
last_error = "not probed yet"
while True:
    try:
        with urlopen(url, timeout=min(5.0, max(0.2, interval_seconds))) as response:
            body = json.loads(response.read().decode("utf-8"))
        if body.get("status") == "ok" and body.get("platform") == "hermes-agent":
            print(json.dumps(body, sort_keys=True))
            break
        last_error = f"unexpected health payload: {body!r}"
    except (HTTPError, URLError, OSError, json.JSONDecodeError, ValueError) as exc:
        last_error = f"{type(exc).__name__}: {exc}"
    if time.monotonic() >= deadline:
        raise SystemExit(
            f"Hermes /health did not become ready within {timeout_seconds}s; "
            f"last error: {last_error}"
        )
    time.sleep(interval_seconds)
PY
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" \
    python3 -B -m zeus.cli bot stop "$bot_id" \
    | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] == "stopped"'
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" \
    python3 -B -m zeus.cli bot status "$bot_id" \
    | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] == "stopped"'
else
  echo "Skipping gateway start. Set ZEUS_VERIFY_START_GATEWAY=1 to exercise hermes gateway run."
fi

echo "Real Hermes verification completed for $bot_id using $state_dir"
