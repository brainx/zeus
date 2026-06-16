#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

bot_id="${ZEUS_VERIFY_BOT_ID:-real-hermes-check}"
template_id="${ZEUS_VERIFY_TEMPLATE:-coding-bot}"
state_dir="${ZEUS_VERIFY_STATE_DIR:-.zeus-real-hermes-check}"

case "$state_dir" in
  "" | "/" | "." | ".." | /* | ../* | */../*)
    echo "unsafe ZEUS_VERIFY_STATE_DIR: use a workspace-relative scratch directory" >&2
    exit 2
    ;;
esac

if ! command -v hermes >/dev/null 2>&1; then
  echo "hermes executable not found on PATH" >&2
  exit 2
fi

cleanup() {
  if [ -d "$state_dir" ]; then
    ZEUS_STATE_DIR="$state_dir" python3 -B -m zeus.cli bot stop "$bot_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

rm -rf -- "$state_dir"

ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli doctor --strict --json
ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot create "$bot_id" --template "$template_id"
ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot doctor "$bot_id"

config_path="$state_dir/hermes/profiles/$bot_id/config.yaml"
test -f "$config_path"
grep -q "max_async_children" "$config_path"

if [ "${ZEUS_VERIFY_START_GATEWAY:-0}" = "1" ]; then
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot start "$bot_id"
  sleep "${ZEUS_VERIFY_GATEWAY_SECONDS:-3}"
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot status "$bot_id"
  ZEUS_STATE_DIR="$state_dir" ZEUS_HERMES_BIN="$(command -v hermes)" python3 -B -m zeus.cli bot stop "$bot_id"
else
  echo "Skipping gateway start. Set ZEUS_VERIFY_START_GATEWAY=1 to exercise hermes gateway run."
fi

echo "Real Hermes verification completed for $bot_id using $state_dir"
