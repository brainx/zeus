#!/usr/bin/env bash
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
log_dir="${ZEUS_VPS_LOG_DIR:-.tmp/fresh-vps-verify/$timestamp}"
mkdir -p "$log_dir"
log_file="$log_dir/run.log"
exec > >(tee -a "$log_file") 2>&1

api_pid=""

section() {
  printf '\n== %s ==\n' "$*"
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

fail() {
  echo "fresh VPS verification failed: $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$api_pid" ] && kill -0 "$api_pid" 2>/dev/null; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

safe_relative_dir() {
  case "$1" in
    "" | "/" | "." | ".." | /* | ../* | */../*)
      fail "$2 must be a workspace-relative scratch directory"
      ;;
  esac
}

sudo_prefix=()
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  sudo_prefix=(sudo)
fi

section "Repository"
test -f pyproject.toml || fail "run this script from a Zeus checkout"
test -f zeus/cli.py || fail "missing zeus/cli.py"
run pwd
run date -u
run uname -a
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  run git rev-parse HEAD
  run git status --short
else
  echo "Git checkout metadata unavailable; commit evidence will not be recorded."
fi

section "Optional OS Bootstrap"
if [ "${ZEUS_VPS_INSTALL_PACKAGES:-0}" = "1" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    run "${sudo_prefix[@]}" apt-get update
    run "${sudo_prefix[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      ca-certificates curl git python3 python3-venv python3-pip
  else
    fail "ZEUS_VPS_INSTALL_PACKAGES=1 is only implemented for apt-get hosts"
  fi
else
  echo "Skipping OS package install. Set ZEUS_VPS_INSTALL_PACKAGES=1 on a clean Debian/Ubuntu VPS."
fi

section "Python Environment"
venv_dir="${ZEUS_VPS_VENV_DIR:-.venv}"
safe_relative_dir "$venv_dir" "ZEUS_VPS_VENV_DIR"
run python3 --version
run python3 -m venv "$venv_dir"
# shellcheck disable=SC1091
source "$venv_dir/bin/activate"
run python -m pip install -e .
run python -B -m zeus.cli doctor --json

section "Optional Hermes Bootstrap"
export PATH="$HOME/.local/bin:$HOME/.hermes/bin:$PATH"
hash -r
if command -v hermes >/dev/null 2>&1; then
  run command -v hermes
elif [ "${ZEUS_VPS_INSTALL_HERMES:-0}" = "1" ]; then
  installer="$log_dir/hermes-install.sh"
  run curl -fsSL https://hermes-agent.nousresearch.com/install.sh -o "$installer"
  run bash "$installer"
  export PATH="$HOME/.local/bin:$HOME/.hermes/bin:$PATH"
  hash -r
  run command -v hermes
else
  fail "hermes is not on PATH. Install it first or set ZEUS_VPS_INSTALL_HERMES=1."
fi

section "Local Zeus Gates"
run sh scripts/test.sh
run sh scripts/repo_check.sh

section "Hermes Diagnostics"
run hermes version
run hermes doctor

section "Real Hermes Compatibility"
run env \
  ZEUS_VERIFY_START_GATEWAY="${ZEUS_VPS_START_GATEWAY:-0}" \
  ZEUS_VERIFY_GATEWAY_SECONDS="${ZEUS_VPS_GATEWAY_SECONDS:-5}" \
  sh scripts/verify_real_hermes.sh

section "Multi Template Profile Check"
multi_state="${ZEUS_VPS_MULTI_STATE_DIR:-.zeus-vps-multi}"
safe_relative_dir "$multi_state" "ZEUS_VPS_MULTI_STATE_DIR"
rm -rf -- "$multi_state"
hermes_bin="$(command -v hermes)"
for spec in "vps-coder:coding-bot" "vps-deepseek:deepseek-coding-bot" "vps-researcher:research-bot" "vps-support:support-gateway"; do
  bot_id="${spec%%:*}"
  template_id="${spec##*:}"
  run env ZEUS_STATE_DIR="$multi_state" ZEUS_HERMES_BIN="$hermes_bin" \
    python -B -m zeus.cli bot create "$bot_id" --template "$template_id"
  run env ZEUS_STATE_DIR="$multi_state" ZEUS_HERMES_BIN="$hermes_bin" \
    python -B -m zeus.cli bot doctor "$bot_id"
done

if [ -n "${ZEUS_VPS_ASYNC_PROMPT:-}" ]; then
  section "Optional Async Delegation Prompt"
  run env HERMES_HOME="$repo_root/$multi_state/hermes" hermes -p vps-coder -z "$ZEUS_VPS_ASYNC_PROMPT"
else
  echo "Skipping live async prompt. Set ZEUS_VPS_ASYNC_PROMPT to exercise delegate_task/background behavior with real credentials."
fi

section "API Smoke"
api_state="${ZEUS_VPS_API_STATE_DIR:-.zeus-vps-api}"
safe_relative_dir "$api_state" "ZEUS_VPS_API_STATE_DIR"
rm -rf -- "$api_state"
api_port="${ZEUS_VPS_API_PORT:-4311}"
api_key="${ZEUS_VPS_API_KEY:-vps-local-check}"
ZEUS_STATE_DIR="$api_state" ZEUS_API_KEY="$api_key" \
  python -B -m zeus.api --host 127.0.0.1 --port "$api_port" >"$log_dir/zeus-api.log" 2>&1 &
api_pid="$!"

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$api_port/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

run curl -fsS "http://127.0.0.1:$api_port/health"
run curl -fsS -H "x-zeus-api-key: $api_key" "http://127.0.0.1:$api_port/doctor"
run curl -fsS \
  -H "x-zeus-api-key: $api_key" \
  -H "content-type: application/json" \
  --data '{"bot_id":"api-vps","template_id":"support-gateway"}' \
  "http://127.0.0.1:$api_port/bots"

cleanup
api_pid=""

section "Summary"
echo "Fresh VPS verification completed."
echo "Evidence log: $log_file"
echo "API log: $log_dir/zeus-api.log"
