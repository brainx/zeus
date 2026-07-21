#!/usr/bin/env bash
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -Eeuo pipefail
umask 077

fail() {
  echo "fresh VPS verification failed: $*" >&2
  exit 1
}

safe_relative_dir() {
  case "$1" in
    "" | "/" | "." | ".." | /* | ../* | */.. | */../*)
      fail "$2 must be a workspace-relative scratch directory"
      ;;
  esac
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

sudo_prefix=()
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  sudo_prefix=(sudo)
fi

if ! command -v python3 >/dev/null 2>&1; then
  if [ "${ZEUS_VPS_INSTALL_PACKAGES:-0}" != "1" ] || ! command -v apt-get >/dev/null 2>&1; then
    fail "Python 3 is required; install it first or enable the supported apt package bootstrap"
  fi
  echo "Bootstrapping the Python 3 prerequisite before private evidence logging."
  "${sudo_prefix[@]}" apt-get update
  "${sudo_prefix[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y python3
  hash -r
  command -v python3 >/dev/null 2>&1 || fail "Python 3 bootstrap completed without a python3 executable"
fi

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
log_dir="${ZEUS_VPS_LOG_DIR:-.tmp/fresh-vps-verify/$timestamp}"
safe_relative_dir "$log_dir" "ZEUS_VPS_LOG_DIR"

private_evidence() {
  python3 -I -B - "$repo_root" "$@" <<'PY'
import os
import stat
import sys


def fail(message: str) -> None:
    raise ValueError(message)


def relative_parts(value: str) -> list[str]:
    if not value or os.path.isabs(value):
        fail("path must be relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail("path contains an unsafe component")
    if any("\r" in part or "\n" in part for part in parts):
        fail("path contains a line break")
    return parts


def same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def validate_directory_bindings(
    bindings: list[tuple[int, str, int]],
    *,
    exact_final_mode: bool,
) -> None:
    for index, (parent_fd, name, child_fd) in enumerate(bindings):
        opened = os.fstat(child_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(opened.st_mode) or not same_identity(opened, current):
            fail("directory binding changed")
        if opened.st_uid != os.geteuid():
            fail("directory is not owned by the current user")
        if exact_final_mode and index == len(bindings) - 1:
            if stat.S_IMODE(opened.st_mode) != 0o700:
                fail("evidence directory is not private")


def open_directory_chain(
    root: str,
    parts: list[str],
    *,
    create: bool,
) -> tuple[list[int], list[tuple[int, str, int]]]:
    if not hasattr(os, "O_NOFOLLOW"):
        fail("O_NOFOLLOW is required for private evidence")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    directory_flags |= os.O_NOFOLLOW
    root_fd = os.open(root, directory_flags)
    descriptors = [root_fd]
    bindings: list[tuple[int, str, int]] = []
    parent_fd = root_fd
    try:
        for index, name in enumerate(parts):
            created = False
            try:
                child_fd = os.open(name, directory_flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                created = True
                child_fd = os.open(name, directory_flags, dir_fd=parent_fd)
            descriptors.append(child_fd)
            bindings.append((parent_fd, name, child_fd))
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid():
                fail("unsafe evidence directory")
            if created or index == len(parts) - 1:
                validate_directory_bindings(bindings, exact_final_mode=False)
                os.fchmod(child_fd, 0o700)
            parent_fd = child_fd
        validate_directory_bindings(bindings, exact_final_mode=True)
        return descriptors, bindings
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def validate_file(opened: os.stat_result, current: os.stat_result) -> None:
    if not stat.S_ISREG(opened.st_mode) or not same_identity(opened, current):
        fail("unsafe evidence file binding")
    if opened.st_uid != os.geteuid() or opened.st_nlink != 1:
        fail("unsafe evidence file ownership")
    if stat.S_IMODE(opened.st_mode) != 0o600:
        fail("evidence file is not private")


def prepare(root: str, relative_directory: str, names: list[str]) -> None:
    descriptors, bindings = open_directory_chain(
        root,
        relative_parts(relative_directory),
        create=True,
    )
    directory_fd = descriptors[-1]
    if not hasattr(os, "O_NOFOLLOW"):
        fail("O_NOFOLLOW is required for private evidence")
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    file_flags |= os.O_NOFOLLOW
    try:
        for name in names:
            if "/" in name or name in {"", ".", ".."}:
                fail("invalid evidence filename")
            file_fd = os.open(name, file_flags, 0o600, dir_fd=directory_fd)
            try:
                opened = os.fstat(file_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(opened.st_mode) or not same_identity(opened, current):
                    fail("unsafe evidence file binding")
                if opened.st_uid != os.geteuid() or opened.st_nlink != 1:
                    fail("unsafe evidence file ownership")
                os.fchmod(file_fd, 0o600)
                validate_file(
                    os.fstat(file_fd),
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                )
                validate_directory_bindings(bindings, exact_final_mode=True)
            finally:
                os.close(file_fd)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def validate_descriptor(
    root: str,
    relative_file: str,
    descriptor: int,
    *,
    truncate: bool,
) -> None:
    parts = relative_parts(relative_file)
    if len(parts) < 2:
        fail("evidence file must be inside an evidence directory")
    descriptors, bindings = open_directory_chain(root, parts[:-1], create=False)
    directory_fd = descriptors[-1]
    try:
        opened = os.fstat(descriptor)
        current = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
        validate_file(opened, current)
        validate_directory_bindings(bindings, exact_final_mode=True)
        if truncate:
            os.ftruncate(descriptor, 0)
        validate_file(
            os.fstat(descriptor),
            os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False),
        )
        validate_directory_bindings(bindings, exact_final_mode=True)
    finally:
        for opened_fd in reversed(descriptors):
            os.close(opened_fd)


try:
    repository_root = sys.argv[1]
    action = sys.argv[2]
    relative_path = sys.argv[3]
    if action == "prepare":
        prepare(repository_root, relative_path, sys.argv[4:])
    elif action == "validate-file":
        validate_descriptor(
            repository_root,
            relative_path,
            int(sys.argv[4]),
            truncate=sys.argv[5] == "truncate",
        )
    else:
        fail("unknown private evidence operation")
except (OSError, ValueError) as error:
    print(f"private evidence validation failed: {error}", file=sys.stderr)
    raise SystemExit(1) from None
PY
}

if ! private_evidence prepare "$log_dir" run.log zeus-api.log; then
  fail "could not create a private evidence directory"
fi
log_file="$log_dir/run.log"
run_log_fd=9
exec 9<>"$log_file"
if ! private_evidence validate-file "$log_file" "$run_log_fd" truncate; then
  exec 9>&-
  fail "could not open the private evidence transcript"
fi
exec > >(tee -a "/dev/fd/$run_log_fd") 2>&1

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

run_stdout_to_fd() {
  local output_fd="$1"
  shift
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@" 1>&"$output_fd"
}

run_sensitive() {
  local label="$1"
  shift
  printf '+ %s\n' "$label"
  "$@"
}

cleanup() {
  if [ -n "$api_pid" ] && kill -0 "$api_pid" 2>/dev/null; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

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
  installer_sha256="${ZEUS_VPS_HERMES_INSTALLER_SHA256:-}"
  if [[ ! "$installer_sha256" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    fail "ZEUS_VPS_HERMES_INSTALLER_SHA256 must be exactly 64 hexadecimal characters"
  fi
  if ! private_evidence prepare "$log_dir" hermes-install.sh; then
    fail "could not create a private Hermes installer evidence file"
  fi
  installer="$log_dir/hermes-install.sh"
  installer_fd=8
  exec 8<>"$installer"
  if ! private_evidence validate-file "$installer" "$installer_fd" truncate; then
    exec 8>&-
    fail "could not open the private Hermes installer evidence file"
  fi
  run_stdout_to_fd "$installer_fd" curl -fsSL https://hermes-agent.nousresearch.com/install.sh
  if ! private_evidence validate-file "$installer" "$installer_fd" preserve; then
    exec 8>&-
    fail "Hermes installer evidence changed during download"
  fi
  if ! python3 -I -B - "$installer_fd" "$installer_sha256" <<'PY'
import hashlib
import hmac
import os
import sys

descriptor = int(sys.argv[1])
expected = sys.argv[2].lower()
digest = hashlib.sha256()
offset = 0
while True:
    chunk = os.pread(descriptor, 1024 * 1024, offset)
    if not chunk:
        break
    digest.update(chunk)
    offset += len(chunk)
matches = hmac.compare_digest(digest.hexdigest(), expected)
if matches:
    os.lseek(descriptor, 0, os.SEEK_SET)
raise SystemExit(0 if matches else 1)
PY
  then
    exec 8>&-
    fail "Hermes installer SHA-256 mismatch; refusing to execute it"
  fi
  run bash "/dev/fd/$installer_fd"
  exec 8>&-
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
  run_sensitive "Hermes async prompt [redacted]" env \
    HERMES_HOME="$repo_root/$multi_state/hermes" \
    hermes -p vps-coder -z "$ZEUS_VPS_ASYNC_PROMPT"
else
  echo "Skipping live async prompt. Set ZEUS_VPS_ASYNC_PROMPT to exercise delegate_task/background behavior with real credentials."
fi

section "API Smoke"
api_state="${ZEUS_VPS_API_STATE_DIR:-.zeus-vps-api}"
safe_relative_dir "$api_state" "ZEUS_VPS_API_STATE_DIR"
rm -rf -- "$api_state"
api_port="${ZEUS_VPS_API_PORT:-4311}"
api_key="${ZEUS_VPS_API_KEY:-$(python -I -B -c 'import secrets; print(secrets.token_hex(32))')}"
if [[ "$api_key" == *$'\r'* || "$api_key" == *$'\n'* ]]; then
  fail "ZEUS_VPS_API_KEY must not contain a line break"
fi

write_api_curl_config() {
  local include_json_header="$1"
  local escaped_key
  escaped_key=${api_key//\\/\\\\}
  escaped_key=${escaped_key//\"/\\\"}
  printf 'header = "x-zeus-api-key: %s"\n' "$escaped_key"
  if [ "$include_json_header" = "1" ]; then
    printf 'header = "content-type: application/json"\n'
  fi
}

api_log_file="$log_dir/zeus-api.log"
api_log_fd=7
exec 7<>"$api_log_file"
if ! private_evidence validate-file "$api_log_file" "$api_log_fd" truncate; then
  exec 7>&-
  fail "could not open the private API evidence log"
fi
ZEUS_STATE_DIR="$api_state" ZEUS_API_KEY="$api_key" \
  python -B -m zeus.api --host 127.0.0.1 --port "$api_port" 1>&"$api_log_fd" 2>&1 &
api_pid="$!"

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$api_port/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

run curl -fsS "http://127.0.0.1:$api_port/health"
write_api_curl_config 0 | run_sensitive "authenticated API request [redacted]" \
  curl -fsS --config - "http://127.0.0.1:$api_port/doctor"
write_api_curl_config 1 | run_sensitive "authenticated API request [redacted]" \
  curl -fsS --config - \
  --data '{"bot_id":"api-vps","template_id":"support-gateway"}' \
  "http://127.0.0.1:$api_port/bots"

cleanup
api_pid=""
exec 7>&-

section "Summary"
echo "Fresh VPS verification completed."
echo "Evidence log: $log_file"
echo "API log: $api_log_file"
