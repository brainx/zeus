#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

state_dir="${ZEUS_STATE_DIR:-}"
if [ -z "$state_dir" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Could not resolve Zeus state directory: python3 is unavailable; set ZEUS_STATE_DIR explicitly" >&2
    exit 1
  fi
  if ! state_dir="$(python3 -B -c 'from zeus.config import Settings; print(Settings.from_env().state_dir)' 2>/dev/null)" || [ -z "$state_dir" ]; then
    echo "Could not resolve Zeus state directory; fix the Zeus configuration or set ZEUS_STATE_DIR explicitly" >&2
    exit 1
  fi
fi
pid_file="$state_dir/zeus.pid"
if [ ! -f "$pid_file" ]; then
  echo "Zeus PID file not found: $pid_file"
  exit 0
fi

read_pid_file() {
  awk '
    NR == 1 && $0 ~ /^[1-9][0-9]*$/ { pid = $0; next }
    { invalid = 1 }
    END {
      if (NR == 1 && invalid != 1) {
        print pid
        exit 0
      }
      exit 1
    }
  ' "$pid_file"
}

process_args_for_pid() {
  ps -p "$1" -o args= 2>/dev/null || ps -p "$1" -o command= 2>/dev/null || :
}

process_state_for_pid() {
  if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "unknown"
    return
  fi
  python3 -B -c '
import errno
import os
import sys

try:
    os.kill(int(sys.argv[1]), 0)
except ProcessLookupError:
    state = "dead"
except PermissionError:
    state = "unknown"
except OSError as exc:
    state = "dead" if exc.errno == errno.ESRCH else "unknown"
else:
    state = "alive"
print(state)
' "$1" 2>/dev/null || printf '%s\n' "unknown"
}

is_zeus_api_process() {
  case "$1" in
    *python*"-m zeus.api "* | *python*"-m zeus.api") return 0 ;;
    *) return 1 ;;
  esac
}

canonical_dir() {
  if [ -d "$1" ]; then
    (cd "$1" 2>/dev/null && pwd -P) || :
  fi
}

cwd_from_lsof() {
  lsof_output="$(lsof -a -p "$1" -d cwd -Fn 2>/dev/null || :)"
  lsof_cwd=""
  while IFS= read -r line; do
    case "$line" in
      n*)
        lsof_cwd="${line#n}"
        break
        ;;
    esac
  done <<EOF
$lsof_output
EOF
  if [ -n "$lsof_cwd" ]; then
    canonical_dir "$lsof_cwd"
  fi
}

process_cwd_for_pid() {
  if [ -d "/proc/$1/cwd" ]; then
    proc_cwd="$(canonical_dir "/proc/$1/cwd")"
    if [ -n "$proc_cwd" ]; then
      printf '%s\n' "$proc_cwd"
      return
    fi
  fi

  if command -v lsof >/dev/null 2>&1; then
    lsof_cwd_result="$(cwd_from_lsof "$1")"
    if [ -n "$lsof_cwd_result" ]; then
      printf '%s\n' "$lsof_cwd_result"
      return
    fi
  fi

  if command -v pwdx >/dev/null 2>&1; then
    pwdx_output="$(pwdx "$1" 2>/dev/null || :)"
    case "$pwdx_output" in
      *": "*) canonical_dir "${pwdx_output#*: }" ;;
    esac
  fi
}

if ! pid="$(read_pid_file)"; then
  echo "Invalid Zeus PID file: $pid_file must contain exactly one positive decimal PID" >&2
  exit 1
fi

process_state="$(process_state_for_pid "$pid")"
case "$process_state" in
  alive) ;;
  dead)
    current_pid="$(read_pid_file 2>/dev/null || :)"
    if [ "$current_pid" = "$pid" ]; then
      rm -f -- "$pid_file"
    fi
    echo "Zeus API process $pid is not running"
    exit 0
    ;;
  *)
    echo "Refusing to remove Zeus PID file for process $pid: could not verify whether it is running" >&2
    exit 1
    ;;
esac

process_args="$(process_args_for_pid "$pid")"
if ! is_zeus_api_process "$process_args"; then
  echo "Refusing to stop PID $pid: process command is not a Zeus API server" >&2
  exit 1
fi

workspace="$(pwd -P)"
process_cwd="$(process_cwd_for_pid "$pid")"
if [ -z "$process_cwd" ]; then
  echo "Refusing to stop PID $pid: could not verify process working directory" >&2
  exit 1
fi

if [ "$process_cwd" != "$workspace" ]; then
  echo "Refusing to stop PID $pid: process working directory is not this workspace" >&2
  exit 1
fi

if kill "$pid" 2>/dev/null; then
  echo "Stopped Zeus API process $pid"
else
  echo "Failed to stop Zeus API process $pid" >&2
  exit 1
fi
