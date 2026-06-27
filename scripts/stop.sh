#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

pid_file=".zeus/zeus.pid"
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

if ! kill -0 "$pid" 2>/dev/null; then
  echo "Zeus API process $pid is not running"
  exit 0
fi

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
