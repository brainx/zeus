#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

pid_file=".zeus/zeus.pid"
if [ ! -f "$pid_file" ]; then
  echo "Zeus PID file not found: $pid_file"
  exit 0
fi

pid="$(cat "$pid_file")"
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  echo "Stopped Zeus API process $pid"
else
  echo "Zeus API process $pid is not running"
fi
