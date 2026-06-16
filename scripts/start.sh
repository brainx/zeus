#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

host="${ZEUS_HOST:-127.0.0.1}"
port="${ZEUS_PORT:-4311}"

exec python3 -m zeus.api --host "$host" --port "$port"
