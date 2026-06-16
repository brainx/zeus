#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

tmp_dir=".tmp/test"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

python3 -B -m compileall zeus tests
python3 -B -m unittest discover -s tests -v
mkdir -p "$tmp_dir"
python3 -B -m zeus.cli doctor --json >"$tmp_dir/zeus-doctor.json"
python3 -B -m zeus.cli template list >"$tmp_dir/zeus-templates.txt"
