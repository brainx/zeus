#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

tmp_dir=".tmp/test"
warning_log="$tmp_dir/unittest-stderr.log"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp_dir"
python3 -B -m compileall zeus tests
unittest_status=0
python3 -B -W error::ResourceWarning -m unittest discover -s tests -v \
  2>"$warning_log" || unittest_status=$?
cat "$warning_log" >&2
if grep -F "ResourceWarning" "$warning_log" >/dev/null; then
  echo "ResourceWarning detected in the test suite." >&2
  exit 1
fi
if [ "$unittest_status" -ne 0 ]; then
  exit "$unittest_status"
fi
python3 -B -m zeus.cli doctor --json >"$tmp_dir/zeus-doctor.json"
python3 -B -m zeus.cli template list >"$tmp_dir/zeus-templates.txt"
