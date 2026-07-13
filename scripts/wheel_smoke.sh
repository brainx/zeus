#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

repo_root="$(pwd)"
tmp_dir="$repo_root/.tmp/wheel-smoke"
build_artifacts="${ZEUS_WHEEL_SMOKE_BUILD:-1}"
fail() {
  echo "wheel smoke failed: $*" >&2
  exit 1
}
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$repo_root/.tmp"
rm -rf "$tmp_dir"
mkdir -p "$tmp_dir"
if command -v python >/dev/null 2>&1; then
  python_cmd="python"
elif [ -x ".venv/bin/python" ]; then
  python_cmd=".venv/bin/python"
else
  python_cmd="python3"
fi
if [ "$build_artifacts" = "1" ]; then
  rm -rf dist
  "$python_cmd" -m build
elif [ "$build_artifacts" != "0" ]; then
  fail "ZEUS_WHEEL_SMOKE_BUILD must be 0 or 1"
fi
set -- "$repo_root"/dist/*.whl
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  fail "expected exactly one wheel in dist/"
fi
wheel_path="$1"
"$python_cmd" -m venv "$tmp_dir/venv"
venv_python="$tmp_dir/venv/bin/python"
venv_zeus="$tmp_dir/venv/bin/zeus"
"$venv_python" -m pip install "$wheel_path"

cd "$tmp_dir"
"$venv_zeus" template list >template-list.txt
"$venv_zeus" doctor --json >doctor.json
"$venv_python" -c "import zeus; print(zeus.__version__)"
ZEUS_STATE_DIR="$tmp_dir/state" "$venv_zeus" demo up --json >demo-up.json
ZEUS_STATE_DIR="$tmp_dir/state" "$venv_zeus" demo status --json >demo-status.json
ZEUS_STATE_DIR="$tmp_dir/state" "$venv_zeus" demo down --json >demo-down.json

grep "coding-bot" template-list.txt >/dev/null
grep "deepseek-coding-bot" template-list.txt >/dev/null
grep '"checks"' doctor.json >/dev/null
grep '"fake_hermes_bin"' demo-up.json >/dev/null
grep '"status": "running"' demo-status.json >/dev/null
grep '"status": "stopped"' demo-down.json >/dev/null

echo "Wheel smoke test passed."
