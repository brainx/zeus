#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

repo_root="$(pwd)"
tmp_dir="$repo_root/.tmp/wheel-smoke"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$repo_root/.tmp"
rm -rf "$tmp_dir"
mkdir -p "$tmp_dir"
rm -rf dist
if command -v python >/dev/null 2>&1; then
  python_cmd="python"
elif [ -x ".venv/bin/python" ]; then
  python_cmd=".venv/bin/python"
else
  python_cmd="python3"
fi
"$python_cmd" -m build
"$python_cmd" -m venv "$tmp_dir/venv"
venv_python="$tmp_dir/venv/bin/python"
venv_zeus="$tmp_dir/venv/bin/zeus"
"$venv_python" -m pip install dist/*.whl

cd "$tmp_dir"
"$venv_zeus" template list >template-list.txt
"$venv_zeus" doctor --json >doctor.json
"$venv_python" -c "import zeus; print(zeus.__version__)"

grep "coding-bot" template-list.txt >/dev/null
grep "deepseek-coding-bot" template-list.txt >/dev/null
grep '"checks"' doctor.json >/dev/null

echo "Wheel smoke test passed."
