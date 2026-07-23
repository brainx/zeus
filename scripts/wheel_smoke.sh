#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

repo_root="$(pwd -P)"
tmp_dir="$repo_root/.tmp/wheel-smoke"
build_artifacts="${ZEUS_WHEEL_SMOKE_BUILD:-1}"
venv_python=""
venv_zeus=""
venv_fake_hermes=""
state_dir="$tmp_dir/state"
demo_started=0
fail() {
  echo "wheel smoke failed: $*" >&2
  exit 1
}
cleanup() {
  if [ "$demo_started" = "1" ] && [ -n "$venv_zeus" ] && [ -x "$venv_zeus" ]; then
    ZEUS_STATE_DIR="$state_dir" "$venv_zeus" demo down --json >/dev/null 2>&1 || true
  fi
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
venv_fake_hermes="$tmp_dir/venv/bin/zeus-fake-hermes"
PIP_NO_INDEX=1 "$venv_python" -m pip install --no-deps "$wheel_path"

cd "$tmp_dir"
unset PYTHONPATH PYTHONHOME
export PYTHONNOUSERSITE=1
export PATH="$tmp_dir/venv/bin:$PATH"
export ZEUS_STATE_DIR="$state_dir"

installed_fake_hermes="$(command -v zeus-fake-hermes || true)"
[ "$installed_fake_hermes" = "$venv_fake_hermes" ] ||
  fail "PATH did not select the installed zeus-fake-hermes entry point"

[ ! -e "$state_dir" ] || fail "state directory exists before stateless CLI checks"
"$venv_zeus" --help >zeus-help.txt
grep -F "usage: zeus" zeus-help.txt >/dev/null
metadata_version=$("$venv_python" -c \
  'from importlib.metadata import version; print(version("zeus-hermes-orchestrator"))')
module_version=$("$venv_python" -c 'import zeus; print(zeus.__version__)')
cli_version=$("$venv_zeus" --version)
module_path=$("$venv_python" -c \
  'from pathlib import Path; import zeus; print(Path(zeus.__file__).resolve())')
[ "$metadata_version" = "$module_version" ] ||
  fail "distribution and module versions differ: $metadata_version != $module_version"
[ "$cli_version" = "zeus $metadata_version" ] ||
  fail "CLI version does not match package metadata: $cli_version"
case "$module_path" in
  "$tmp_dir"/venv/*) ;;
  *) fail "zeus imported outside the isolated virtual environment: $module_path" ;;
esac
[ "$($venv_python -c 'from importlib.resources import files; print(files("zeus.bundled_skills.audit").joinpath("SKILL.md").is_file())')" = "True" ] ||
  fail "installed wheel is missing the bundled audit skill"
[ "$($venv_python -c 'from zeus.audit_profile import AUDIT_SKILL_VERSION, load_audit_skill; print(f"version: {AUDIT_SKILL_VERSION}" in load_audit_skill())')" = "True" ] ||
  fail "installed wheel cannot load the bundled audit skill"
[ ! -e "$state_dir" ] || fail "help or version checks created runtime state"

"$venv_python" -m pip check
"$venv_zeus" template list >template-list.txt
"$venv_zeus" doctor --json >doctor.json
for template_id in \
  coding-bot \
  deepseek-coding-bot \
  docs-writer-bot \
  gateway-operator \
  log-triage-bot \
  research-bot \
  support-gateway; do
  grep "^${template_id}[[:space:]]" template-list.txt >/dev/null ||
    fail "installed wheel is missing bundled template: $template_id"
done

grep '"checks"' doctor.json >/dev/null
demo_started=1
"$venv_zeus" demo up --json >demo-up.json
"$venv_zeus" demo status --json >demo-status.json
"$venv_zeus" demo down --json >demo-down.json
demo_started=0

grep '"fake_hermes_bin"' demo-up.json >/dev/null
grep -F "\"fake_hermes_bin\": \"$venv_fake_hermes\"" demo-up.json >/dev/null
grep '"status": "running"' demo-up.json >/dev/null
grep '"status": "running"' demo-status.json >/dev/null
grep '"status": "stopped"' demo-down.json >/dev/null

echo "Wheel smoke test passed."
