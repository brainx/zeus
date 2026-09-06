#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

fail() {
  echo "Service recovery drill refused: $*" >&2
  exit 2
}

[ "${ZEUS_SERVICE_RECOVERY_DRILL:-}" = "1" ] || fail "explicit CI opt-in is required"
[ "${GITHUB_ACTIONS:-}" = "true" ] || fail "GitHub Actions is required"
[ "${RUNNER_ENVIRONMENT:-}" = "github-hosted" ] || fail "a disposable GitHub-hosted runner is required"
[ "${RUNNER_OS:-}" = "Linux" ] && [ "$(uname -s)" = "Linux" ] || fail "Linux is required"
[ "$(id -u)" = "0" ] || fail "run through sudo on the disposable runner"
case "${SUDO_UID:-}:${SUDO_GID:-}" in
  *[!0-9:]*|:*|*:) fail "the invoking non-root runner identity is required" ;;
esac
[ "$SUDO_UID" -gt 0 ] || fail "the service must run as the non-root runner"
# This is an OS-owned configuration file, never a repository input.
# shellcheck disable=SC1091
. /etc/os-release
[ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "24.04" ] || fail "Ubuntu 24.04 is required"
[ "$(cat /proc/1/comm)" = "systemd" ] || fail "systemd must be PID 1"
[ -d /run/systemd/system ] || fail "the runtime unit directory is unavailable"
repo_root=$(pwd -P)
[ "$repo_root" = "${GITHUB_WORKSPACE:-}" ] || fail "run from the checked-out CI workspace"
[ "$#" = 1 ] && [ -x "$1" ] || fail "provide the CI Python executable"
build_python=$1
set -- "$repo_root"/dist/*.whl
[ "$#" = 1 ] && [ -f "$1" ] && [ ! -L "$1" ] || fail "expected exactly one built regular wheel"
wheel_path=$1

umask 077
drill_root=$(mktemp -d /run/zeus-service-recovery.XXXXXXXX)
root_identity=$(stat -c '%d:%i' "$drill_root")
venv_python="$drill_root/venv/bin/python"
cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [ ! -L "$drill_root" ] && [ "$(stat -c '%d:%i' "$drill_root")" = "$root_identity" ]; then
    if [ -f "$drill_root/driver.py" ] && [ -x "$venv_python" ]; then
      if ! timeout 60 "$venv_python" -I "$drill_root/driver.py" cleanup "$drill_root" "$repo_root" "$SUDO_UID" "$SUDO_GID"; then
        echo "Service recovery cleanup failed; disposable state retained at $drill_root" >&2
        exit 1
      fi
    fi
    rm -rf -- "$drill_root"
  else
    echo "Service recovery cleanup refused a replaced temporary root" >&2
    exit 1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Only traversal is shared; the state, working directory, and environment are private.
chmod 0711 "$drill_root"
"$build_python" -m venv "$drill_root/venv"
PIP_NO_INDEX=1 "$venv_python" -m pip install --no-deps "$wheel_path"
chmod -R a+rX "$drill_root/venv"
cp "$repo_root/tests/fixtures/service_recovery_drill.py" "$drill_root/driver.py"
timeout 180 "$venv_python" -I "$drill_root/driver.py" run "$drill_root" "$repo_root" "$SUDO_UID" "$SUDO_GID"
