#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

tmp_dir=".tmp/repo-check"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM
mkdir -p "$tmp_dir"

required_files="
README.md
LICENSE
CREDITS.md
CONTRIBUTING.md
SECURITY.md
CHANGELOG.md
pyproject.toml
.env.example
.gitignore
.github/workflows/ci.yml
docs/ARCHITECTURE.md
docs/API.md
docs/TEMPLATE_AUTHORING.md
docs/REAL_HERMES_VERIFICATION.md
docs/FRESH_VPS_TEST.md
docs/REPO_GENERATION.md
scripts/test.sh
scripts/verify_real_hermes.sh
scripts/fresh_vps_verify.sh
templates/coding-bot.toml
templates/deepseek-coding-bot.toml
templates/research-bot.toml
templates/support-gateway.toml
"

for file in $required_files; do
  if [ ! -f "$file" ]; then
    echo "missing required repository file: $file" >&2
    exit 1
  fi
done

python3 -B -m zeus.cli template list >/dev/null
ZEUS_STATE_DIR="$tmp_dir/state" python3 -B -m zeus.cli doctor --json >/dev/null

python3 -B - <<'PY'
from pathlib import Path
import re
import sys

paths = [
    Path("README.md"),
    Path("CREDITS.md"),
    Path("CONTRIBUTING.md"),
    Path("SECURITY.md"),
    Path("CHANGELOG.md"),
    Path("pyproject.toml"),
    Path(".env.example"),
    Path(".gitignore"),
    Path("docs"),
    Path("scripts"),
    Path("templates"),
    Path("tests"),
    Path("zeus"),
]

patterns = [
    re.compile(r"(?<![A-Za-z])sk-[A-Za-z0-9]"),
    re.compile(r"xoxb-[A-Za-z0-9]"),
    re.compile(r"TELEGRAM_BOT_TOKEN=[A-Za-z0-9:_-]{8,}"),
    re.compile("/" + "Users/"),
    re.compile(r"TO[D]O|TB[D]"),
]

failures = []
for path in paths:
    files = [path] if path.is_file() else sorted(path.rglob("*"))
    for file in files:
        if not file.is_file():
            continue
        text = file.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            if pattern.search(text):
                failures.append(f"{file}: matched {pattern.pattern}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
PY

echo "Repository readiness check passed."
