#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

hermes_version=0.20.0
hermes_tag=v2026.8.3
hermes_tag_object=7de39e700d2c329e15d32eb0b96e2f7cdd9fbdb2
hermes_commit=3c27eb6234bf91b8ceee9e9071591b31e9b148cb
hermes_archive_sha256=370542c7219faba6300905c3b419e14e6508a31ac698a1a5174e0386990834be
hermes_archive_url="https://codeload.github.com/NousResearch/hermes-agent/tar.gz/refs/tags/${hermes_tag}"

download_directory=$(mktemp -d)
trap 'rm -rf -- "$download_directory"' EXIT HUP INT TERM
archive_path="$download_directory/hermes-agent-${hermes_tag}.tar.gz"
source_directory=".tmp/hermes-agent-${hermes_tag}"

printf 'Fetching Hermes Agent %s from signed tag %s (tag object %s, commit %s)\n' \
    "$hermes_version" "$hermes_tag" "$hermes_tag_object" "$hermes_commit"
curl --fail --location --silent --show-error \
    --retry 3 --retry-all-errors --connect-timeout 15 --max-time 120 \
    --output "$archive_path" "$hermes_archive_url"

checksum_path="$download_directory/hermes-agent.sha256"
printf '%s  %s\n' "$hermes_archive_sha256" "$archive_path" > "$checksum_path"
sha256sum -c "$checksum_path"
mkdir -p .tmp
rm -rf -- "$source_directory"
mkdir -p "$source_directory"
tar --extract --gzip --file "$archive_path" --directory "$source_directory" \
    --strip-components=1
test -f "$source_directory/pyproject.toml"
python -m pip install --no-deps --no-build-isolation --editable "$source_directory"
python -c \
    'import importlib.metadata as m; expected = "0.20.0"; actual = m.version("hermes-agent"); assert actual == expected, f"expected Hermes Agent {expected}, found {actual}"'
