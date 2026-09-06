#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

hermes_version=0.21.0
hermes_tag=v2026.8.31
hermes_tag_object=6e8f8418e6378eb2617e4de074e13dedd091b8af
hermes_commit=29112bef099274229cadff79cdff7bf7b99c4b77
hermes_archive_sha256=76b99a8be9b77d66833c3cfe2b35c6d6f6a58e4ff9637ef8effcfc1f420ab35a
hermes_archive_url="https://codeload.github.com/NousResearch/hermes-agent/tar.gz/${hermes_commit}"

download_directory=$(mktemp -d)
trap 'rm -rf -- "$download_directory"' EXIT HUP INT TERM
archive_path="$download_directory/hermes-agent-${hermes_tag}.tar.gz"
source_directory=".tmp/hermes-agent-${hermes_tag}"

printf 'Fetching Hermes Agent %s from pinned commit for unsigned tag %s (tag object %s, commit %s)\n' \
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
python -c '
import importlib.metadata as m

expected = "0.21.0"
actual = m.version("hermes-agent")
if actual != expected:
    raise SystemExit(f"expected Hermes Agent {expected}, found {actual}")
'
