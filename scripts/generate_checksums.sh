#!/bin/sh
# Zeus Hermes Orchestrator
# Maintained by BrainX: https://github.com/brainx
set -eu

artifact_dir="${1:-dist}"
if [ ! -d "$artifact_dir" ]; then
  echo "Artifact directory not found: $artifact_dir" >&2
  exit 1
fi

set --
for artifact_path in "$artifact_dir"/*; do
  [ -f "$artifact_path" ] || continue
  artifact_name=${artifact_path#"$artifact_dir"/}
  [ "$artifact_name" = "SHA256SUMS.txt" ] && continue
  set -- "$@" "$artifact_name"
done

if [ "$#" -eq 0 ]; then
  echo "No artifacts found in $artifact_dir" >&2
  exit 1
fi

checksum_tmp=$(mktemp "$artifact_dir/.SHA256SUMS.XXXXXX")
cleanup() {
  rm -f -- "$checksum_tmp"
}
trap cleanup EXIT INT TERM

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$artifact_dir" && sha256sum -- "$@") >"$checksum_tmp"
elif command -v shasum >/dev/null 2>&1; then
  (cd "$artifact_dir" && shasum -a 256 -- "$@") >"$checksum_tmp"
else
  echo "Neither sha256sum nor shasum is available" >&2
  exit 1
fi

mv -f -- "$checksum_tmp" "$artifact_dir/SHA256SUMS.txt"
chmod 0644 "$artifact_dir/SHA256SUMS.txt"
trap - EXIT INT TERM
