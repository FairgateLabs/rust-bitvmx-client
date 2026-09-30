#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version-tag>" >&2
  exit 1
fi

tag="$1"
image_version="${tag#force-build-}"

if [[ "$tag" != force-build-* ]]; then
  manifest_version="$(awk -F '"' '
    /^\[package\][[:space:]]*$/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^[[:space:]]*version[[:space:]]*=[[:space:]]*"/ {
      print $2
      exit
    }
  ' Cargo.toml)"

  if [[ -z "$manifest_version" ]]; then
    echo "::error::Could not read [package].version from Cargo.toml" >&2
    exit 1
  fi

  if [[ "$image_version" != "v$manifest_version" ]]; then
    echo "::error::Tag $tag does not match Cargo.toml package version $manifest_version" >&2
    exit 1
  fi
fi

printf '%s\n' "$image_version"
