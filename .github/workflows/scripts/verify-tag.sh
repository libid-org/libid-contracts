#!/usr/bin/env bash
# Assert the single-version invariant: the crate version and the npm package
# version are equal, and — when a tag is given — both equal the release tag.
#
#   verify-tag.sh v1.2.3   # release mode: tag == cargo == npm, or die
#   verify-tag.sh          # PR mode: cargo == npm, or die
#
# Run from the repository root (CI's default working directory).
set -euo pipefail

cargo_manifest="rust/contracts/Cargo.toml"
npm_manifest="ts/packages/contracts/package.json"

cargo_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$cargo_manifest" | head -n1)"
npm_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$npm_manifest")"

if [ -z "$cargo_version" ]; then
  echo "::error::could not read a version from $cargo_manifest" >&2
  exit 1
fi

echo "cargo ($cargo_manifest):        $cargo_version"
echo "npm   ($npm_manifest): $npm_version"

if [ "$cargo_version" != "$npm_version" ]; then
  echo "::error::version mismatch: cargo=$cargo_version npm=$npm_version — run scripts/bump-version.sh to set both" >&2
  exit 1
fi

if [ "$#" -ge 1 ]; then
  tag="$1"
  case "$tag" in
    v[0-9]*) ;;
    *)
      echo "::error::release tag '$tag' does not look like v<semver> (e.g. v1.2.3)" >&2
      exit 1
      ;;
  esac
  tag_version="${tag#v}"
  echo "tag:                            $tag_version (from $tag)"
  if [ "$tag_version" != "$cargo_version" ]; then
    echo "::error::release tag $tag ($tag_version) does not match the manifests ($cargo_version) — retag, or bump with scripts/bump-version.sh first" >&2
    exit 1
  fi
fi

echo "OK: versions agree."
