#!/usr/bin/env bash
# Set the release version everywhere it lives: the crate manifest, the crate's
# entry in Cargo.lock, and the npm package manifest. The version is single-
# sourced by convention — this script is the only supported way to change it,
# and CI's `versions` job fails any PR where the two manifests disagree.
#
#   scripts/bump-version.sh 1.2.3
#   scripts/bump-version.sh 1.2.0-rc.1
set -euo pipefail

new="${1:?usage: scripts/bump-version.sh <new-version>  (e.g. 1.2.3 or 1.2.0-rc.1)}"

# Plain semver, optional prerelease/build. The leading 'v' belongs to the git
# tag, not the manifests.
if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: '$new' is not a semver version (did you include a leading 'v'? drop it)" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cargo_manifest="$root/rust/contracts/Cargo.toml"
identity_manifest="$root/rust/identity/Cargo.toml"
npm_manifest="$root/ts/packages/contracts/package.json"

python3 - "$new" "$cargo_manifest" "$identity_manifest" "$npm_manifest" <<'PY'
import re
import sys

new, cargo_manifest, identity_manifest, npm_manifest = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def rewrite(path, pattern, replacement):
    text = open(path).read()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if count != 1:
        sys.exit(f"error: no version field found in {path}")
    open(path, "w").write(updated)

rewrite(cargo_manifest, r'^version = ".*"$', f'version = "{new}"')
rewrite(identity_manifest, r'^version = ".*"$', f'version = "{new}"')
rewrite(npm_manifest, r'^(\s*)"version": ".*",$', rf'\1"version": "{new}",')
PY

# Refresh the crate's own entry in Cargo.lock so the lockfile does not go
# stale-red in CI. --workspace touches only workspace members; offline first
# because that is all this needs, with a networked fallback just in case.
(cd "$root/rust" && (cargo update --workspace --offline 2>/dev/null || cargo update --workspace))

# Prove the two manifests now agree, using the same check CI runs.
"$root/.github/workflows/scripts/verify-tag.sh" >/dev/null

echo "Version set to $new in:"
echo "  rust/contracts/Cargo.toml (+ rust/Cargo.lock)"
echo "  rust/identity/Cargo.toml"
echo "  ts/packages/contracts/package.json"
echo
echo "Next steps:"
echo "  1. git checkout -b release/v$new && git commit -sam 'chore: release v$new'"
echo "  2. open a PR, get it merged"
echo "  3. gh release create v$new --title 'v$new' --generate-notes"
echo "     (publishing the GitHub Release triggers the crates.io + npm publish jobs)"
