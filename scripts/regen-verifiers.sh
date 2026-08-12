#!/usr/bin/env bash
# Regenerate the bb-generated Solidity verifiers from the pinned
# libid-circuits release.
#
# solidity/circuits-version pins a release tag on libid-org/libid-circuits.
# This script downloads that release's artifacts (per-circuit tarballs plus a
# manifest with their sha256s and the toolchain versions that produced them),
# verifies the hashes, obtains bb at exactly the manifest's version, and
# re-derives both committed verifiers from the released verification keys:
#
#   solidity/contracts/login/oidc/Verifier.sol      ⟵ jwt_email vk
#   solidity/contracts/login/zk/XHonkVerifier.sol   ⟵ dyaka-noir-token vk
#                                                     (HonkVerifier renamed
#                                                      XHonkVerifier — two bb
#                                                      verifiers in one
#                                                      project would collide)
#
# Post-processing mirrors libid-circuits' scripts/gen-verifier.sh: every
# assembly block is annotated ("memory-safe") for via_ir, then the output is
# formatted under solidity/foundry.toml.
#
# Usage:
#   scripts/regen-verifiers.sh --check   # byte-compare against the committed
#                                        # files; nonzero + diffstat on drift
#                                        # (what CI's `verifiers` job runs)
#   scripts/regen-verifiers.sh --write   # overwrite the committed files
#
# Requirements: gh (authenticated; GH_TOKEN in CI), jq, curl, perl, forge.
# bb is used from PATH (or ~/.bb) when it already matches the manifest's
# version; otherwise bbup installs the pinned version into ~/.bb.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="${1:-}"
case "$MODE" in
  --check|--write) ;;
  *)
    echo "usage: $0 --check|--write" >&2
    exit 2
    ;;
esac

TAG="$(cat "$REPO_ROOT/solidity/circuits-version")"
echo "Pinned libid-circuits release: $TAG"

# Download dir is a real temp dir; the generation dir lives under solidity/
# (gitignored) because forge fmt formats it under solidity/foundry.toml.
DL="$(mktemp -d "${TMPDIR:-/tmp}/libid-circuits.XXXXXX")"
GEN="$REPO_ROOT/solidity/.circuits-check"
cleanup() { rm -rf "$DL" "$GEN"; }
trap cleanup EXIT
rm -rf "$GEN"
mkdir -p "$GEN"

# --- Download the release assets -------------------------------------------
if ! gh release download "$TAG" \
    --repo libid-org/libid-circuits \
    --dir "$DL" \
    --pattern 'libid-circuits-*.tar.gz' \
    --pattern 'manifest.json'; then
  echo "::error::libid-circuits release '$TAG' (pinned in solidity/circuits-version) does not exist or has no artifacts yet. Cut that release first, or fix the pin." >&2
  exit 1
fi

# --- Verify tarball sha256s against the manifest ---------------------------
# Every tarball must hash to what the manifest promises before anything
# inside it is trusted.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1 # macOS
  fi
}
for tarball in "$DL"/libid-circuits-*.tar.gz; do
  name="$(basename "$tarball")"
  want="$(jq -re --arg t "$name" '.tarballs[$t].sha256' "$DL/manifest.json")"
  got="$(sha256 "$tarball")"
  if [ "$want" != "$got" ]; then
    echo "::error::$name sha256 mismatch: manifest says $want, asset is $got" >&2
    exit 1
  fi
  echo "$name: sha256 OK"
done

# --- Extract the circuits we regenerate from -------------------------------
VERSION="$(jq -re .version "$DL/manifest.json")"
for circuit in jwt_email dyaka-noir-token; do
  mkdir -p "$DL/$circuit"
  tar -xzf "$DL/libid-circuits-${VERSION}-${circuit}.tar.gz" -C "$DL/$circuit"
done

# --- bb at the manifest's toolchain version --------------------------------
# The bb pin comes from the manifest — the release names the version that
# produced its vks, and only that version reproduces them. An existing bb at
# the right version (on PATH or in ~/.bb) is used as-is; otherwise bbup
# installs the pinned version into ~/.bb.
BB_VERSION="$(jq -re .toolchain.bb "$DL/manifest.json")"
BB=""
for candidate in "$(command -v bb || true)" "$HOME/.bb/bb"; do
  if [ -n "$candidate" ] && [ -x "$candidate" ] \
      && [ "$("$candidate" --version | tail -1)" = "$BB_VERSION" ]; then
    BB="$candidate"
    break
  fi
done
if [ -z "$BB" ]; then
  echo "No bb $BB_VERSION found; installing via bbup."
  if ! command -v bbup >/dev/null 2>&1 && [ ! -x "$HOME/.bb/bbup" ]; then
    curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
  fi
  PATH="$HOME/.bb:$PATH" bbup --version "$BB_VERSION"
  BB="$HOME/.bb/bb"
  [ "$("$BB" --version | tail -1)" = "$BB_VERSION" ] || {
    echo "::error::bbup installed $("$BB" --version | tail -1), wanted $BB_VERSION" >&2
    exit 1
  }
fi
echo "Using bb $BB_VERSION at $BB"

# --- Regenerate ------------------------------------------------------------
"$BB" write_solidity_verifier -k "$DL/jwt_email/vk" \
  -o "$GEN/Verifier.sol" -t evm
"$BB" write_solidity_verifier -k "$DL/dyaka-noir-token/vk" \
  -o "$GEN/XHonkVerifier.sol" -t evm

perl -i -pe 's/assembly \{/assembly ("memory-safe") \{/g' \
  "$GEN/Verifier.sol" "$GEN/XHonkVerifier.sol"
perl -i -pe 's/contract HonkVerifier is BaseZKHonkVerifier/contract XHonkVerifier is BaseZKHonkVerifier/g' \
  "$GEN/XHonkVerifier.sol"

(cd "$REPO_ROOT/solidity" && forge fmt .circuits-check/Verifier.sol .circuits-check/XHonkVerifier.sol)

# --- Compare or write ------------------------------------------------------
PAIRS=(
  "$GEN/Verifier.sol:$REPO_ROOT/solidity/contracts/login/oidc/Verifier.sol"
  "$GEN/XHonkVerifier.sol:$REPO_ROOT/solidity/contracts/login/zk/XHonkVerifier.sol"
)

status=0
for pair in "${PAIRS[@]}"; do
  fresh="${pair%%:*}"
  committed="${pair##*:}"
  rel="${committed#"$REPO_ROOT"/}"
  if [ "$MODE" = "--write" ]; then
    if diff -q "$fresh" "$committed" >/dev/null 2>&1; then
      echo "$rel is already current."
    else
      cp "$fresh" "$committed"
      echo "$rel rewritten from the $TAG release vk."
    fi
  elif diff -q "$fresh" "$committed" >/dev/null; then
    echo "$rel reproduces from the release vk."
  else
    echo "::error::$rel does not match the verifier regenerated from the pinned circuits release" >&2
    git diff --no-index --stat "$committed" "$fresh" || true
    git diff --no-index "$committed" "$fresh" | head -60 || true
    status=1
  fi
done
exit "$status"
