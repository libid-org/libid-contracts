#!/usr/bin/env bash
# Vendor the forge artifacts the Rust crate embeds.
#
# Runs `forge build` in solidity/ (submodules must be initialized), then copies
# the artifact JSONs the crate needs from solidity/out into
# rust/contracts/artifacts/<File>.sol/<Name>.json, pruned to the fields the
# crate reads: bytecode.object, bytecode.linkReferences, methodIdentifiers.
# Libraries referenced through linkReferences are followed transitively and
# vendored too (none of the covered contracts links one today; the Honk
# verifiers the ceremony circuits will bring do).
#
# The result is NOT committed: rust/contracts/artifacts is gitignored and
# regenerated on demand. Run this before any cargo command in rust/ — the
# crate embeds the directory with include_dir!, so a missing one is a compile
# error. CI runs it in every job that touches the crate, publishing included.
#
# solc is pinned (0.8.33) and via_ir builds are deterministic, so two runs of
# this script over the same contracts produce byte-identical output.
#
# Usage:
#   scripts/vendor-artifacts.sh           # regenerate rust/contracts/artifacts
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/solidity/out"
DEST="$REPO_ROOT/rust/contracts/artifacts"

# "<File>:<Contract>" — the artifact lives at out/<File>.sol/<Contract>.json.
# Keep in sync with the covered-contract list in rust/contracts/src/artifacts.rs.
ARTIFACTS=(
    # ceremony
    "NotaryService:NotaryService"
    "CeremonyProofVerifier:CeremonyProofVerifier"
    "ERC1967Proxy:ERC1967Proxy"
    # identity
    "IdentityNames:IdentityNames"
    "IdentityJwksRoots:IdentityJwksRoots"
    # factory
    "LibidFactory:LibidFactory"
    "WTIA9:WTIA9"
)

if [[ $# -gt 0 ]]; then
    echo "unknown argument: $1" >&2
    exit 2
fi

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

echo "==> forge build"
(cd "$REPO_ROOT/solidity" && forge build)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# prune <src> <file> <contract>: write the pruned artifact into the stage.
prune() {
    local src="$1" file="$2" contract="$3"
    mkdir -p "$STAGE/$file.sol"
    jq -S '{
        bytecode: {
            object: .bytecode.object,
            linkReferences: .bytecode.linkReferences
        },
        methodIdentifiers: .methodIdentifiers
    }' "$src" > "$STAGE/$file.sol/$contract.json"
}

# Vendor the listed artifacts, then follow linkReferences transitively so every
# library the crate's linker needs ships too.
queue=("${ARTIFACTS[@]}")
seen=""
while [[ ${#queue[@]} -gt 0 ]]; do
    entry="${queue[0]}"
    queue=("${queue[@]:1}")
    case " $seen " in *" $entry "*) continue ;; esac
    seen="$seen $entry"

    file="${entry%%:*}"
    contract="${entry##*:}"
    src="$OUT/$file.sol/$contract.json"
    if [[ ! -f "$src" ]]; then
        echo "missing artifact: $src (did forge build succeed?)" >&2
        exit 1
    fi
    prune "$src" "$file" "$contract"

    # linkReferences: { "path/to/LibFile.sol": { "LibName": [...] } } — the
    # library artifact lives at out/<LibFile>.sol/<LibName>.json.
    while IFS=: read -r lib_path lib_name; do
        [[ -n "$lib_path" ]] || continue
        lib_file="$(basename "$lib_path" .sol)"
        queue+=("$lib_file:$lib_name")
    done < <(jq -r '.bytecode.linkReferences // {}
                    | to_entries[]
                    | .key as $p
                    | .value | keys[]
                    | "\($p):\(.)"' "$src")
done

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$STAGE" "$DEST"
echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into rust/contracts/artifacts"
