#!/usr/bin/env bash
# Vendor the forge artifacts the Rust crate embeds.
#
# Runs `forge build` in solidity/ (submodules must be initialized), then copies
# the artifact JSONs the crate needs from solidity/out into
# rust/contracts/artifacts/<File>.sol/<Name>.json, pruned to the fields the
# crate reads: bytecode.object, bytecode.linkReferences, methodIdentifiers.
# Libraries referenced through linkReferences (e.g. ZKTranscriptLib for the
# Honk verifiers) are followed transitively and vendored too.
#
# The result is committed. solc is pinned (0.8.33) and via_ir builds are
# deterministic, so regeneration is reproducible.
#
# Usage:
#   scripts/vendor-artifacts.sh           # regenerate rust/contracts/artifacts
#   scripts/vendor-artifacts.sh --check   # regenerate to a temp dir, diff
#                                         # against the committed copy, exit
#                                         # nonzero on drift
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/solidity/out"
DEST="$REPO_ROOT/rust/contracts/artifacts"

# "<File>:<Contract>" — the artifact lives at out/<File>.sol/<Contract>.json.
# Keep in sync with the covered-contract list in rust/contracts/src/artifacts.rs.
ARTIFACTS=(
    # login
    "Registry:Registry"
    "Notary:Notary"
    "WalletFactory:WalletFactory"
    "WebWallet:WebWallet"
    "ERC1967Proxy:ERC1967Proxy"
    "XZkVerifier:XZkVerifier"
    "XHonkVerifier:XHonkVerifier"
    # oidc (the Google OIDC circuit verifier is generated into Verifier.sol
    # under the contract name HonkVerifier)
    "Verifier:HonkVerifier"
    "GoogleOidcVerifier:GoogleOidcVerifier"
    # transfer (bank diamond)
    "Diamond:Diamond"
    "DiamondCutFacet:DiamondCutFacet"
    "DiamondLoupeFacet:DiamondLoupeFacet"
    "OwnershipFacet:OwnershipFacet"
    "AdminFacet:AdminFacet"
    "VaultFacet:VaultFacet"
    "TransferFacet:TransferFacet"
    "BankInit:BankInit"
    "IBank:IBank"
    "MockERC20:MockERC20"
    "WTIA9:WTIA9"
    # identity
    "IdentityNames:IdentityNames"
    "GitHubIdentityVerifier:GitHubIdentityVerifier"
    "GoogleIdentityVerifier:GoogleIdentityVerifier"
    "XIdentityVerifier:XIdentityVerifier"
    "IdentityJwksRoots:IdentityJwksRoots"
    # identity — the native token price, for the first-bind fee. Which one a
    # chain gets is the whole of the configuration: the Chainlink wrapper where
    # a feed exists, the owner-pushed one where none does.
    "ChainlinkNativePriceSource:ChainlinkNativePriceSource"
    "OwnerPushedNativePriceSource:OwnerPushedNativePriceSource"
    # factory
    "LibidFactory:LibidFactory"
)

MODE="vendor"
if [[ "${1:-}" == "--check" ]]; then
    MODE="check"
elif [[ $# -gt 0 ]]; then
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

if [[ "$MODE" == "check" ]]; then
    if diff -r "$STAGE" "$DEST" >/dev/null 2>&1; then
        echo "==> artifacts are up to date"
    else
        echo "==> vendored artifacts drift from solidity/out:" >&2
        diff -r "$STAGE" "$DEST" >&2 || true
        echo "run scripts/vendor-artifacts.sh and commit the result" >&2
        exit 1
    fi
else
    rm -rf "$DEST"
    mkdir -p "$(dirname "$DEST")"
    cp -R "$STAGE" "$DEST"
    echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into rust/contracts/artifacts"
fi
