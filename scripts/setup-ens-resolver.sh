#!/usr/bin/env bash
# Point an ENS name at a freshly deployed HandleResolver, signing with the
# deployer's KMS key.
#
# The name is already claimed — `handles.link` was imported through
# `DNSRegistrar` — so this is the two steps that remain: deploy the resolver,
# and set it on the node. Nothing here writes a record; the resolver holds
# none.
#
#   AWS_REGION=eu-central-1 \
#   AWS_KMS_KEY_ID=alias/dyaka-testnet-deployer \
#   RPC_URL=https://… \
#   GATEWAY_URL='https://gw.example/{sender}/{data}.json' \
#   GATEWAY_SIGNER=0x… \
#   scripts/setup-ens-resolver.sh [--execute]
#
# Without `--execute` it checks every precondition and prints what it would
# send. That is the default because these are real transactions on a public
# chain.
set -euo pipefail

ENS_NAME="${ENS_NAME:-handles.link}"
# The ENS registry sits at one address on mainnet and every testnet.
REGISTRY="${REGISTRY:-0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e}"
EXECUTE="${1:-}"

need() { [ -n "${!1:-}" ] || { echo "set $1" >&2; exit 2; }; }
need RPC_URL
need AWS_REGION
need AWS_KMS_KEY_ID
need GATEWAY_URL
need GATEWAY_SIGNER

# ERC-3668 substitutes these; a URL without them reaches the gateway carrying
# no query at all, and every name fails with an opaque client-side error while
# the deploy, `urlCount()` and the interface probe all report success.
case "$GATEWAY_URL" in
    *'{sender}'*'{data}'*) ;;
    *) echo "refusing: GATEWAY_URL must carry the {sender} and {data} placeholders" >&2
       exit 1 ;;
esac

node=$(cast namehash "$ENS_NAME")
echo "name      $ENS_NAME"
echo "node      $node"
echo "chain     $(cast chain-id --rpc-url "$RPC_URL")"

# ── who the KMS key is ───────────────────────────────────────────────────────
signer=$(cast wallet address --aws)
echo "signer    $signer  (from $AWS_KMS_KEY_ID)"

# ── and whether that is the account that may set the resolver ────────────────
# Checked rather than assumed: `setResolver` reverts for anyone else, and a
# revert after a deploy leaves a contract nobody points at.
owner=$(cast call "$REGISTRY" "owner(bytes32)(address)" "$node" --rpc-url "$RPC_URL")
echo "owner     $owner"
if [ "${owner,,}" != "${signer,,}" ]; then
    echo "refusing: the KMS key is not the owner of $ENS_NAME" >&2
    exit 1
fi

balance=$(cast balance "$signer" --rpc-url "$RPC_URL")
echo "balance   $(cast to-unit "$balance" ether) ETH"
[ "$balance" != "0" ] || { echo "refusing: the deployer cannot pay for gas" >&2; exit 1; }

current=$(cast call "$REGISTRY" "resolver(bytes32)(address)" "$node" --rpc-url "$RPC_URL")
echo "resolver  $current"

echo
echo "would deploy HandleResolver(owner=$signer, urls=[$GATEWAY_URL], signers=[$GATEWAY_SIGNER])"
echo "would call  setResolver($node, <deployed>)"

if [ "$EXECUTE" != "--execute" ]; then
    echo
    echo "dry run. re-run with --execute to send."
    exit 0
fi

echo
# `--json` goes BEFORE `--constructor-args`, and that is not style: the
# argument list is greedy, so a flag after it is swallowed as one more
# constructor value and forge reports an arity mismatch that names nothing.
# The address array is unquoted and the string array is quoted, which is what
# forge's parser wants.
resolver=$(cd solidity && forge create --aws --broadcast --rpc-url "$RPC_URL" --json \
    contracts/ens/HandleResolver.sol:HandleResolver \
    --constructor-args "$signer" "[\"$GATEWAY_URL\"]" "[$GATEWAY_SIGNER]" \
    | jq -r '.deployedTo // empty')
# Validated, because the next line spends the deploy: `forge create` can exit 0
# with a payload this does not name, and `setResolver(node, null)` would abort
# AFTER a contract was paid for, leaving it orphaned and the node unchanged.
case "$resolver" in
    0x[0-9a-fA-F][0-9a-fA-F]*) [ ${#resolver} -eq 42 ] || resolver="" ;;
    *) resolver="" ;;
esac
[ -n "$resolver" ] || { echo "refusing: forge create returned no address" >&2; exit 1; }
echo "deployed  $resolver"

cast send --aws --rpc-url "$RPC_URL" "$REGISTRY" \
    "setResolver(bytes32,address)" "$node" "$resolver" >/dev/null
# Read back and COMPARE. `cast send` returns 0 for a transaction that reverted,
# so printing the registry value without checking it reports success for a name
# that still points at whatever it did before.
now=$(cast call "$REGISTRY" "resolver(bytes32)(address)" "$node" --rpc-url "$RPC_URL")
echo "set       $now"
if [ "${now,,}" != "${resolver,,}" ]; then
    echo "refusing: the registry still names $now — setResolver did not take" >&2
    exit 1
fi

# ── the name now answers, and answering means reverting ──────────────────────
echo
echo "checking that resolution reaches it:"
# Asked of the registry's resolver rather than of `$resolver`, so this probes
# what a client would actually reach.
wildcard=$(cast call "$now" "supportsInterface(bytes4)(bool)" 0x9061b923 --rpc-url "$RPC_URL")
echo "  ENSIP-10 announced: $wildcard"
[ "$wildcard" = "true" ] || { echo "refusing: the resolver does not announce ENSIP-10" >&2; exit 1; }
