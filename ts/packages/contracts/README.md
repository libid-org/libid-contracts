# @libid/contracts

Typed, viem-ready ABIs for every libid contract, plus the identity helper
layer: handle normalization, proof encoding for `bind`, and name resolution.

The ABIs in `src/abis/` are generated from the forge artifacts
(`solidity/out`) by `scripts/codegen.mjs` and committed; each is exported
`as const satisfies Abi`, so viem infers argument and return types from them.
The handle vector table in `src/identity/handleVectors.ts` is generated from
`solidity/contracts/identity/handles.json` by
`scripts/regen-identity-handles.py`.

```sh
pnpm add @libid/contracts viem
```

## Reading a contract with viem

```ts
import { createPublicClient, http } from 'viem'
import { registryAbi, bankAbi } from '@libid/contracts/abis'

const client = createPublicClient({ transport: http(RPC_URL) })

// Fully typed: viem infers the argument and return types from the ABI.
const wallet = await client.readContract({
  address: REGISTRY,
  abi: registryAbi,
  functionName: 'walletOf',
  args: ['github', '583231'],
})

const tokens = await client.readContract({
  address: BANK,
  abi: bankAbi,
  functionName: 'getRegisteredTokens',
})
```

## Resolving a name

```ts
import {
  platformId,
  resolveHandle,
  resolvePair,
  primaryName,
  PLATFORM_X_DOMAIN,
} from '@libid/contracts/identity'

const reader = { client, address: IDENTITY_NAMES }
const x = platformId(PLATFORM_X_DOMAIN)

// The wallet that last proved a handle, or null. Pass what the user typed —
// normalization happens on chain.
const owner = await resolveHandle(reader, x, '@Alice')

// Before sending funds: does the account id still agree with the handle?
const { wallet, idAgrees } = await resolvePair(reader, x, 'alice', '42')

// The display name for a wallet, forward-checked on chain.
const name = await primaryName(reader, wallet!, x)
```

## Binding a name

`bindCall` builds calldata and nothing more — an EOA sends it directly, a
smart account wraps it in its own execute:

```ts
import { bindCall, encodeGitHubProof, platformId, PLATFORM_GITHUB_DOMAIN } from '@libid/contracts/identity'

const proof = encodeGitHubProof(gitHubProof) // from the notarization flow
const call = bindCall(IDENTITY_NAMES, platformId(PLATFORM_GITHUB_DOMAIN), proof, true)
// call = { to, data } — sign and send from the address the proof names.
```

## Normalizing a handle locally

```ts
import { normalize, RULES_X, HandleError } from '@libid/contracts/identity'

normalize(' @Alice_1 ', RULES_X) // 'alice_1'
// Throws HandleError (with a kind matching the on-chain error) on refusal.
```

## Development

```sh
cd solidity && forge build   # codegen reads the artifacts
pnpm -C ts install
pnpm -C ts codegen           # regenerate src/abis/ (codegen:check diffs)
pnpm -C ts build             # tsc → dist/ (ESM + .d.ts)
pnpm -C ts test              # vitest
pnpm -C ts lint && pnpm -C ts fmt:check
```
