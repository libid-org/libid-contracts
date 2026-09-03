# @libid/contracts

Typed, viem-ready ABIs for every libid contract, a call builder for every
state-changing function, and the identity helper layer: handle normalization,
proof encoding for `bind`, and name resolution.

Both `src/abis/` and `src/calls/` are generated from the forge artifacts
(`solidity/out`) by `scripts/codegen.mjs`, and neither is committed — CI
regenerates them before every build, test and publish. Each ABI is exported
`as const satisfies Abi`, so viem infers argument and return types from it, and
each call builder reads its arguments off that ABI, so adding a write function
to a contract produces its wrapper instead of requiring someone to remember to
write one. The handle vector table in `src/identity/handleVectors.ts` is
generated from `solidity/contracts/identity/handles.json` by
`scripts/regen-identity-handles.py`.

```sh
pnpm add @libid/contracts viem
```

## Reading a contract with viem

```ts
import { createPublicClient, http } from 'viem'
import { identityJwksRootsAbi, identityNamesAbi } from '@libid/contracts/abis'

const client = createPublicClient({ transport: http(RPC_URL) })

// Fully typed: viem infers the argument and return types from the ABI.
const owner = await client.readContract({
  address: IDENTITY_NAMES,
  abi: identityNamesAbi,
  functionName: 'resolveHandle',
  args: [platformId, 'alice'],
})

const roots = await client.readContract({
  address: IDENTITY_JWKS_ROOTS,
  abi: identityJwksRootsAbi,
  functionName: 'currentRoots',
})
```

## Building a call

One builder per state-changing function, namespaced by contract because names
like `initialize` are on almost all of them. A builder returns the call as
data — no provider, no signer — so you decide how it is submitted: directly,
batched, or through a smart account's `execute`.

```ts
import { calls } from '@libid/contracts/calls'

const call = calls.identityNames.unpublish(names, platformId)
// { to: `0x…`, data: `0x…` }

await wallet.sendTransaction(call)
```

Arguments are typed from the ABI, so a wrong type or a missing argument fails
to compile rather than reverting on chain. Payable functions take `value`
before their arguments and set it on the returned call:

```ts
// A JWKS rotation pays the Notary Fee: read it with `quoteRotation` first.
const rotate = calls.identityJwksRoots.rotate(roots, fee, attestedData, proof)
// { to: `0x…`, value: fee, data: `0x…` }
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
pnpm -C ts codegen           # generate src/abis/ + src/calls/ (gitignored; required first)
pnpm -C ts build             # tsc → dist/ (ESM + .d.ts)
pnpm -C ts test              # vitest
pnpm -C ts lint && pnpm -C ts fmt:check
```
