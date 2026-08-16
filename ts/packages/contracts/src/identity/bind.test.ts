import { readFileSync } from 'node:fs'
import type { Hex } from 'viem'
import { describe, expect, it } from 'vitest'
import { b32, GITHUB_FIXTURE, GOOGLE_FIXTURE, NAMES, X_FIXTURE } from './bind.fixtures.js'
import {
  bindAtVersionCall,
  bindCall,
  encodeGitHubProof,
  encodeGoogleProof,
  encodeXProof,
  unpublishCall,
} from './bind.js'

/// One fixture, encoded here and decoded by `BindEncoding.t.sol`.
///
/// Two languages agreeing with each other proves only that they drift
/// together, so neither side authors this: the file is the contract's own
/// reading of what this module produced, and a change on either side stops
/// matching it.
const pinned = JSON.parse(
  readFileSync(
    new URL(
      '../../../../../solidity/contracts/identity/test/fixtures/bind-encoding.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as { github: Hex; x: Hex; google: Hex }

describe('encoding a proof for the chain', () => {
  it('encodes a GitHub proof the way the verifier reads it', () => {
    expect(encodeGitHubProof(GITHUB_FIXTURE)).toBe(pinned.github)
  })

  it('encodes an X proof the way the verifier reads it', () => {
    expect(encodeXProof(X_FIXTURE)).toBe(pinned.x)
  })

  it('encodes a Google proof the way the verifier reads it', () => {
    expect(encodeGoogleProof(GOOGLE_FIXTURE)).toBe(pinned.google)
  })
})

describe('building the call', () => {
  const platform = b32(0xabc)

  it('targets the naming contract and nothing else', () => {
    const call = bindCall(NAMES, platform, '0xdead', true)

    expect(call.to).toBe(NAMES)
    expect(call.data.startsWith('0x')).toBe(true)
  })

  /// The flag is a real argument, not decoration: publishing writes the handle
  /// as a string on chain, and for Google that string is an email address.
  it('carries the publish flag', () => {
    const published = bindCall(NAMES, platform, '0xdead', true)
    const not = bindCall(NAMES, platform, '0xdead', false)

    expect(published.data).not.toBe(not.data)
  })

  it('builds an unpublish that names only the platform', () => {
    const call = unpublishCall(NAMES, platform)

    expect(call.to).toBe(NAMES)
    expect(call.data.slice(0, 10)).not.toBe(
      bindCall(NAMES, platform, '0x', false).data.slice(0, 10),
    )
  })

  /// The fee rides in `value`; the CEILING rides in the calldata, because the
  /// chain has to enforce it.
  it('sends the fee as value and encodes the ceiling', () => {
    const paid = bindCall(NAMES, platform, '0xdead', false, 400000000000000n)
    const free = bindCall(NAMES, platform, '0xdead', false)

    expect(paid.value).toBe(400000000000000n)
    expect(free.value).toBe(0n)
    expect(paid.data).not.toBe(free.data)
  })

  /// The default ceiling is what was sent — "do not charge me more than I put
  /// up" — and a buffer is expressed by parting the two.
  it('defaults the ceiling to the value and lets a buffer cap lower', () => {
    const exact = bindCall(NAMES, platform, '0xdead', false, 100n)
    const capped = bindCall(NAMES, platform, '0xdead', false, 120n, 100n)

    expect(exact.value).toBe(100n)
    expect(capped.value).toBe(120n)
    // Same ceiling of 100 in both, so the calldata matches.
    expect(capped.data).toBe(exact.data)
  })

  /// Every builder sets it, so a wallet that spreads the call never has to
  /// guess whether the field is there.
  it('sets a value on every call it builds', () => {
    expect(unpublishCall(NAMES, platform).value).toBe(0n)
    expect(bindAtVersionCall(NAMES, platform, 2, '0xdead', false).value).toBe(0n)
    expect(bindAtVersionCall(NAMES, platform, 2, '0xdead', false, 7n).value).toBe(7n)
  })
})
