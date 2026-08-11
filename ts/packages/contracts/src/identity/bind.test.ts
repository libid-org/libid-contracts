import { readFileSync } from 'node:fs'
import type { Hex } from 'viem'
import { describe, expect, it } from 'vitest'
import { b32, GITHUB_FIXTURE, GOOGLE_FIXTURE, NAMES, X_FIXTURE } from './bind.fixtures.js'
import {
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
})
