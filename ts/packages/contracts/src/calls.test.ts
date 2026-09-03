import { decodeFunctionData } from 'viem'
import { describe, expect, it } from 'vitest'

import { googleJwtRootsAbi } from './abis/googleJwtRoots.js'
import { identityNamesAbi } from './abis/identityNames.js'
import { calls } from './index.js'

const NAMES = '0x00000000000000000000000000000000000000aa' as const
const ROOTS = '0x00000000000000000000000000000000000000cc' as const
const PLATFORM = `0x${'11'.repeat(32)}` as const
// Opaque to the builder: the contract decodes the record and the Notary
// Service checks the proof, so any bytes round-trip through the ABI here.
const ATTESTED = `0x${'a7'.repeat(40)}` as const
const PROOF = `0x${'b8'.repeat(65)}` as const

describe('generated call builders', () => {
  it('encodes a call the ABI decodes back to the same arguments', () => {
    const call = calls.identityNames.unpublish(NAMES, PLATFORM)

    expect(call.to).toBe(NAMES)
    expect(decodeFunctionData({ abi: identityNamesAbi, data: call.data })).toEqual({
      functionName: 'unpublish',
      args: [PLATFORM],
    })
  })

  it('carries a selector and nothing but the declared arguments', () => {
    // Withdrawing what you chose to show must not depend on proving anything
    // again, so this call is a selector and one word.
    expect(calls.identityNames.unpublish(NAMES, PLATFORM).data.length).toBe(2 + 8 + 64)
  })

  it('omits value on a nonpayable function', () => {
    expect(calls.identityNames.unpublish(NAMES, PLATFORM).value).toBeUndefined()
  })

  it('takes value before the arguments on a payable function', () => {
    // A rotation pays the Notary Fee, so the value is the part a caller must
    // not be able to forget: it comes before the attested bytes and the proof.
    const call = calls.googleJwtRoots.rotate(ROOTS, 7n, ATTESTED, PROOF)

    expect(call.value).toBe(7n)
    expect(call.to).toBe(ROOTS)
    expect(decodeFunctionData({ abi: googleJwtRootsAbi, data: call.data })).toEqual({
      functionName: 'rotate',
      args: [ATTESTED, PROOF],
    })
  })

  it('namespaces by contract, so colliding names stay distinct', () => {
    // `initialize` is on almost every contract; the two must not be one export.
    expect(calls.notaryService.initialize).not.toBe(calls.identityNames.initialize)
  })
})
