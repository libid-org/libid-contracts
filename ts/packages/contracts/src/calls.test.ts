import { decodeFunctionData } from 'viem'
import { describe, expect, it } from 'vitest'

import { bankAbi } from './abis/bank.js'
import { identityNamesAbi } from './abis/identityNames.js'
import { calls } from './index.js'

const NAMES = '0x00000000000000000000000000000000000000aa' as const
const PLATFORM = `0x${'11'.repeat(32)}` as const

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
    const call = calls.bank.deposit(
      NAMES,
      7n,
      'x',
      'alice',
      'TIA',
      '0x00000000000000000000000000000000000000bb',
      3n,
    )

    expect(call.value).toBe(7n)
    expect(call.to).toBe(NAMES)
    expect(decodeFunctionData({ abi: bankAbi, data: call.data })).toEqual({
      functionName: 'deposit',
      args: ['x', 'alice', 'TIA', '0x00000000000000000000000000000000000000bb', 3n],
    })
  })

  it('namespaces by contract, so colliding names stay distinct', () => {
    // `initialize` is on almost every contract; the two must not be one export.
    expect(calls.identityNames.initialize).not.toBe(calls.registry.initialize)
  })
})
