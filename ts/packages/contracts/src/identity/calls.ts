// SPDX-License-Identifier: MIT
/// Calldata for the naming contract's own writes.
///
/// Binding goes through `claim`, which takes a ceremony submission — that
/// encoder lives in `../ceremony/`. What is left here is the one write that
/// needs no proof at all.
import { encodeFunctionData } from 'viem'
import type { Address, Hex } from 'viem'

import { identityNamesAbi } from '../abis/identityNames.js'

export interface Call {
  to: Address
  data: Hex
}

/// Withdraw a published handle. The binding itself stays: this stops the chain
/// displaying the string, and needs no proof, because withdrawing what you
/// chose to show must not depend on being able to log in again.
export function unpublishCall(names: Address, platformId: Hex): Call {
  return {
    to: names,
    data: encodeFunctionData({
      abi: identityNamesAbi,
      functionName: 'unpublish',
      args: [platformId],
    }),
  }
}
