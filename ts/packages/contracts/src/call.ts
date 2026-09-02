// SPDX-License-Identifier: MIT
/// One contract call, as data rather than as an action.
///
/// The builders in `./calls` return this instead of sending anything: they
/// take no provider and no signer, so the caller decides how it is submitted —
/// directly, batched, or through a smart account's `execute`.
import type { Address, Hex } from 'viem'

export interface Call {
  to: Address
  /// ABI-encoded selector and arguments.
  data: Hex
  /// Set only by builders for payable functions.
  value?: bigint
}
