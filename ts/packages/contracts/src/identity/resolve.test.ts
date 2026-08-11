import {
  type Address,
  BaseError,
  ContractFunctionRevertedError,
  type PublicClient,
  zeroAddress,
} from 'viem'
import { describe, expect, it, vi } from 'vitest'

import { PLATFORM_X_DOMAIN } from './handleVectors.js'
import {
  type NamesReader,
  platformId,
  primaryName,
  resolveHandle,
  resolveId,
  resolvePair,
  reverseOf,
} from './resolve.js'

const CONTRACT = '0x1111111111111111111111111111111111111111' as Address
const ALICE = '0x2222222222222222222222222222222222222222' as Address

function reader(readContract: ReturnType<typeof vi.fn>): NamesReader {
  return {
    client: { readContract } as unknown as PublicClient,
    address: CONTRACT,
  }
}

const X = platformId(PLATFORM_X_DOMAIN)

describe('resolving a name', () => {
  /// The contract keys on the hash of the domain, and the domains are generated
  /// from handles.json — so this and the chain agree by construction rather
  /// than by somebody keeping two lists in step.
  it('derives the platform id from the generated domain', () => {
    expect(X).toMatch(/^0x[0-9a-f]{64}$/)
    expect(platformId(PLATFORM_X_DOMAIN)).toBe(X)
    expect(platformId('dyaka.identity.platform.github')).not.toBe(X)
  })

  it('reads the wallet that proved an account id', async () => {
    const readContract = vi.fn().mockResolvedValue(ALICE)
    expect(await resolveId(reader(readContract), X, '42')).toBe(ALICE)

    expect(readContract.mock.calls[0][0]).toMatchObject({
      address: CONTRACT,
      functionName: 'resolveId',
      args: [X, '42'],
    })
  })

  it('reads the wallet that last proved a handle', async () => {
    const readContract = vi.fn().mockResolvedValue(ALICE)
    expect(await resolveHandle(reader(readContract), X, 'alice')).toBe(ALICE)
  })

  /// An unbound name is absent, not the zero address. Handing a caller
  /// `0x000…0` invites sending funds to it.
  it('reports an unbound name as null rather than the zero address', async () => {
    const readContract = vi.fn().mockResolvedValue(zeroAddress)

    expect(await resolveId(reader(readContract), X, 'nobody')).toBeNull()
    expect(await resolveHandle(reader(readContract), X, 'nobody')).toBeNull()
  })

  /// The handle goes to the chain as the user typed it: normalization happens
  /// there, so the key a reader computes is the key a writer wrote.
  it('passes the handle through unnormalized', async () => {
    const readContract = vi.fn().mockResolvedValue(ALICE)
    await resolveHandle(reader(readContract), X, '  @Alice ')

    expect(readContract.mock.calls[0][0].args[1]).toBe('  @Alice ')
  })
})

describe('resolving a wallet back to a name', () => {
  it('reads the published handle verbatim', async () => {
    const readContract = vi.fn().mockResolvedValue('alice')
    expect(await reverseOf(reader(readContract), ALICE, X)).toBe('alice')
  })

  it('reports an unpublished handle as null', async () => {
    const readContract = vi.fn().mockResolvedValue('')
    expect(await reverseOf(reader(readContract), ALICE, X)).toBeNull()
  })

  /// `primaryOf` is forward-checked on chain, so a stale name arrives here as
  /// empty. ENS asks integrators to run that check themselves and warns that
  /// skipping it shows a name its holder no longer owns; this cannot skip it.
  it('gives no primary name once the handle has moved on', async () => {
    const readContract = vi.fn().mockResolvedValue('')
    expect(await primaryName(reader(readContract), ALICE, X)).toBeNull()
  })
})

describe('checking a handle against an account id', () => {
  it('agrees when both point at one wallet', async () => {
    const readContract = vi.fn().mockResolvedValue([ALICE, true])

    expect(await resolvePair(reader(readContract), X, 'alice', '42')).toEqual({
      wallet: ALICE,
      idAgrees: true,
    })
  })

  /// The case the two mappings exist for. The handle still resolves — and the
  /// transfer must still be allowed to go there, because that is what the name
  /// now means — but the caller learns its id is out of date and can say so
  /// before anybody signs.
  it('still resolves the handle when the id disagrees', async () => {
    const readContract = vi.fn().mockResolvedValue([ALICE, false])
    const pair = await resolvePair(reader(readContract), X, 'alice', '42')

    expect(pair.wallet).toBe(ALICE)
    expect(pair.idAgrees).toBe(false)
  })

  it('reports no wallet for a handle nobody has proved', async () => {
    const readContract = vi.fn().mockResolvedValue([zeroAddress, false])
    const pair = await resolvePair(reader(readContract), X, 'nobody', '42')

    expect(pair.wallet).toBeNull()
    expect(pair.idAgrees).toBe(false)
  })

  it('treats a handle the rules reject as unowned', async () => {
    // The contract is total in the handle: it answers about a string it could
    // never hold rather than reverting, so this is an ordinary zero answer.
    const readContract = vi.fn().mockResolvedValue([zeroAddress, false])

    expect(await resolvePair(reader(readContract), X, 'not a handle', '42')).toEqual({
      wallet: null,
      idAgrees: false,
    })
  })
})

/// A revert as viem hands it over: a `ContractFunctionRevertedError` reachable
/// through the thrown error's `walk`.
function revertingWith(errorName: string): BaseError {
  const reverted = Object.create(
    ContractFunctionRevertedError.prototype,
  ) as ContractFunctionRevertedError
  Object.assign(reverted, { data: { errorName, args: [] } })

  const outer = new BaseError('reverted')
  outer.walk = ((fn?: (e: unknown) => boolean) =>
    fn ? (fn(reverted) ? reverted : null) : reverted) as BaseError['walk']
  return outer
}

describe('a handle that cannot be normalized', () => {
  /// Nobody owns a string that is not a handle on that platform, and the
  /// contract says so with a zero address rather than a revert — which is what
  /// a search box needs, since the alternative is a rejected promise on every
  /// keystroke that has not finished being typed.
  it('reads as unowned', async () => {
    const readContract = vi.fn().mockResolvedValue(zeroAddress)

    expect(await resolveHandle(reader(readContract), X, 'not a handle')).toBeNull()
  })

  /// An unconfigured platform is a deployment mistake, not an answer about a
  /// name. Reporting it as "unowned" would hide it behind a plausible result.
  it('lets an unconfigured platform surface', async () => {
    const readContract = vi.fn().mockRejectedValue(revertingWith('UnknownPlatform'))

    await expect(resolveHandle(reader(readContract), X, 'alice')).rejects.toThrow()
  })
})
