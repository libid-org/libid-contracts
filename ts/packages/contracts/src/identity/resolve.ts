/// Reading names from the chain.
///
/// Everything here is a view call. Binding a name needs a proof and a wallet;
/// reading one needs neither, which is the point — any product can resolve a
/// name without touching the login that created it.
///
/// The client and the contract address are arguments rather than imports. This
/// package ships separately from the repository it currently lives in, so it
/// carries no configuration of its own and reaches for nothing outside itself.

import { type Address, keccak256, type PublicClient, toHex, zeroAddress } from 'viem'

import { identityNamesAbi } from '../abis/identityNames.js'

/// A platform id is `keccak256` of its domain string. The domains are generated
/// from `handles.json`, so this and the contract agree by construction.
export function platformId(domain: string): `0x${string}` {
  return keccak256(toHex(domain))
}

export interface NamesReader {
  client: PublicClient
  /// The deployed `IdentityNames` contract.
  address: Address
}

/// One view call.
///
/// Routed through a narrow cast for the same reason the wallet package does it:
/// viem's `PublicClient`, without its chain type parameters, types
/// `authorizationList` as required even for a read. The alternative is to
/// spread that noise across every call site here.
function read<T>(reader: NamesReader, functionName: string, args: readonly unknown[]): Promise<T> {
  return (
    reader.client as unknown as {
      readContract: (request: Record<string, unknown>) => Promise<T>
    }
  ).readContract({
    authorizationList: undefined,
    address: reader.address,
    abi: identityNamesAbi,
    functionName,
    args,
  })
}

/// The wallet that proved this account id, or `null`.
export async function resolveId(
  reader: NamesReader,
  platform: `0x${string}`,
  userId: string,
): Promise<Address | null> {
  const owner = await read<Address>(reader, 'resolveId', [platform, userId])
  return owner === zeroAddress ? null : owner
}

/// The wallet that last proved this handle, or `null`.
///
/// The handle is normalized on chain before it is looked up, so a caller may
/// pass what a user typed — including something that is not a handle at all.
/// The contract is total in the handle: a string no platform could hold answers
/// the zero address, which is the same answer as a handle nobody has proved,
/// and the one a search box wants.
///
/// A revert propagates. `UnknownPlatform` in particular means the platform is
/// not configured, and answering "unowned" would bury a deployment mistake
/// under a plausible result.
export async function resolveHandle(
  reader: NamesReader,
  platform: `0x${string}`,
  handle: string,
): Promise<Address | null> {
  const owner = await read<Address>(reader, 'resolveHandle', [platform, handle])
  return owner === zeroAddress ? null : owner
}

/// The handle a wallet published, exactly as stored.
///
/// It may be stale: it says what the wallet proved once, not what the handle
/// resolves to now. Use `primaryName` to display one.
export async function reverseOf(
  reader: NamesReader,
  wallet: Address,
  platform: `0x${string}`,
): Promise<string | null> {
  const name = await read<string>(reader, 'reverseOf', [wallet, platform])
  return name.length === 0 ? null : name
}

/// The handle to show for a wallet, or `null`.
///
/// Forward-checked on chain: empty once the stored handle resolves somewhere
/// else. ENS asks integrators to perform that check themselves and warns that
/// skipping it displays a name its holder no longer owns; here it cannot be
/// skipped, because the contract does it.
export async function primaryName(
  reader: NamesReader,
  wallet: Address,
  platform: `0x${string}`,
): Promise<string | null> {
  const name = await read<string>(reader, 'primaryOf', [wallet, platform])
  return name.length === 0 ? null : name
}

export interface PairResolution {
  /// The current owner of the handle, or `null`.
  wallet: Address | null
  /// True only when the account id resolves to that same wallet.
  ///
  /// False means the caller's `(handle, id)` pair comes from two moments:
  /// somebody proved the handle after the caller learned who held it. That is
  /// staleness, not corruption.
  idAgrees: boolean
}

/// Resolve a handle and report whether an account id still agrees with it.
///
/// **Read this before signing, and do not let it block a transfer.** A name
/// that will not route is not a name: sending to a handle means sending to
/// whoever proved it last, which is what the handle now means. What the flag is
/// for is telling a user that the account they think they are paying is not the
/// one that holds the name today — a decision they can only make beforehand.
///
/// Both halves are needed. A handle on its own has nothing to disagree with.
///
/// A handle the platform's rules reject resolves to `{wallet: null, idAgrees:
/// false}`, the same as one nobody has proved — see `resolveHandle`.
export async function resolvePair(
  reader: NamesReader,
  platform: `0x${string}`,
  handle: string,
  userId: string,
): Promise<PairResolution> {
  const [wallet, idAgrees] = await read<[Address, boolean]>(reader, 'resolvePair', [
    platform,
    handle,
    userId,
  ])

  return { wallet: wallet === zeroAddress ? null : wallet, idAgrees }
}

/// What binding this account will cost, in wei. Zero when it is free.
///
/// Quote this before building the bind and pass it to `bindCall`. It answers
/// for THIS account: zero once the account is bound, so a rename or a move to
/// another wallet costs nothing and reaches that zero without the chain
/// consulting a price source at all.
///
/// **It can throw.** A deployment that charges a fee and whose price source has
/// gone stale refuses to quote rather than naming a price nobody has confirmed.
/// Treat the throw as "cannot bind right now", not as zero.
export function bindFee(
  reader: NamesReader,
  platform: `0x${string}`,
  userId: string,
): Promise<bigint> {
  return read<bigint>(reader, 'bindFeeWeiFor', [platform, userId])
}
