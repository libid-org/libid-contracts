/// Binding a name: the write half.
///
/// Reading a name is a view call and needs nothing. Writing one is a
/// transaction the holder's own address sends, because `IdentityNames` requires
/// the proof's target to be the caller — that single rule is the whole of the
/// authorization, and it is why a proof read from the mempool is useless to
/// anybody else.
///
/// This module builds the calldata and nothing more. It does not sign, does not
/// send, and does not know what kind of address the caller is: an EOA sends it
/// directly, a smart account wraps it in whatever its own execute looks like.
/// Keeping it at calldata is what lets a product with its own account model use
/// the naming system without either side knowing about the other.

import { type Address, encodeAbiParameters, encodeFunctionData, type Hex } from 'viem'

import { identityNamesAbi } from '../abis/identityNames.js'

/// The proof each platform's verifier takes, as it travels on chain.
///
/// The verifier decodes one `bytes` argument, so a platform's fields are
/// abi-encoded into it here. The shapes mirror the verifier structs exactly; a
/// mismatch does not compile there and reverts here, which is why they are
/// written out rather than built by hand at a call site.

/// One notarized TLS session, as `GitHubIdentityVerifier` takes it.
export interface TlsProof {
  notarySignature: Hex
  backendSignature: Hex
  userAddress: Address
  /// The address the proof is made out to. `IdentityNames` refuses a zero.
  walletAddress: Address
  domainHash: Hex
  clientRandom: Hex
  serverRandom: Hex
  serverEphemeralKey: Hex
  transcriptRoot: Hex
  timestamp: bigint
  domainPath: readonly Hex[]
  usernamePath: readonly Hex[]
  endpointPath: readonly Hex[]
  idPath: readonly Hex[]
}

export interface GitHubProof {
  tls: TlsProof
  domain: string
  handle: string
  userId: string
  endpoint: string
}

/// The notarized `/me` session, as `XIdentityVerifier` takes it. There is only
/// one: a name binding does not read the OAuth client id, so it never asks for
/// the `/token` session that exists to carry it.
export interface MeAttestation {
  bearerHash: Hex
  bearerRangeStart: number
  bearerRangeEnd: number
  sentRevealed: Hex
  sentPrefixEnd: number
  sentSuffixEnd: number
  recvRevealed: Hex
  handle: string
  userId: string
  sessionAddr: Address
  timestamp: bigint
  notarySignature: Hex
}

export interface XProof {
  proof: Hex
  publicInputs: readonly Hex[]
  meAttest: MeAttestation
}

export interface GoogleProof {
  honkProof: Hex
  publicInputs: readonly Hex[]
  email: string
  /// The address inside the Google-signed nonce. This is the target, so it must
  /// be the address that will hold the name — the wallet, not a session key.
  sessionKey: Address
  sub: string
}

const tlsProofComponents = [
  { name: 'notarySignature', type: 'bytes' },
  { name: 'backendSignature', type: 'bytes' },
  { name: 'userAddress', type: 'address' },
  { name: 'walletAddress', type: 'address' },
  { name: 'domainHash', type: 'bytes32' },
  { name: 'clientRandom', type: 'bytes32' },
  { name: 'serverRandom', type: 'bytes32' },
  { name: 'serverEphemeralKey', type: 'bytes' },
  { name: 'transcriptRoot', type: 'bytes32' },
  { name: 'timestamp', type: 'uint256' },
  { name: 'domainPath', type: 'bytes32[]' },
  { name: 'usernamePath', type: 'bytes32[]' },
  { name: 'endpointPath', type: 'bytes32[]' },
  { name: 'idPath', type: 'bytes32[]' },
] as const

export function encodeGitHubProof(p: GitHubProof): Hex {
  return encodeAbiParameters(
    [
      {
        type: 'tuple',
        components: [
          { name: 'tls', type: 'tuple', components: tlsProofComponents },
          { name: 'domain', type: 'string' },
          { name: 'handle', type: 'string' },
          { name: 'userId', type: 'string' },
          { name: 'endpoint', type: 'string' },
        ],
      },
    ],
    [p],
  )
}

export function encodeXProof(p: XProof): Hex {
  return encodeAbiParameters(
    [
      {
        type: 'tuple',
        components: [
          { name: 'proof', type: 'bytes' },
          { name: 'publicInputs', type: 'bytes32[]' },
          {
            name: 'meAttest',
            type: 'tuple',
            components: [
              { name: 'bearerHash', type: 'bytes32' },
              { name: 'bearerRangeStart', type: 'uint32' },
              { name: 'bearerRangeEnd', type: 'uint32' },
              { name: 'sentRevealed', type: 'bytes' },
              { name: 'sentPrefixEnd', type: 'uint32' },
              { name: 'sentSuffixEnd', type: 'uint32' },
              { name: 'recvRevealed', type: 'bytes' },
              { name: 'handle', type: 'string' },
              { name: 'userId', type: 'string' },
              { name: 'sessionAddr', type: 'address' },
              { name: 'timestamp', type: 'uint64' },
              { name: 'notarySignature', type: 'bytes' },
            ],
          },
        ],
      },
    ],
    [p],
  )
}

export function encodeGoogleProof(p: GoogleProof): Hex {
  return encodeAbiParameters(
    [
      {
        type: 'tuple',
        components: [
          { name: 'honkProof', type: 'bytes' },
          { name: 'publicInputs', type: 'bytes32[]' },
          { name: 'email', type: 'string' },
          { name: 'sessionKey', type: 'address' },
          { name: 'sub', type: 'string' },
        ],
      },
    ],
    [p],
  )
}

/// One call, ready to send or to wrap.
export interface Call {
  to: Address
  data: Hex
}

/// Bind a proven account to the caller.
///
/// `publishName` also stores the handle as a string, so a contract can read the
/// reverse direction on chain. The event carries the plaintext either way, so
/// an indexer never needs it — say true only when something on chain must
/// display the name. For Google the handle is an email address, which is worth
/// a thought before publishing it.
export function bindCall(names: Address, platformId: Hex, proof: Hex, publishName: boolean): Call {
  return {
    to: names,
    data: encodeFunctionData({
      abi: identityNamesAbi,
      functionName: 'bind',
      args: [platformId, proof, publishName],
    }),
  }
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
