/// The proofs the encoding tests pin.
///
/// Their own module so the generator that writes `fixtures/bind-encoding.json`
/// and the test that checks against it read the same values — and so the shapes
/// double as a worked example of what each verifier takes.

import type { Address, Hex } from 'viem'

import type { GitHubProof, GoogleProof, XProof } from './bind.js'

export const NAMES = '0x1111111111111111111111111111111111111111' as Address
const WALLET = '0x2222222222222222222222222222222222222222' as Address
const SESSION = '0x3333333333333333333333333333333333333333' as Address

export const b32 = (n: number): Hex => `0x${n.toString(16).padStart(64, '0')}`

export const GITHUB_FIXTURE: GitHubProof = {
  tls: {
    notarySignature: '0xaabb',
    backendSignature: '0xccdd',
    userAddress: SESSION,
    walletAddress: WALLET,
    domainHash: b32(1),
    clientRandom: b32(2),
    serverRandom: b32(3),
    serverEphemeralKey: '0xeeff',
    transcriptRoot: b32(4),
    timestamp: 1_700_000_000n,
    domainPath: [b32(5), b32(6)],
    usernamePath: [b32(7)],
    endpointPath: [],
    idPath: [b32(8), b32(9), b32(10)],
  },
  domain: 'api.github.com',
  handle: 'octocat',
  userId: '583231',
  endpoint: '/user',
}

export const X_FIXTURE: XProof = {
  proof: '0x1234',
  publicInputs: [b32(11), b32(12)],
  meAttest: {
    bearerHash: b32(13),
    bearerRangeStart: 100,
    bearerRangeEnd: 200,
    sentRevealed: '0x5566',
    sentPrefixEnd: 100,
    sentSuffixEnd: 202,
    recvRevealed: '0x7788',
    handle: 'alice',
    userId: '42',
    sessionAddr: SESSION,
    timestamp: 1_700_000_001n,
    notarySignature: '0x99aa',
  },
}

export const GOOGLE_FIXTURE: GoogleProof = {
  honkProof: '0xbbcc',
  publicInputs: [b32(14), b32(15), b32(16)],
  email: 'alice@example.com',
  sessionKey: WALLET,
  sub: '1234567890',
}
