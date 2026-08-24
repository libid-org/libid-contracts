/// Ceremony profile constants, the protocol parameters governance owns, and
/// the GitHub Token-Exchange Service contract.
///
/// # The namespaced strings are ours, not the specification's
///
/// ceremony-common fixes exactly one literal: `libid.identity.pkce`, in
/// section 7. Every other libID-namespaced string — the platform name
/// each Consumer's operation domain (REQ-COMMON-01A) — is required to exist
/// and required to be pinned, but its bytes are left to the profile author.
///
/// So these are a cross-implementation agreement, not a reading of the
/// specification. A notary emitting one string and a verifier pinning another
/// derives a key nobody trusts and rejects every genuine attestation, with no
/// error that says why. `libid-rs/crates/libid-ceremony/src/profile.rs` and
/// `solidity/contracts/ceremony/CeremonyProfile.sol` carry the same strings.

import { type Hex, keccak256 } from 'viem'

const tag = (s: string): Hex => keccak256(new TextEncoder().encode(s))

/// Names the attested-data layout and its version (REQ-COMMON-53).
/// Which session of the ceremony an attestation covers (REQ-COMMON-55).

/// How a profile binds the Authorization Digest to its evidence — exactly one
/// of the two, never both and never neither (REQ-COMMON-02C).
export type DigestBinding = 'public-proof-input' | 'revealed-code-verifier'

/// One notarized session of a ceremony.
export interface SessionProfile {
  /// The TLS server name the notary authenticated, lowercase ASCII with no
  /// trailing dot. It reaches the verifier as `authorityId`, never as a
  /// transcript range: the transcript holds it only in a prover-composed
  /// `Host` header, which says nothing about which server answered.
  authority: string
  method: 'GET' | 'POST'
  /// Origin-form path, no query.
  path: string
}

/// The five parameters of platform-ceremonies §2.1a. `isEmail` supersedes the
/// two booleans below it (REQ-PLAT-67); they are stated because REQ-PLAT-72
/// requires a profile to fix all five.
export interface HandleRules {
  maxLength: number
  stripLeadingAt: boolean
  isEmail: boolean
  allowUnderscore: boolean
  allowHyphen: boolean
}

export interface PlatformProfile {
  /// Preimage of `platformId` (REQ-COMMON-55).
  name: string
  platformId: Hex
  /// Launch profiles use 1 (REQ-PLAT-01).
  platformVerifierVersion: number
  digestBinding: DigestBinding
  tokenSession?: SessionProfile
  identitySession?: SessionProfile
  handle: HandleRules
}

/// `google/v1` — authentication-only OIDC. No token exchange, no client
/// secret, no PKCE, no notarized session, and therefore no Notary Fee.
export const GOOGLE_V1: PlatformProfile = {
  name: 'google',
  platformId: tag('google'),
  platformVerifierVersion: 1,
  digestBinding: 'public-proof-input',
  handle: {
    maxLength: 62,
    stripLeadingAt: false,
    isEmail: true,
    allowUnderscore: false,
    allowHyphen: false,
  },
}

/// `x/v1` — a public client with S256 PKCE and two browser-owned sessions.
export const X_V1: PlatformProfile = {
  name: 'x',
  platformId: tag('x'),
  platformVerifierVersion: 1,
  digestBinding: 'revealed-code-verifier',
  tokenSession: {
    authority: 'api.x.com',
    method: 'POST',
    path: '/2/oauth2/token',
  },
  identitySession: {
    authority: 'api.x.com',
    method: 'GET',
    path: '/2/users/me',
  },
  handle: {
    maxLength: 15,
    stripLeadingAt: true,
    isEmail: false,
    allowUnderscore: true,
    allowHyphen: false,
  },
}

/// `github/v1` — a confidential client, so the exchange runs in the
/// deployment's Token-Exchange Service and that service is the notarized party
/// for the token session. The two sessions have two different authorities.
export const GITHUB_V1: PlatformProfile = {
  name: 'github',
  platformId: tag('github'),
  platformVerifierVersion: 1,
  digestBinding: 'revealed-code-verifier',
  tokenSession: {
    authority: 'github.com',
    method: 'POST',
    path: '/login/oauth/access_token',
  },
  identitySession: {
    authority: 'api.github.com',
    method: 'GET',
    path: '/user',
  },
  handle: {
    maxLength: 39,
    stripLeadingAt: true,
    isEmail: false,
    allowUnderscore: false,
    allowHyphen: true,
  },
}

export const LAUNCH_PROFILES = [GOOGLE_V1, X_V1, GITHUB_V1] as const

/// Derived from the session list the profile fixes, never stated beside it
/// (REQ-COMMON-41). Google verifies none and pays nothing; X and GitHub verify
/// two each, so one submission on either path pays two Notary Fees.
export function attestationCount(profile: PlatformProfile): number {
  return (profile.tokenSession ? 1 : 0) + (profile.identitySession ? 1 : 0)
}

/// Governance-owned seconds. The Platform Verifier reads the current value
/// when it verifies; a browser read is advisory only (libid.md, REQ-PARAM-02).
export interface ProtocolParameters {
  proofLifetimeX: bigint
  proofLifetimeGithub: bigint
  maxFutureAttestationSkew: bigint
}

export const LAUNCH_PARAMETERS: ProtocolParameters = {
  proofLifetimeX: 3600n,
  proofLifetimeGithub: 3600n,
  maxFutureAttestationSkew: 300n,
}

// --- GitHub Token-Exchange Service (platform-ceremonies §6.3) ---------------

/// Fixed route on the redirect origin.
export const TOKEN_EXCHANGE_ROUTE = '/oauth/github/token-exchange'

export const MAX_GITHUB_CODE_BYTES = 1024
export const GITHUB_CODE_VERIFIER_LEN = 43
export const MAX_GITHUB_ACCESS_TOKEN_BYTES = 4096
export const MAX_GITHUB_BEARER_OPENING_BYTES = 256
export const MAX_GITHUB_TOKEN_ATTESTATION_BYTES = 2 * 1024 * 1024
export const MAX_GITHUB_TOKEN_EXCHANGE_RESPONSE_BYTES = 3 * 1024 * 1024

export interface TokenExchangeRequestV1 {
  schema: 1
  code: string
  codeVerifier: string
}

export interface TokenExchangeResponseV1 {
  schema: 1
  accessToken: string
  /// Canonical unpadded base64url of the attested data.
  tokenAttestation: string
  /// Canonical unpadded base64url of the blinder that opens the committed
  /// bearer range of that attestation.
  ///
  /// Private witness material. It must never enter a submission, a log, or
  /// anything leaving the browser: the opening and the commitment together
  /// reveal the credential the commitment exists to hide (REQ-PLAT-55).
  bearerOpening: string
}

export class TokenExchangeError extends Error {}

/// Bounded parsing, per REQ-PLAT-37, REQ-PLAT-38 and REQ-PLAT-40.
export function validateTokenExchangeRequest(request: TokenExchangeRequestV1): void {
  if (request.schema !== 1) throw new TokenExchangeError(`unknown schema ${request.schema}`)
  if (request.code.length === 0) throw new TokenExchangeError('code is empty')
  if (request.code.length > MAX_GITHUB_CODE_BYTES) {
    throw new TokenExchangeError(`code is ${request.code.length} bytes, over the bound`)
  }
  // Printable ASCII excludes whitespace and control characters.
  if (!/^[\x21-\x7e]+$/.test(request.code)) {
    throw new TokenExchangeError('code carries a byte outside printable ASCII')
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(request.codeVerifier)) {
    throw new TokenExchangeError('codeVerifier must match [A-Za-z0-9_-]{43}')
  }
}

/// Bounded parsing, per REQ-PLAT-39.
export function validateTokenExchangeResponse(response: TokenExchangeResponseV1): void {
  if (response.schema !== 1) throw new TokenExchangeError(`unknown schema ${response.schema}`)
  if (response.accessToken.length > MAX_GITHUB_ACCESS_TOKEN_BYTES) {
    throw new TokenExchangeError('accessToken is over the bound')
  }
  // The bounds are on the DECODED lengths, so base64url expands by 4/3.
  if (decodedLength(response.bearerOpening) > MAX_GITHUB_BEARER_OPENING_BYTES) {
    throw new TokenExchangeError('bearerOpening is over the bound')
  }
  if (decodedLength(response.tokenAttestation) > MAX_GITHUB_TOKEN_ATTESTATION_BYTES) {
    throw new TokenExchangeError('tokenAttestation is over the bound')
  }
}

function decodedLength(base64UrlNoPad: string): number {
  const groups = Math.floor(base64UrlNoPad.length / 4)
  const rest = base64UrlNoPad.length - groups * 4
  return groups * 3 + (rest === 0 ? 0 : rest - 1)
}
