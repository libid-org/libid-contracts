import { describe, expect, it } from 'vitest'
import {
  attestationCount,
  FORMAT_TAG,
  GITHUB_V1,
  GOOGLE_V1,
  IDENTITY_SESSION_TAG,
  LAUNCH_PARAMETERS,
  LAUNCH_PROFILES,
  TOKEN_SESSION_TAG,
  TokenExchangeError,
  type TokenExchangeRequestV1,
  validateTokenExchangeRequest,
  validateTokenExchangeResponse,
  X_V1,
} from './profile.js'

/// Expected values computed with `cast keccak`, independently of this module.
/// The same strings live in the Rust and Solidity profiles; a disagreement
/// rejects every genuine attestation with no error that says why.
describe('profile tags', () => {
  it('pins the attestation tags', () => {
    expect(FORMAT_TAG).toBe('0xf1b67c286f7f90224eb4661a5922406b5092042b9515e4e9e448ec1d4f55b352')
    expect(TOKEN_SESSION_TAG).toBe(
      '0x197620cf765b4e8ce251f1d1f78b0c2997cc15d9e996e5938c6bf2a7bbfd8ab0',
    )
    expect(IDENTITY_SESSION_TAG).toBe(
      '0xe7b961087ec316778e6885d11145cc06f1d75360430f461d0322fb7f105899dd',
    )
  })

  it('pins the platform ids, and they are distinct', () => {
    expect(GOOGLE_V1.platformId).toBe(
      '0x8f2f90d8304f6eb382d037c47a041d8c8b4d18bdd8b082fa32828e016a584ca7',
    )
    expect(X_V1.platformId).toBe(
      '0x7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83',
    )
    expect(GITHUB_V1.platformId).toBe(
      '0x07a17bd3c7c8d7b88e93a4d9007e3bc230b0a586a434de0bed6500e9f343deb7',
    )
    expect(new Set(LAUNCH_PROFILES.map((p) => p.platformId)).size).toBe(3)
  })

  it('separates the two sessions of one ceremony', () => {
    expect(TOKEN_SESSION_TAG).not.toBe(IDENTITY_SESSION_TAG)
  })
})

describe('profiles', () => {
  it('counts attestations from the session list', () => {
    // Google's path stops at the Platform Verifier and costs nothing; X and
    // GitHub each pay two Notary Fees per submission.
    expect(attestationCount(GOOGLE_V1)).toBe(0)
    expect(attestationCount(X_V1)).toBe(2)
    expect(attestationCount(GITHUB_V1)).toBe(2)
  })

  it('binds the digest by exactly one method per profile', () => {
    expect(GOOGLE_V1.digestBinding).toBe('public-proof-input')
    expect(X_V1.digestBinding).toBe('revealed-code-verifier')
    expect(GITHUB_V1.digestBinding).toBe('revealed-code-verifier')
  })

  it('gives GitHub two different authorities', () => {
    // The exchange is served by github.com, the identity read by
    // api.github.com. One pinned authority per profile would be wrong.
    expect(GITHUB_V1.tokenSession?.authority).toBe('github.com')
    expect(GITHUB_V1.identitySession?.authority).toBe('api.github.com')
  })

  it('keeps every authority and path canonical', () => {
    for (const profile of LAUNCH_PROFILES) {
      for (const session of [profile.tokenSession, profile.identitySession]) {
        if (!session) continue
        expect(session.authority).toBe(session.authority.toLowerCase())
        expect(session.authority.endsWith('.')).toBe(false)
        expect(session.authority).not.toMatch(/[/:]/)
        expect(session.path.startsWith('/')).toBe(true)
        expect(session.path).not.toContain('?')
      }
    }
  })

  it('carries the published launch parameters', () => {
    expect(LAUNCH_PARAMETERS).toEqual({
      proofLifetimeX: 3600n,
      proofLifetimeGithub: 3600n,
      maxFutureAttestationSkew: 300n,
    })
  })

  it('matches the published handle parameter table', () => {
    expect(GOOGLE_V1.handle).toEqual({
      maxLength: 62,
      stripLeadingAt: false,
      isEmail: true,
      allowUnderscore: false,
      allowHyphen: false,
    })
    expect(X_V1.handle.maxLength).toBe(15)
    expect(X_V1.handle.allowUnderscore).toBe(true)
    expect(GITHUB_V1.handle.maxLength).toBe(39)
    expect(GITHUB_V1.handle.allowHyphen).toBe(true)
  })
})

describe('token exchange', () => {
  const request = (): TokenExchangeRequestV1 => ({
    schema: 1,
    code: 'abc123',
    codeVerifier: 'iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I',
  })

  it('accepts a well-formed request', () => {
    expect(() => validateTokenExchangeRequest(request())).not.toThrow()
  })

  it('accepts the verifier the specification itself publishes', () => {
    // If it did not, the service would refuse a value §7 produces.
    expect(request().codeVerifier).toHaveLength(43)
  })

  it.each([
    ['', /empty/],
    ['a'.repeat(1025), /over the bound/],
    ['ab cd', /printable ASCII/],
    ['ab\tcd', /printable ASCII/],
    ['ab\ncd', /printable ASCII/],
  ])('refuses code %o', (code, message) => {
    expect(() => validateTokenExchangeRequest({ ...request(), code })).toThrow(message)
  })

  it.each([
    'short',
    'iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5', // 42
    'iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1+gIZs5I', // base64, not base64url
    'iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1/gIZs5I',
  ])('refuses codeVerifier %o', (codeVerifier) => {
    expect(() => validateTokenExchangeRequest({ ...request(), codeVerifier })).toThrow(
      TokenExchangeError,
    )
  })

  it('bounds the response on decoded lengths, not encoded ones', () => {
    // base64url expands by 4/3, so bounding the string would bound the wrong
    // number and admit an oversized opening.
    const opening = 'A'.repeat(Math.ceil((257 * 4) / 3))
    expect(() =>
      validateTokenExchangeResponse({
        schema: 1,
        accessToken: 'token',
        tokenAttestation: 'AAAA',
        bearerOpening: opening,
      }),
    ).toThrow(/bearerOpening/)
  })

  it('accepts a 256-byte opening, which is the bound', () => {
    const opening = 'A'.repeat((256 / 3) * 4) // 256 bytes decodes from 344 chars
    expect(() =>
      validateTokenExchangeResponse({
        schema: 1,
        accessToken: 'token',
        tokenAttestation: 'AAAA',
        bearerOpening: opening,
      }),
    ).not.toThrow()
  })
})
