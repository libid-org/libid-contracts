import { describe, expect, it } from 'vitest'
import {
  AttestationError,
  type AttestedData,
  attestationDigest,
  decodeAttestedData,
  encodeAttestedData,
  HEADER_LEN,
  requireExactCoverage,
  tag,
} from './attestation.js'

/// The exact bytes `libid-rs/crates/libid-ceremony` encodes and
/// `solidity/contracts/ceremony/test/CeremonyAttestation.t.sol` decodes. All
/// three carry this fixture: a divergence would have the notary sign a
/// preimage the chain rebuilds differently, deriving a key nobody trusts and
/// rejecting every genuine attestation.
const FIXTURE =
  'f1b67c286f7f90224eb4661a5922406b5092042b9515e4e9e448ec1d4f55b352' +
  '7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83' +
  'e7b961087ec316778e6885d11145cc06f1d75360430f461d0322fb7f105899dd' +
  '4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d' +
  '0000000069800e800000003c00000028' +
  '000200000000000000146161616161616161616161616161616161616161' +
  '000000280000003c6262626262626262626262626262626262626262' +
  '00010000001400000028' +
  '0707070707070707070707070707070707070707070707070707070707070707' +
  '0001000000000000000a63636363636363636363' +
  '00010000000a00000028' +
  '0909090909090909090909090909090909090909090909090909090909090909'

const FIXTURE_DIGEST = '0x511d91f8a3c13c1824fd1d3e7c011caf09f2f0763f1ede5c786839592ae8d252'

function bytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function sample(): AttestedData {
  return {
    formatTag: tag('libid.attestation.v1'),
    platformId: tag('x'),
    operationTag: tag('libid.ceremony.session.identity.v1'),
    authorityId: tag('api.x.com'),
    createdAt: 1_770_000_000n,
    sentTranscriptLength: 60,
    recvTranscriptLength: 40,
    sent: {
      revealed: [
        { start: 0, end: 20, bytes: new Uint8Array(20).fill(0x61) },
        { start: 40, end: 60, bytes: new Uint8Array(20).fill(0x62) },
      ],
      commitments: [{ start: 20, end: 40, commitment: new Uint8Array(32).fill(7) }],
    },
    received: {
      revealed: [{ start: 0, end: 10, bytes: new Uint8Array(10).fill(0x63) }],
      commitments: [{ start: 10, end: 40, commitment: new Uint8Array(32).fill(9) }],
    },
  }
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

describe('attested data', () => {
  it('agrees with the Rust encoder and the Solidity decoder', () => {
    expect(hex(encodeAttestedData(sample()))).toBe(FIXTURE)
    expect(attestationDigest(sample())).toBe(FIXTURE_DIGEST)
  })

  it('round trips', () => {
    const decoded = decodeAttestedData(bytes(FIXTURE))
    expect(hex(encodeAttestedData(decoded))).toBe(FIXTURE)
    expect(decoded.createdAt).toBe(1_770_000_000n)
    expect(decoded.sentTranscriptLength).toBe(60)
    expect(decoded.sent.revealed).toHaveLength(2)
    expect(decoded.sent.commitments).toHaveLength(1)
    expect(new TextDecoder().decode(decoded.received.revealed[0]!.bytes)).toBe('cccccccccc')
  })

  it('lays the header out in 144 bytes', () => {
    expect(HEADER_LEN).toBe(144)
  })

  it('separates the two sessions of one ceremony', () => {
    // REQ-COMMON-55: without operationTag the token and identity attestations
    // would differ in nothing a verifier reads.
    const token = { ...sample(), operationTag: tag('libid.ceremony.session.token.v1') }
    expect(attestationDigest(token)).not.toBe(attestationDigest(sample()))
  })

  it('refuses trailing bytes', () => {
    expect(() => decodeAttestedData(bytes(FIXTURE + '00'))).toThrow(AttestationError)
  })

  it('refuses every truncation', () => {
    const full = bytes(FIXTURE)
    for (let cut = 0; cut < full.length; cut++) {
      expect(() => decodeAttestedData(full.subarray(0, cut))).toThrow(AttestationError)
    }
  })

  it('refuses a count that outruns the buffer', () => {
    const tampered = bytes(FIXTURE)
    tampered[HEADER_LEN] = 0xff
    tampered[HEADER_LEN + 1] = 0xff
    expect(() => decodeAttestedData(tampered)).toThrow(AttestationError)
  })

  it('refuses out-of-order ranges', () => {
    const a = sample()
    a.sent.revealed.reverse()
    expect(() => encodeAttestedData(a)).toThrow(/behind the previous end/)
  })

  it('refuses an empty range', () => {
    const a = sample()
    a.sent.revealed[0] = { start: 0, end: 0, bytes: new Uint8Array(0) }
    expect(() => encodeAttestedData(a)).toThrow(/is empty/)
  })

  it('refuses a range past the signed transcript length', () => {
    // The signed length is what makes bytes past the last revealed range
    // visible at all (REQ-COMMON-36).
    const a = { ...sample(), sentTranscriptLength: 50 }
    expect(() => encodeAttestedData(a)).toThrow(/past the signed transcript length/)
  })

  it('refuses a commitment overlapping a revealed range', () => {
    const a = sample()
    a.sent.commitments[0]!.start = 10
    expect(() => encodeAttestedData(a)).toThrow(/overlaps a revealed range/)
  })

  it('refuses a range whose bytes disagree with its offsets', () => {
    const a = sample()
    a.sent.revealed[0]!.bytes = new Uint8Array(19)
    expect(() => encodeAttestedData(a)).toThrow(/carries 19 bytes/)
  })

  it('accepts an exact tiling', () => {
    const a = sample()
    expect(() => requireExactCoverage(a.sent, 'sent', a.sentTranscriptLength)).not.toThrow()
  })

  it('rejects a gap, which validate accepts on purpose', () => {
    // Coverage is conditional under REQ-COMMON-43, so the shape check passes
    // and the identity-session verifier is what must refuse this.
    const a = sample()
    a.sent.commitments[0]!.start = 21
    expect(() => encodeAttestedData(a)).not.toThrow()
    expect(() => requireExactCoverage(a.sent, 'sent', a.sentTranscriptLength)).toThrow(
      /bytes 20\.\.21 .* covered by nothing/,
    )
  })

  it('rejects a trailing gap', () => {
    // Bytes past the last range are invisible without the signed length.
    const a = sample()
    expect(() => requireExactCoverage(a.sent, 'sent', 80)).toThrow(/bytes 60\.\.80/)
  })
})
