/// The attestation format of ceremony-common section 9.1.
///
/// This mirrors `solidity/contracts/ceremony/CeremonyAttestation.sol` and
/// `libid-rs/crates/libid-ceremony` byte for byte. The browser needs the
/// decoder as much as the chain does: REQ-PLAT-44 has the Canonical Runtime
/// verify the token-exchange attestation locally, against the profile's pinned
/// notary key and this format, before it spends a `/user` session on it.
///
/// Every boundary is derivable from the bytes before it, so decoding is one
/// forward pass and two different attestations cannot share one preimage by
/// shifting a boundary (REQ-COMMON-48).

import { type Hex, keccak256, toHex } from 'viem'

/// Four 32-byte tags, `createdAt`, and the two transcript lengths.
export const HEADER_LEN = 144

/// Offsets are zero-based into that direction's complete transcript, `start`
/// inclusive and `end` exclusive.
export interface RevealedRange {
  start: number
  end: number
  bytes: Uint8Array
}

/// A hidden range, carried as its offsets and a blinded commitment. The
/// plaintext of a committed range never appears in the attested data.
export interface RangeCommitment {
  start: number
  end: number
  commitment: Uint8Array
}

export interface DirectionBlock {
  revealed: RevealedRange[]
  commitments: RangeCommitment[]
}

/// The signed bytes.
///
/// The attested data describes the observed session and says nothing about
/// where the evidence will be spent: no chain, no verifier identity.
export interface AttestedData {
  formatTag: Uint8Array
  platformId: Uint8Array
  operationTag: Uint8Array
  authorityId: Uint8Array
  createdAt: bigint
  sentTranscriptLength: number
  recvTranscriptLength: number
  sent: DirectionBlock
  received: DirectionBlock
}

export class AttestationError extends Error {}

/// Derive a 32-byte tag from a libID-namespaced ASCII string.
export function tag(namespaced: string): Uint8Array {
  return hexToBytes(keccak256(new TextEncoder().encode(namespaced)))
}

function hexToBytes(value: Hex): Uint8Array {
  const body = value.slice(2)
  const out = new Uint8Array(body.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16)
  return out
}

class Writer {
  private parts: Uint8Array[] = []
  push(bytes: Uint8Array) {
    this.parts.push(bytes)
  }
  uint(value: number | bigint, width: number) {
    const out = new Uint8Array(width)
    let v = BigInt(value)
    for (let i = width - 1; i >= 0; i--) {
      out[i] = Number(v & 0xffn)
      v >>= 8n
    }
    if (v !== 0n) throw new AttestationError(`value does not fit ${width} bytes`)
    this.parts.push(out)
  }
  finish(): Uint8Array {
    const total = this.parts.reduce((n, p) => n + p.length, 0)
    const out = new Uint8Array(total)
    let at = 0
    for (const p of this.parts) {
      out.set(p, at)
      at += p.length
    }
    return out
  }
}

class Reader {
  constructor(
    private readonly bytes: Uint8Array,
    public at = 0,
  ) {}
  take(n: number, field: string): Uint8Array {
    if (n < 0 || this.at + n > this.bytes.length) {
      throw new AttestationError(`attested data ends inside the ${field} field`)
    }
    const out = this.bytes.subarray(this.at, this.at + n)
    this.at += n
    return out
  }
  uint(width: number, field: string): number {
    const raw = this.take(width, field)
    let out = 0
    for (const b of raw) out = out * 256 + b
    return out
  }
  bigUint(width: number, field: string): bigint {
    const raw = this.take(width, field)
    let out = 0n
    for (const b of raw) out = (out << 8n) | BigInt(b)
    return out
  }
}

function checkSpan(
  direction: string,
  kind: string,
  start: number,
  end: number,
  length: number,
  previousEnd: number,
): void {
  if (end <= start)
    throw new AttestationError(`${kind} of the ${direction} direction is empty at ${start}`)
  if (start < previousEnd) {
    throw new AttestationError(
      `${kind} of the ${direction} direction starts at ${start}, behind the previous end ${previousEnd}`,
    )
  }
  if (end > length) {
    throw new AttestationError(
      `${kind} of the ${direction} direction ends at ${end}, past the signed transcript length ${length}`,
    )
  }
}

/// Reject a shape the Platform Verifier must refuse: ranges out of order,
/// overlapping, empty, or ending past the signed transcript length
/// (REQ-COMMON-59, REQ-COMMON-60).
function validateDirection(block: DirectionBlock, direction: string, length: number): void {
  if (block.revealed.length > 0xffff || block.commitments.length > 0xffff) {
    throw new AttestationError(`a direction holds more entries than the two-byte count admits`)
  }

  let previousEnd = 0
  for (const range of block.revealed) {
    checkSpan(direction, 'revealed range', range.start, range.end, length, previousEnd)
    if (range.bytes.length !== range.end - range.start) {
      throw new AttestationError(
        `revealed range ${range.start}..${range.end} of the ${direction} direction carries ${range.bytes.length} bytes`,
      )
    }
    previousEnd = range.end
  }

  previousEnd = 0
  for (const commitment of block.commitments) {
    checkSpan(direction, 'commitment', commitment.start, commitment.end, length, previousEnd)
    previousEnd = commitment.end
    if (commitment.commitment.length !== 32) {
      throw new AttestationError(`a commitment of the ${direction} direction is not 32 bytes`)
    }
    for (const range of block.revealed) {
      if (commitment.start < range.end && range.start < commitment.end) {
        throw new AttestationError(
          `a commitment of the ${direction} direction overlaps a revealed range at ${commitment.start}..${commitment.end}`,
        )
      }
    }
  }
}

/// Require the revealed ranges and commitments of one direction to tile
/// `[0, length)` exactly, with no gap and no overlap (REQ-COMMON-35).
///
/// Only for a direction whose profile demands exact coverage. The rule is
/// conditional: REQ-COMMON-43 withholds it from a credential committed in a
/// request body, which is GitHub's `client_secret`, so `validate` does not
/// apply it and a caller asks for it where the profile does.
///
/// A gap is where a prover hides bytes. Exact coverage leaves the committed
/// range as the only region the verifier cannot read.
export function requireExactCoverage(
  block: DirectionBlock,
  direction: string,
  length: number,
): void {
  const spans: Array<[number, number]> = [
    ...block.revealed.map((r): [number, number] => [r.start, r.end]),
    ...block.commitments.map((c): [number, number] => [c.start, c.end]),
  ].sort((a, b) => a[0] - b[0])

  let at = 0
  for (const [start, end] of spans) {
    if (start !== at) {
      throw new AttestationError(
        `transcript bytes ${at}..${start} of the ${direction} direction are covered by nothing`,
      )
    }
    at = end
  }
  if (at !== length) {
    throw new AttestationError(
      `transcript bytes ${at}..${length} of the ${direction} direction are covered by nothing`,
    )
  }
}

export function validate(attested: AttestedData): void {
  validateDirection(attested.sent, 'sent', attested.sentTranscriptLength)
  validateDirection(attested.received, 'received', attested.recvTranscriptLength)
}

function requireTag(value: Uint8Array, field: string): Uint8Array {
  if (value.length !== 32) throw new AttestationError(`${field} must be 32 bytes`)
  return value
}

/// Serialize exactly the byte concatenation of section 9.1.
export function encodeAttestedData(attested: AttestedData): Uint8Array {
  validate(attested)
  const w = new Writer()
  w.push(requireTag(attested.formatTag, 'formatTag'))
  w.push(requireTag(attested.platformId, 'platformId'))
  w.push(requireTag(attested.operationTag, 'operationTag'))
  w.push(requireTag(attested.authorityId, 'authorityId'))
  w.uint(attested.createdAt, 8)
  w.uint(attested.sentTranscriptLength, 4)
  w.uint(attested.recvTranscriptLength, 4)
  for (const block of [attested.sent, attested.received]) {
    w.uint(block.revealed.length, 2)
    for (const range of block.revealed) {
      w.uint(range.start, 4)
      w.uint(range.end, 4)
      w.push(range.bytes)
    }
    w.uint(block.commitments.length, 2)
    for (const commitment of block.commitments) {
      w.uint(commitment.start, 4)
      w.uint(commitment.end, 4)
      w.push(commitment.commitment)
    }
  }
  return w.finish()
}

function decodeDirection(r: Reader): DirectionBlock {
  const revealedCount = r.uint(2, 'revealed range count')
  const revealed: RevealedRange[] = []
  for (let i = 0; i < revealedCount; i++) {
    const start = r.uint(4, 'revealed range start')
    const end = r.uint(4, 'revealed range end')
    // A start past its end would give a negative length; the shape check
    // rejects it, so read nothing here rather than compute a wild one.
    const len = end > start ? end - start : 0
    revealed.push({ start, end, bytes: r.take(len, 'revealed range bytes') })
  }

  const commitmentCount = r.uint(2, 'commitment count')
  const commitments: RangeCommitment[] = []
  for (let i = 0; i < commitmentCount; i++) {
    commitments.push({
      start: r.uint(4, 'commitment start'),
      end: r.uint(4, 'commitment end'),
      commitment: r.take(32, 'commitment value'),
    })
  }
  return { revealed, commitments }
}

/// Parse and validate. Trailing bytes are refused: the layout accounts for
/// every byte, so a suffix is a second message hiding behind the first.
export function decodeAttestedData(bytes: Uint8Array): AttestedData {
  const r = new Reader(bytes)
  const attested: AttestedData = {
    formatTag: r.take(32, 'formatTag'),
    platformId: r.take(32, 'platformId'),
    operationTag: r.take(32, 'operationTag'),
    authorityId: r.take(32, 'authorityId'),
    createdAt: r.bigUint(8, 'createdAt'),
    sentTranscriptLength: r.uint(4, 'sentTranscriptLength'),
    recvTranscriptLength: r.uint(4, 'recvTranscriptLength'),
    sent: { revealed: [], commitments: [] },
    received: { revealed: [], commitments: [] },
  }
  attested.sent = decodeDirection(r)
  attested.received = decodeDirection(r)
  if (r.at !== bytes.length) {
    throw new AttestationError(
      `${bytes.length - r.at} bytes remain after the received direction block`,
    )
  }
  validate(attested)
  return attested
}

/// `keccak256(attestedData)` — the only preimage the notary signs.
export function attestationDigest(attested: AttestedData): Hex {
  return keccak256(toHex(encodeAttestedData(attested)))
}
