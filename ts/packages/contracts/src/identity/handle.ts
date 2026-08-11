/// Turns a platform handle into the one form the identity system keys.
///
/// This mirrors `solidity/contracts/identity/HandleNormalizer.sol` and
/// `rust/identity/src/handle.rs` byte for byte. The three transforms
/// are hand written; the rules they run and the vectors they are checked
/// against are generated from `solidity/contracts/identity/handles.json`, so a
/// difference between them fails a test instead of looking up a key the chain
/// never wrote.

import {
  ALLOW_HYPHEN_GITHUB,
  ALLOW_HYPHEN_GOOGLE,
  ALLOW_HYPHEN_X,
  ALLOW_UNDERSCORE_GITHUB,
  ALLOW_UNDERSCORE_GOOGLE,
  ALLOW_UNDERSCORE_X,
  ERROR_BADCHARACTER,
  ERROR_BADSHAPE,
  ERROR_EMPTY,
  ERROR_TOOLONG,
  IS_EMAIL_GITHUB,
  IS_EMAIL_GOOGLE,
  IS_EMAIL_X,
  MAX_LENGTH_GITHUB,
  MAX_LENGTH_GOOGLE,
  MAX_LENGTH_X,
  STRIP_LEADING_AT_GITHUB,
  STRIP_LEADING_AT_GOOGLE,
  STRIP_LEADING_AT_X,
} from './handleVectors.js'

/// Why a handle was refused. The kinds match the Solidity errors and the Rust
/// ones, because the vector table names which refusal it expects.
export class HandleError extends Error {
  constructor(
    readonly kind: number,
    message: string,
  ) {
    super(message)
    this.name = 'HandleError'
  }
}

const EMPTY = () => new HandleError(ERROR_EMPTY, 'the handle is empty')
const TOO_LONG = () => new HandleError(ERROR_TOOLONG, 'the handle is too long for this platform')
const BAD_CHARACTER = () =>
  new HandleError(ERROR_BADCHARACTER, 'the handle has a character this platform does not allow')
const BAD_SHAPE = () =>
  new HandleError(ERROR_BADSHAPE, 'the handle has an arrangement this platform does not allow')

/// What one platform accepts. Held per platform, so a new platform is
/// configuration rather than code.
export interface Rules {
  /** Bytes allowed after trimming and the `@` strip. */
  maxLength: number
  /** Remove one leading `@`. X and GitHub do. An email keeps its own `@`. */
  stripLeadingAt: boolean
  /** Validate as an address instead of a bare handle. */
  isEmail: boolean
  /** Allowed by X, not by GitHub. */
  allowUnderscore: boolean
  /** A hyphen may not start or end the handle, and two may not touch. */
  allowHyphen: boolean
}

export const RULES_X: Rules = {
  maxLength: MAX_LENGTH_X,
  stripLeadingAt: STRIP_LEADING_AT_X,
  isEmail: IS_EMAIL_X,
  allowUnderscore: ALLOW_UNDERSCORE_X,
  allowHyphen: ALLOW_HYPHEN_X,
}

export const RULES_GITHUB: Rules = {
  maxLength: MAX_LENGTH_GITHUB,
  stripLeadingAt: STRIP_LEADING_AT_GITHUB,
  isEmail: IS_EMAIL_GITHUB,
  allowUnderscore: ALLOW_UNDERSCORE_GITHUB,
  allowHyphen: ALLOW_HYPHEN_GITHUB,
}

export const RULES_GOOGLE: Rules = {
  maxLength: MAX_LENGTH_GOOGLE,
  stripLeadingAt: STRIP_LEADING_AT_GOOGLE,
  isEmail: IS_EMAIL_GOOGLE,
  allowUnderscore: ALLOW_UNDERSCORE_GOOGLE,
  allowHyphen: ALLOW_HYPHEN_GOOGLE,
}

/// The rules for a platform key from the vector table.
export function rulesFor(platform: string): Rules | null {
  if (platform === 'x') return RULES_X
  if (platform === 'github') return RULES_GITHUB
  if (platform === 'google') return RULES_GOOGLE
  return null
}

/// The normalized handle, or a `HandleError` naming what was wrong.
export function normalize(raw: string, rules: Rules): string {
  // Work on bytes, not code units. A character above 0x7f is several bytes and
  // must be refused as bytes, the way Solidity sees it.
  const input = new TextEncoder().encode(raw)

  // Trim ASCII spaces only. A tab or a newline is not whitespace to remove
  // here; it is a byte the platform does not allow, and the character check
  // below refuses it. Trimming it would accept "ali\tce" as "alice" here and
  // refuse it on chain.
  let start = 0
  let end = input.length
  while (start < end && input[start] === 0x20) start++
  while (end > start && input[end - 1] === 0x20) end--

  if (rules.stripLeadingAt && end > start && input[start] === 0x40) start++

  const length = end - start
  if (length === 0) throw EMPTY()
  if (length > rules.maxLength) throw TOO_LONG()

  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    let c = input[start + i]
    // Fold A-Z down. Nothing else changes, so two addresses that differ in more
    // than case stay two identities.
    if (c >= 0x41 && c <= 0x5a) c += 0x20
    if (!allowed(c, rules)) throw BAD_CHARACTER()
    out[i] = c
  }

  if (rules.isEmail) requireEmailShape(out)
  else if (rules.allowHyphen) requireHyphenShape(out)

  return new TextDecoder().decode(out)
}

/// One byte, after folding. Anything outside the platform's set is refused,
/// including every byte above 0x7f, so a multi-byte character never reaches a
/// key.
function allowed(c: number, rules: Rules): boolean {
  if (c >= 0x61 && c <= 0x7a) return true // a-z
  if (c >= 0x30 && c <= 0x39) return true // 0-9
  if (rules.isEmail) {
    // The set a Google address uses. The dot, the plus and the tag stay exactly
    // as proved: this transform must never map two addresses onto one identity.
    return c === 0x2e || c === 0x2b || c === 0x2d || c === 0x5f || c === 0x40
  }
  if (rules.allowUnderscore && c === 0x5f) return true
  if (rules.allowHyphen && c === 0x2d) return true
  return false
}

/// Exactly one `@`, and not at either edge.
function requireEmailShape(value: Uint8Array): void {
  let at = -1
  for (let i = 0; i < value.length; i++) {
    if (value[i] === 0x40) {
      if (at !== -1) throw BAD_SHAPE() // a second one
      at = i
    }
  }
  if (at === -1) throw BAD_SHAPE() // none
  if (at === 0 || at === value.length - 1) throw BAD_SHAPE() // an empty side
}

/// A hyphen may not start or end the handle, and two may not touch.
function requireHyphenShape(value: Uint8Array): void {
  if (value[0] === 0x2d || value[value.length - 1] === 0x2d) throw BAD_SHAPE()
  for (let i = 1; i < value.length; i++) {
    if (value[i] === 0x2d && value[i - 1] === 0x2d) throw BAD_SHAPE()
  }
}
