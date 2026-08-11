import { describe, expect, it } from 'vitest'

import { HandleError, normalize, RULES_GITHUB, RULES_GOOGLE, RULES_X, rulesFor } from './handle.js'
import { HANDLE_VECTORS } from './handleVectors.js'

/// The shared handle vector table, run against the TypeScript normalizer.
///
/// Solidity and Rust run the same table from the same JSON. That is the whole
/// guard: three hand-written normalizers, one set of cases, so a language that
/// disagrees fails here instead of looking up a key the chain never wrote.
describe('handle normalization', () => {
  it('matches the shared table on every vector', () => {
    for (const [i, v] of HANDLE_VECTORS.entries()) {
      const rules = rulesFor(v.platform)
      expect(rules, `vector ${i}: unknown platform ${v.platform}`).not.toBeNull()

      if (v.accepted) {
        expect(normalize(v.input, rules!), `vector ${i}`).toBe(v.output)
        continue
      }

      // The table names WHICH refusal, not merely that one happened. Accepting
      // any error would pass when the normalizer refused for the wrong reason,
      // and the reason is what the three languages must agree on.
      let thrown: unknown
      try {
        normalize(v.input, rules!)
      } catch (e) {
        thrown = e
      }
      expect(thrown, `vector ${i}: expected a refusal`).toBeInstanceOf(HandleError)
      expect((thrown as HandleError).kind, `vector ${i}: refused for the wrong reason`).toBe(
        v.errorKind,
      )
    }
  })

  /// The table must keep covering both outcomes. A regeneration that dropped
  /// every refusal would leave the test green and prove nothing.
  it('keeps covering both outcomes', () => {
    const accepted = HANDLE_VECTORS.filter((v) => v.accepted).length
    expect(accepted).toBeGreaterThan(0)
    expect(HANDLE_VECTORS.length - accepted).toBeGreaterThan(0)
  })

  /// Case folding is the only change to an accepted handle. Anything else could
  /// map two platform accounts onto one identity.
  it('folds case and changes nothing else', () => {
    expect(normalize('A.B+tag@Example.COM', RULES_GOOGLE)).toBe('a.b+tag@example.com')
    expect(normalize('Alice_1', RULES_X)).toBe('alice_1')
    expect(normalize('Octo-Cat', RULES_GITHUB)).toBe('octo-cat')
  })
})
