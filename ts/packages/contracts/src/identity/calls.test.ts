import { describe, expect, it } from 'vitest'

import { unpublishCall } from './calls.js'

const NAMES = '0x00000000000000000000000000000000000000aa' as const

describe('building the call', () => {
  const platform = `0x${'11'.repeat(32)}` as const

  it('builds an unpublish that names only the platform', () => {
    const call = unpublishCall(NAMES, platform)

    expect(call.to).toBe(NAMES)
    // A selector and one word: the platform, and nothing else. Withdrawing
    // what you chose to show must not depend on proving anything again.
    expect(call.data.length).toBe(2 + 8 + 64)
    expect(call.data.endsWith(platform.slice(2))).toBe(true)
  })
})
