// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, it } from 'vitest'

import { browserStepCount, maxBrowserSteps, safeISOString } from '../lib/clientGuards'

// WEB-24: agent-reported step counts and timestamps are untrusted; the UI must
// bound/guard them before allocating or formatting.
describe('clientGuards (WEB-24)', () => {
  it('clamps a hostile agent-reported step count', () => {
    expect(browserStepCount(1_000_000_000, 0)).toBe(maxBrowserSteps)
    expect(browserStepCount(5, 3)).toBe(5)
    expect(browserStepCount(3, 7)).toBe(7)
    expect(browserStepCount(Number.NaN, -1)).toBe(0)
  })

  it('formats an invalid timestamp without throwing', () => {
    expect(() => safeISOString('not-a-date')).not.toThrow()
    expect(safeISOString('not-a-date')).toBe('not-a-date')
    expect(safeISOString('2026-01-02T03:04:05.000Z')).toBe('2026-01-02T03:04:05.000Z')
  })
})
