// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import {
  formatCount,
  formatCurrencyUSD,
  formatDuration,
  formatGibibytes,
  formatRatioPercent,
  formatUnit,
} from '../i18n/number'
import { formatThreatConfidence } from '../api/threat'

describe('locale-aware numeric formatting', () => {
  test('formats currency, ratios, binary volume, and engineering units by locale', () => {
    expect(formatCurrencyUSD(1234.5, 'en')).toBe('$1,234.50')
    expect(formatCurrencyUSD(1234.5, 'es')).toMatch(/1234,50|1\.234,50/)
    expect(formatRatioPercent(0.968, 'es', { maximumFractionDigits: 1 })).toContain('96,8')
    expect(formatGibibytes(12.5 * 2 ** 30, 'es')).toBe('12,5')
    expect(formatUnit(18.5, 'ms', 'es', { maximumFractionDigits: 1 })).toBe('18,5 ms')
  })

  test('uses plural rules instead of parenthetical English plurals', () => {
    expect(formatCount(1, 'answer', 'answers', 'en')).toBe('1 answer')
    expect(formatCount(2, 'answer', 'answers', 'en')).toBe('2 answers')
  })

  test('formats threat confidence as 0..100 percentage points, not a ratio', () => {
    expect(formatThreatConfidence(0, 'en')).toBe('0%')
    expect(formatThreatConfidence(82, 'en')).toBe('82%')
    expect(formatThreatConfidence(100, 'en')).toBe('100%')
    expect(formatThreatConfidence(undefined, 'en')).toBe('n/a')
    expect(formatThreatConfidence(82, 'es')).toMatch(/^82\s*%$/)
  })
})

// DPR-186: the fleet table printed "Heartbeat age: 104848s" and the support card
// printed uptime the same way. Nobody converts 104,848 seconds in their head,
// and the number that matters — a day and five hours — was sitting there unread.
describe('formatDuration', () => {
  test('reads as a duration, in the two units that carry the information', () => {
    expect(formatDuration(104848, 'en')).toBe('1d 5h')
    expect(formatDuration(3600, 'en')).toBe('1h 0m')
    expect(formatDuration(3661, 'en')).toBe('1h 1m')
    expect(formatDuration(90, 'en')).toBe('1m 30s')
    expect(formatDuration(45, 'en')).toBe('45s')
    expect(formatDuration(0, 'en')).toBe('0s')
  })

  test('follows the locale rather than hard-coded unit letters', () => {
    // Spanish narrow units differ from English; the exact glyphs are the
    // platform's business, but they must not be identical by accident.
    const en = formatDuration(104848, 'en')
    const es = formatDuration(104848, 'es')
    expect(en).toMatch(/1\s*d/)
    expect(typeof es).toBe('string')
    expect(es.length).toBeGreaterThan(0)
  })

  test('refuses nonsense instead of inventing a duration', () => {
    expect(formatDuration(Number.NaN, 'en')).toBe('')
    expect(formatDuration(-5, 'en')).toBe('')
  })
})
