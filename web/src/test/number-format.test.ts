// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import {
  formatCount,
  formatCurrencyUSD,
  formatGibibytes,
  formatRatioPercent,
  formatUnit,
} from '../i18n/number'

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
})
