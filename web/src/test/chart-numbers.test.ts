// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import { formatPlotCoordinate } from '../lib/chartNumbers'

describe('readable chart coordinates (DPR415)', () => {
  test.each([
    Number.MAX_SAFE_INTEGER,
    Number('18446744073709551617'),
    1e100,
    1e-100,
    -1e100,
    -0.00123456789,
    0.123456789,
    9999.9,
  ])('keeps %s coordinate labels inside the fixed axis', (value) => {
    const label = formatPlotCoordinate(value)
    expect(label.length).toBeLessThanOrEqual(10)
    expect(Number(label)).not.toBeNaN()
    expect(Math.abs(Number(label) - value) / Math.abs(value)).toBeLessThan(0.01)
  })
  test('handles zero and invalid geometry explicitly', () => {
    expect(formatPlotCoordinate(0)).toBe('0')
    expect(formatPlotCoordinate(-0)).toBe('0')
    expect(formatPlotCoordinate(Infinity)).toBe('—')
    expect(formatPlotCoordinate(NaN)).toBe('—')
  })
})
