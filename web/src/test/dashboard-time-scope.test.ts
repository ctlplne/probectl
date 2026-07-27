// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import {
  canonicalDashboardSearchParams,
  parseDashboardTimeScope,
} from '../routes/dashboardTimeScope'

describe('dashboard relative-time URL contract', () => {
  test.each([
    ['15m', 15 * 60 * 1000, '1m'],
    ['1h', 60 * 60 * 1000, '5m'],
    ['6h', 6 * 60 * 60 * 1000, '15m'],
    ['24h', 24 * 60 * 60 * 1000, '1h'],
  ])('accepts the bounded %s scope', (value, durationMs, bucket) => {
    const parsed = parseDashboardTimeScope(new URLSearchParams({ range: value }))
    expect(parsed).toMatchObject({ value, durationMs, bucket })
  })

  test.each([
    '',
    'range=',
    'range=2h',
    'range=24hours',
    'range=1h&range=6h',
    `range=${'x'.repeat(128)}`,
  ])('fails closed to 1h for malformed state %s', (query) => {
    expect(parseDashboardTimeScope(new URLSearchParams(query)).value).toBe('1h')
  })

  test('canonicalizes one scope, preserves harmless state, and strips tenant identity', () => {
    const canonical = canonicalDashboardSearchParams(
      new URLSearchParams(
        'view=view-1&demo=1&range=1h&range=24h&tenant_id=other&tenantId=also-other',
      ),
      '6h',
    )

    expect(canonical.getAll('range')).toEqual(['6h'])
    expect(canonical.get('view')).toBe('view-1')
    expect(canonical.get('demo')).toBe('1')
    expect(canonical.toString().toLowerCase()).not.toContain('tenant')
  })
})
