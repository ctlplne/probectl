// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test } from 'vitest'
import {
  MAX_CONFIG_DIFF_LINES,
  MAX_RENDERED_CONFIG_DIFF_ROWS,
  createConfigDiff,
  findPreviousConfig,
  type ConfigVersionForComparison,
} from './configDiff'

function version(
  id: string,
  device: string,
  number: number,
  hash: string,
  content?: string,
): ConfigVersionForComparison {
  return {
    id,
    device,
    version: number,
    content_hash: hash,
    content,
    drifted: number > 1,
  }
}

describe('device config comparison', () => {
  test('links only an exact older same-device redacted predecessor', () => {
    const prior = version('prior', 'edge-r1', 1, 'hash-prior', 'redacted prior')
    const repeated = version('repeated', 'edge-r1', 2, 'hash-prior', 'redacted prior')
    const current = {
      ...version('current', 'edge-r1', 3, 'hash-current', 'redacted current'),
      previous_hash: 'hash-prior',
    }
    const foreignDevice = version('foreign', 'edge-r2', 2, 'hash-prior', 'foreign content')
    const future = version('future', 'edge-r1', 4, 'hash-prior', 'future content')

    expect(findPreviousConfig([prior, foreignDevice, repeated, current, future], current)).toBe(
      repeated,
    )
    expect(findPreviousConfig([prior, foreignDevice, future, current], current)).toBe(prior)
    expect(findPreviousConfig([foreignDevice, future, current], current)).toBeUndefined()
    expect(findPreviousConfig([prior, { ...current, content: undefined }], current)).toBe(prior)
    expect(
      findPreviousConfig([prior, { ...current, content: undefined }], {
        ...current,
        content: undefined,
      }),
    ).toBeUndefined()
  })

  test('emits stable line numbers and explicit add, remove, and unchanged semantics', () => {
    const diff = createConfigDiff(
      'hostname edge-r1\r\ninterface Gi0/1\r\n shutdown\r\n[REDACTED]',
      'hostname edge-r1\ninterface Gi0/1\n description payments\n no shutdown\n[REDACTED]',
    )

    expect(diff.bounded).toBe(false)
    expect(diff.added).toBe(2)
    expect(diff.removed).toBe(1)
    expect(diff.unchanged).toBe(3)
    expect(diff.rows).toEqual([
      {
        status: 'unchanged',
        text: 'hostname edge-r1',
        beforeLine: 1,
        afterLine: 1,
      },
      {
        status: 'unchanged',
        text: 'interface Gi0/1',
        beforeLine: 2,
        afterLine: 2,
      },
      { status: 'removed', text: ' shutdown', beforeLine: 3 },
      { status: 'added', text: ' description payments', afterLine: 3 },
      { status: 'added', text: ' no shutdown', afterLine: 4 },
      { status: 'unchanged', text: '[REDACTED]', beforeLine: 4, afterLine: 5 },
    ])
  })

  test('folds distant unchanged context without losing change evidence', () => {
    const stable = Array.from({ length: 30 }, (_, index) => `stable-${index + 1}`)
    const before = [...stable.slice(0, 15), 'old value', ...stable.slice(15)].join('\n')
    const after = [...stable.slice(0, 15), 'new value', ...stable.slice(15)].join('\n')
    const diff = createConfigDiff(before, after)

    expect(diff.contextFolded).toBe(true)
    expect(diff.rows.some((row) => row.status === 'omitted' && (row.omitted ?? 0) > 0)).toBe(true)
    expect(diff.rows).toContainEqual({
      status: 'removed',
      text: 'old value',
      beforeLine: 16,
    })
    expect(diff.rows).toContainEqual({
      status: 'added',
      text: 'new value',
      afterLine: 16,
    })
  })

  test('bounds pathological input and rendered churn honestly', () => {
    const before = Array.from({ length: MAX_CONFIG_DIFF_LINES + 20 }, (_, index) => `old-${index}`)
    const after = Array.from({ length: MAX_CONFIG_DIFF_LINES + 20 }, (_, index) => `new-${index}`)
    const diff = createConfigDiff(before.join('\n'), after.join('\n'))

    expect(diff.bounded).toBe(true)
    expect(diff.rows).toHaveLength(MAX_RENDERED_CONFIG_DIFF_ROWS)
    expect(diff.rows.some((row) => row.status === 'omitted' && (row.omitted ?? 0) > 0)).toBe(true)
    expect(diff.removed).toBe(MAX_CONFIG_DIFF_LINES)
    expect(diff.added).toBe(MAX_CONFIG_DIFF_LINES)
  })
})
