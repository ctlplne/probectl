// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import { createConfigDiff, findPreviousConfig, type ConfigVersionForComparison } from './configDiff'

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
    expect(findPreviousConfig([prior, foreignDevice, future, current], current)).toBeUndefined()
    expect(findPreviousConfig([foreignDevice, future, current], current)).toBeUndefined()
    expect(findPreviousConfig([prior, { ...current, content: undefined }], current)).toBeUndefined()
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

  test('keeps complete supported archive bodies and every changed middle/tail row', () => {
    const count = 20000
    const before = Array.from({ length: count }, (_, index) => `old-${index} ${'x'.repeat(48)}`)
    const after = Array.from({ length: count }, (_, index) => `new-${index} ${'y'.repeat(48)}`)
    const diff = createConfigDiff(before.join('\n'), after.join('\n'))
    expect(diff.replacement).toBe(true)
    expect(diff.rows).toHaveLength(count * 2)
    expect(diff.completeRows).toHaveLength(count * 2)
    expect(diff.removed).toBe(count)
    expect(diff.added).toBe(count)
    expect(diff.rows.some((row) => row.status === 'omitted')).toBe(false)
    expect(diff.rows.filter((row) => row.status === 'removed').map((row) => row.text)).toEqual(
      before,
    )
    expect(diff.rows.filter((row) => row.status === 'added').map((row) => row.text)).toEqual(after)
    expect(diff.rows[count - 1]).toMatchObject({
      status: 'removed',
      beforeLine: count,
      text: before[count - 1],
    })
    expect(diff.rows[count * 2 - 1]).toMatchObject({
      status: 'added',
      afterLine: count,
      text: after[count - 1],
    })
  })

  test('retains exact sparse changes beyond old line and character ceilings', () => {
    const before = Array.from(
      { length: 20000 },
      (_, index) => `interface-${index} ${'x'.repeat(48)}`,
    )
    const after = [...before]
    after[10000] = 'middle line changed'
    after[19999] = 'last line changed'
    const diff = createConfigDiff(before.join('\n'), after.join('\n'))
    expect(diff.replacement).toBe(false)
    expect(diff.added).toBe(2)
    expect(diff.removed).toBe(2)
    expect(diff.unchanged).toBe(19998)
    expect(
      diff.completeRows.filter((row) => row.status !== 'added').map((row) => row.text),
    ).toEqual(before)
    expect(
      diff.completeRows.filter((row) => row.status !== 'removed').map((row) => row.text),
    ).toEqual(after)
    expect(diff.rows).toContainEqual({
      status: 'added',
      afterLine: 20000,
      text: 'last line changed',
    })
  })
})
