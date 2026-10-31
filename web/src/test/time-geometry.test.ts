// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, describe, expect, test, vi } from 'vitest'
import type uPlot from 'uplot'
import {
  intervalSamples,
  intervalSampleAt,
  percentageDenominator,
  timeGeometry,
} from '../lib/timeGeometry'
import { stackedTimePaths } from '../lib/timePaths'
import { flowPaintRange } from '../routes/flowPlot'

afterEach(() => vi.unstubAllGlobals())

function percentGeometry(
  series: Parameters<typeof timeGeometry>[0],
  options: Parameters<typeof timeGeometry>[2] = {},
) {
  return timeGeometry(
    series.map((entry) => ({
      ...entry,
      intervals: entry.values.map((value, i) =>
        value === null ? null : ([i * 60, (i + 1) * 60] as const),
      ),
    })),
    'percent_area',
    options,
  )
}

describe('time chart paint geometry', () => {
  test('isolated percentage fill covers its actual partial interval even when zoom starts inside it', () => {
    class Path {
      vertices: number[][] = []
      rect() {}
      moveTo(...point: number[]) {
        this.vertices.push(point)
      }
      lineTo(...point: number[]) {
        this.vertices.push(point)
      }
      closePath() {}
    }
    vi.stubGlobal('Path2D', Path)
    const plot = {
      bbox: { left: 100, top: 40, width: 600, height: 300 },
      data: [
        [0, 10, 20, 30, 40, 50, 60, 75],
        [40, null, null, null, null, null, null, null],
      ],
      scales: { x: { min: 30, max: 40 } },
      valToPos: (value: number, scale: string) =>
        scale === 'x' ? 100 + value * 2 : 340 - value * 3,
    } as unknown as uPlot
    const paths = stackedTimePaths(
      'percent_area',
      [0, null, null, null, null, null, null, null],
      [[0, 75], null, null, null, null, null, null, null],
      false,
      false,
    )(plot, 1, 3, 4)!
    const xs = (paths.fill as unknown as Path).vertices.map((point) => point[0])
    expect(Math.min(...xs)).toBe(100)
    expect(Math.max(...xs)).toBe(250)
    expect(xs.every(Number.isFinite)).toBe(true)
  })

  test('percentage shares separate periods and exclude independent nonadditive totals from the basis', () => {
    const source = [
      { values: [2, 0, null], stackGroup: 'current' },
      { values: [6, 0, null], stackGroup: 'current' },
      { values: [3, null, 0], stackGroup: 'previous' },
      { values: [1, null, 0], stackGroup: 'previous' },
      { values: [1, 0, null], emphasis: 'total' as const },
    ]
    const before = JSON.stringify(source)
    const denominator = percentageDenominator(source)
    const selected = source.slice(0, 4)
    const geometry = percentGeometry(selected, { denominator })
    expect(geometry.error).toBeUndefined()
    expect(geometry.upper.map((samples) => samples.slice(1))).toEqual([
      [null, null],
      [null, null],
      [null, null],
      [null, null],
    ])
    for (const [i, expected] of [25, 100, 75, 100].entries())
      expect(geometry.upper[i][0]).toBeCloseTo(expected, 12)
    expect(geometry.lower[1][0]).toBeCloseTo(25, 12)
    expect(percentGeometry([selected[0]], { denominator }).upper[0][0]).toBeCloseTo(25, 12)
    expect(percentGeometry([selected[0]]).upper[0][0]).toBe(100)
    expect(percentGeometry(source).error).toMatch(/separate absolute scale/)
    expect(JSON.stringify(source)).toBe(before)
  })

  test('percentage geometry handles overflowing absolute sums, reordered samples and invalid bases honestly', () => {
    expect(timeGeometry([{ values: [1] }], 'percent_area').error).toMatch(/Bucket intervals/)
    const large = percentGeometry([{ values: [1e308] }, { values: [1e308] }])
    expect(large.error).toBeUndefined()
    expect(large.upper).toEqual([[50], [100]])
    const denominator = percentageDenominator([{ values: [2, 6] }, { values: [6, 6] }])
    const reordered = percentGeometry([{ values: [6, 2] }], {
      denominator,
      sourceOrder: [1, 0],
    }).upper[0]
    expect(reordered[0]).toBeCloseTo(50, 12)
    expect(reordered[1]).toBeCloseTo(25, 12)
    expect(percentGeometry([{ values: [100] }], { denominator }).error).toMatch(/does not cover/)
    expect(percentGeometry([{ values: [-1] }]).error).toMatch(/nonnegative/)
    expect(percentGeometry([{ values: [Infinity] }]).error).toMatch(/finite/)
    expect(
      percentGeometry([{ values: [1] }], { denominator: percentageDenominator([]) }).error,
    ).toMatch(/incomplete/)
  })

  test('column pointer respects interval membership across union samples and exclusive partial ends', () => {
    const current = intervalSamples([[0, 60], null, [60, 75], null])
    const previous = intervalSamples([[0, 90], null, null, [90, 120]])
    expect(intervalSampleAt(current, 45)).toBe(0)
    expect(intervalSampleAt(current, 60)).toBe(2)
    expect(intervalSampleAt(current, 74.999)).toBe(2)
    expect(intervalSampleAt(current, 75)).toBeNull()
    expect(intervalSampleAt(previous, 75)).toBe(0)
    expect(intervalSampleAt(previous, 90)).toBe(3)
    expect(intervalSampleAt(previous, 120)).toBeNull()
    expect(intervalSampleAt(current, -1)).toBeNull()
    expect(intervalSampleAt(current, NaN)).toBeNull()
    expect(intervalSampleAt([], 0)).toBeNull()
  })
  test('periods and totals stay independent, with exact source arrays unchanged', () => {
    const current = [2, 0, null, 3]
    const source = [
      { values: current, stackGroup: 'current' },
      { values: [3, 0, 4, 5], stackGroup: 'current' },
      { values: [7, null, 0, 1], stackGroup: 'previous' },
      { values: [11, 0, 0, 2], stackGroup: 'previous' },
      { values: [1, 0, 2, 2], emphasis: 'total' as const },
    ]
    const before = JSON.stringify(source)
    const geometry = timeGeometry(source, 'stacked_area')
    expect(geometry.error).toBeUndefined()
    expect(geometry.upper).toEqual([
      current,
      [5, 0, 4, 8],
      [7, null, 0, 1],
      [18, 0, 0, 3],
      [1, 0, 2, 2],
    ])
    expect(geometry.lower[1]).toEqual([2, 0, 0, 3])
    expect(geometry.lower[3]).toEqual([7, 0, 0, 1])
    expect(JSON.stringify(source)).toBe(before)
    const plots = source.map((entry, i) => ({ ...entry, label: String(i) }))
    expect(
      flowPaintRange([plots, [{ label: 'different metric', values: [19] }]], 'stacked_area', false),
    ).toEqual([0, 19])
    expect(
      flowPaintRange(
        plots.map((entry) => [entry]),
        'stacked_area',
        false,
      ),
    ).toEqual([0, 11])
  })

  test('invalid intervals and cumulative overflow refuse instead of hiding groups', () => {
    expect(timeGeometry([{ values: [3] }], 'stacked_columns').error).toMatch(/Run a fresh query/)
    expect(timeGeometry([{ values: [1e308] }, { values: [1e308] }], 'stacked_area').error).toMatch(
      /overflow/,
    )
    expect(timeGeometry([{ values: [null, 0] }], 'stacked_area').upper).toEqual([[null, 0]])
  })

  test('columns use actual partial intervals in canvas pixels, including one across a zoom boundary', () => {
    class Path {
      rectangles: number[][] = []
      rect(...values: number[]) {
        this.rectangles.push(values)
      }
    }
    vi.stubGlobal('Path2D', Path)
    const plot = {
      bbox: { left: 100, top: 40, width: 600, height: 300 },
      scales: { x: { min: 0, max: 75 } },
      data: [
        [0, 60, 75],
        [4, 8, null],
      ],
      valToPos: (value: number, scale: string) =>
        scale === 'x' ? 100 + value * 2 : 340 - value * 10,
    } as unknown as uPlot
    const paths = stackedTimePaths(
      'stacked_columns',
      [0, 4, null],
      [[0, 60], [60, 75], null],
      false,
      false,
    )(plot, 1, 1, 2)!
    expect((paths.stroke as unknown as Path).rectangles).toEqual([
      [100, 300, 120, 40],
      [220, 260, 30, 40],
    ])
    expect((paths.fill as unknown as Path).rectangles).toHaveLength(2)
    const previous = stackedTimePaths(
      'stacked_columns',
      [0, 4, null],
      [[0, 60], [60, 75], null],
      true,
      true,
    )(plot, 1, 0, 2)!
    expect(previous.fill).toBeNull()
    expect((previous.stroke as unknown as Path).rectangles[0]).toEqual([100, 300, 120, 40])
  })
})
