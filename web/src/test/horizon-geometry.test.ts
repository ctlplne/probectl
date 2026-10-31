// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, expect, test, vi } from 'vitest'
import type uPlot from 'uplot'
import { horizonBasis, horizonBand } from '../lib/horizonGeometry'
import { timeGeometry, type TimeGeometrySeries } from '../lib/timeGeometry'
import { horizonTimePaths } from '../lib/timePaths'

afterEach(() => vi.unstubAllGlobals())
const group = (
  laneKey: string,
  values: (number | null)[],
  stackGroup = 'current',
): TimeGeometrySeries => ({
  laneKey,
  values,
  stackGroup,
  intervals: values.map((value, index) => (value === null ? null : [index * 60, index * 60 + 60])),
})

test('paired periods use one lane and common amplitude, shared across generated facets without changing observations', () => {
  const source = [
    group('a', [10, 20]),
    group('b', [40, null]),
    group('a', [20, 40], 'previous'),
    group('b', [100, null], 'previous'),
  ]
  const before = JSON.stringify(source),
    basis = horizonBasis(source)
  const shared = timeGeometry(source, 'horizon', { horizonBasis: basis })
  expect(shared.error).toBeUndefined()
  expect(shared.horizon).toEqual({
    keys: ['a', 'b'],
    bases: [1, 0, 1, 0],
    amplitudes: [100, 100, 100, 100],
  })
  expect(shared.upper[0][0]).toBe(1.5)
  const own = timeGeometry(source, 'horizon', { horizonScale: 'lane', horizonBasis: basis })
  expect(own.horizon?.amplitudes).toEqual([40, 100, 40, 100])
  expect(own.upper[0][0]).toBe(1.25)
  const facet = timeGeometry([source[0], source[2]], 'horizon', { horizonBasis: basis })
  expect(facet.horizon?.amplitudes).toEqual([100, 100])
  expect(facet.upper[0][0]).toBe(0.5)
  expect(JSON.stringify(source)).toBe(before)
})

test('five exact thresholds remain full bands, zeros stay baseline and missing samples stay absent', () => {
  const values = [0, 20, 40, 60, 80, 100, null],
    entry = group('a', values)
  const result = timeGeometry([entry], 'horizon')
  expect(result.error).toBeUndefined()
  expect(result.upper[0]).toEqual([0, 1, 1, 1, 1, 1, null])
  for (let band = 0; band < 5; band++)
    expect(horizonBand(values, 100, 0, band)).toEqual(
      values.map((value) => (value === null ? null : Math.max(0, Math.min(1, value / 20 - band)))),
    )
  expect(timeGeometry([group('a', [0, null])], 'horizon').upper[0]).toEqual([0, null])
  expect(timeGeometry([group('a', [1e308]), group('b', [1e308])], 'horizon').error).toBeUndefined()
})

test('horizon rejects incomplete intervals, invalid amplitudes, signed data and source totals honestly', () => {
  expect(timeGeometry([{ ...group('a', [1]), intervals: undefined }], 'horizon').error).toMatch(
    /intervals/,
  )
  expect(timeGeometry([group('a', [-1])], 'horizon').error).toMatch(/nonnegative/)
  expect(timeGeometry([group('a', [Infinity])], 'horizon').error).toMatch(/finite/)
  expect(timeGeometry([{ ...group('a', [1]), emphasis: 'total' }], 'horizon').error).toMatch(
    /separate absolute scale/,
  )
  expect(timeGeometry([{ values: [1] }], 'horizon').error).toMatch(/lane/)
  expect(
    timeGeometry([group('a', [2])], 'horizon', { horizonBasis: horizonBasis([group('a', [1])]) })
      .error,
  ).toMatch(/does not cover/)
})

test('all five real painter bands retain isolated partial intervals inside zoom and previous bands are outlines', () => {
  class Path {
    vertices: number[][] = []
    rect() {}
    moveTo(...v: number[]) {
      this.vertices.push(v)
    }
    lineTo(...v: number[]) {
      this.vertices.push(v)
    }
    closePath() {}
  }
  vi.stubGlobal('Path2D', Path)
  const plot = {
    bbox: { left: 0, top: 0, width: 200, height: 100 },
    scales: { x: { min: 130, max: 135 } },
    valToPos: (v: number, scale: string) => (scale === 'x' ? v : 100 - v * 100),
  } as unknown as uPlot
  const values = [20, null, 100],
    intervals = [[0, 60] as const, null, [120, 140] as const],
    colors = ['one', 'two', 'three', 'four', 'five']
  const build = (previous: boolean) =>
    horizonTimePaths(values, 0, 100, intervals, colors, previous)(plot, 1, 2, 2)!
  const current = build(false)
  expect(current.fill).toBeInstanceOf(Map)
  expect((current.fill as Map<string, Path2D>).size).toBe(5)
  for (const path of (current.fill as unknown as Map<string, Path>).values()) {
    expect(Math.min(...path.vertices.map((v) => v[0]))).toBe(120)
    expect(Math.max(...path.vertices.map((v) => v[0]))).toBe(140)
    expect(path.vertices.flat().every(Number.isFinite)).toBe(true)
  }
  const previous = build(true)
  expect(previous.fill).toBeNull()
  expect((previous.stroke as Map<string, Path2D>).size).toBe(5)
})
