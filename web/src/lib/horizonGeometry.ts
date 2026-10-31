// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { TimeGeometrySeries } from './timeGeometry'

export type HorizonScale = 'shared' | 'lane'
export interface HorizonBasis {
  shared: number
  lanes: ReadonlyMap<string, number>
  error?: string
}
export interface HorizonLanes {
  keys: string[]
  bases: number[]
  amplitudes: number[]
}

/** Current and previous observations share their group's amplitude. A single
 * read-only basis also keeps generated facets comparable to the main chart. */
export function horizonBasis(series: TimeGeometrySeries[]): HorizonBasis {
  const lanes = new Map<string, number>()
  let shared = 0
  for (const entry of series) {
    if (entry.emphasis === 'total') continue
    if (!entry.laneKey) return { shared, lanes, error: 'Horizon lane identity is unavailable.' }
    let maximum = lanes.get(entry.laneKey) ?? 0
    for (const value of entry.values) {
      if (value === null) continue
      if (!Number.isFinite(value) || value < 0)
        return { shared, lanes, error: 'Horizon requires finite nonnegative observations.' }
      maximum = Math.max(maximum, value)
    }
    lanes.set(entry.laneKey, maximum)
    shared = Math.max(shared, maximum)
  }
  return { lanes, shared }
}

export function horizonGeometry(
  series: TimeGeometrySeries[],
  scale: HorizonScale,
  basis = horizonBasis(series),
) {
  const keys = [...new Set(series.map((entry) => entry.laneKey ?? ''))]
  const bases = series.map((entry) => keys.length - keys.indexOf(entry.laneKey ?? '') - 1)
  const amplitudes = series.map((entry) =>
    scale === 'shared' ? basis.shared : (basis.lanes.get(entry.laneKey ?? '') ?? 0),
  )
  let error = basis.error
  const upper = series.map((entry, index) =>
    entry.values.map((value, sample) => {
      if (!entry.laneKey || entry.emphasis === 'total') {
        error = 'Horizon needs group lanes; source totals use a separate absolute scale.'
        return null
      }
      if (value === null) return null
      const amplitude = amplitudes[index]
      if (!Number.isFinite(value) || value < 0 || !Number.isFinite(amplitude) || amplitude < 0) {
        error = 'Horizon requires finite nonnegative observations and amplitudes.'
        return null
      }
      const interval = entry.intervals?.[sample]
      if (!interval || !interval.every(Number.isFinite) || interval[1] <= interval[0]) {
        error =
          'Bucket intervals are unavailable for horizon. Run a fresh query; exact values remain available.'
        return null
      }
      if ((amplitude === 0 && value !== 0) || value / amplitude > 1 + Number.EPSILON * 8) {
        error = 'Horizon amplitude does not cover the selected observations.'
        return null
      }
      const bands = amplitude === 0 ? 0 : 5 * Math.min(1, value / amplitude)
      // Exact band thresholds occupy the full lower band instead of folding
      // to zero. Coordinates never replace the original observations.
      return bases[index] + (bands === 0 ? 0 : bands - Math.max(0, Math.ceil(bands) - 1))
    }),
  )
  const lower = series.map((entry, index) =>
    entry.values.map((value) => (value === null ? null : bases[index])),
  )
  return { upper, lower, horizon: { keys, bases, amplitudes }, error }
}

export function horizonBand(
  values: (number | null)[],
  amplitude: number,
  base: number,
  band: number,
) {
  return values.map((value) =>
    value === null
      ? null
      : base +
        Math.max(0, Math.min(1, (amplitude === 0 ? 0 : 5 * Math.min(1, value / amplitude)) - band)),
  )
}
