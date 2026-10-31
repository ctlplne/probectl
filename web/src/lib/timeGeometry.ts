// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import {
  horizonGeometry,
  type HorizonBasis,
  type HorizonLanes,
  type HorizonScale,
} from './horizonGeometry'

export type TimeStyle = 'line' | 'stacked_area' | 'stacked_columns' | 'percent_area' | 'horizon'
export type TimeInterval = readonly [start: number, end: number]

export interface TimeGeometrySeries {
  values: (number | null)[]
  emphasis?: 'total'
  stackGroup?: string
  laneKey?: string
  intervals?: (TimeInterval | null)[]
}

export interface PercentDenominator {
  periods: ReadonlyMap<string, { maxima: number[]; sums: number[] }>
  error?: string
}

interface TimePaintGeometry {
  horizon?: HorizonLanes
  upper: (number | null)[][]
  lower: (number | null)[][]
  error: string | undefined
}

/** Scaled sums avoid overflowing an otherwise valid finite set of source
 * observations. Share one denominator across all generated facets. */
export function percentageDenominator(series: TimeGeometrySeries[]): PercentDenominator {
  const periods = new Map<string, { maxima: number[]; sums: number[] }>()
  for (const entry of series) {
    if (entry.emphasis === 'total') continue
    const key = entry.stackGroup ?? 'current'
    const period = periods.get(key) ?? { maxima: [], sums: [] }
    periods.set(key, period)
    for (const [i, value] of entry.values.entries()) {
      if (value === null) continue
      if (!Number.isFinite(value) || value < 0)
        return { periods, error: 'Percentage shares require finite nonnegative observations.' }
      period.maxima[i] = Math.max(period.maxima[i] ?? 0, value)
    }
  }
  for (const entry of series) {
    if (entry.emphasis === 'total') continue
    const period = periods.get(entry.stackGroup ?? 'current')!
    for (const [i, value] of entry.values.entries())
      if (value !== null && period.maxima[i] > 0)
        period.sums[i] = (period.sums[i] ?? 0) + value / period.maxima[i]
  }
  return { periods }
}

export interface IntervalSample {
  start: number
  end: number
  sample: number
}

export function intervalSamples(intervals: (TimeInterval | null)[]): IntervalSample[] {
  return intervals
    .flatMap((interval, sample) =>
      interval ? [{ start: interval[0], end: interval[1], sample }] : [],
    )
    .sort((a, b) => a.start - b.start)
}

/** A column is an interval, not the nearest starting point. Keeping original
 * indices also handles unsampled coordinates inserted by the other period. */
export function intervalSampleAt(samples: IntervalSample[], at: number): number | null {
  if (!Number.isFinite(at)) return null
  let low = 0,
    high = samples.length
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2)
    if (samples[middle].start <= at) low = middle + 1
    else high = middle
  }
  const interval = samples[low - 1]
  return interval && at < interval.end ? interval.sample : null
}

/** Paint coordinates only: callers retain the original observations for every
 * readout and export. Periods stack separately; source totals never stack. */
export function timeGeometry(
  series: TimeGeometrySeries[],
  style: TimeStyle,
  options: {
    denominator?: PercentDenominator
    sourceOrder?: number[]
    horizonScale?: HorizonScale
    horizonBasis?: HorizonBasis
  } = {},
): TimePaintGeometry {
  if (style === 'horizon')
    return horizonGeometry(series, options.horizonScale ?? 'shared', options.horizonBasis)
  const upper = series.map((entry) => [...entry.values])
  const lower = series.map((entry) => entry.values.map((): number | null => null))
  if (style === 'percent_area') {
    const basis = options.denominator ?? percentageDenominator(series)
    if (basis.error) return { upper, lower, error: basis.error }
    let error: string | undefined
    const shares = series.map((entry) => ({
      ...entry,
      values: entry.values.map((value, sample) => {
        if (entry.emphasis === 'total') {
          error = 'Source totals need a separate absolute scale, not a percentage stack.'
          return null
        }
        if (value === null) return null
        if (!Number.isFinite(value) || value < 0) {
          error = 'Percentage shares require finite nonnegative observations.'
          return null
        }
        const index = options.denominator ? (options.sourceOrder?.[sample] ?? sample) : sample
        const period = basis.periods.get(entry.stackGroup ?? 'current')
        const maximum = period?.maxima[index],
          sum = period?.sums[index]
        if (!maximum || !sum) {
          if (value > 0) error = 'Percentage basis is incomplete for the selected observations.'
          return null
        }
        return (100 * (value / maximum)) / sum
      }),
    }))
    if (error) return { upper, lower, error }
    for (const entry of shares)
      for (const [sample, value] of entry.values.entries()) {
        if (value === null) continue
        const interval = entry.intervals?.[sample]
        if (!interval || !interval.every(Number.isFinite) || interval[1] <= interval[0])
          return {
            upper,
            lower,
            error:
              'Bucket intervals are unavailable for percentage area. Run a fresh query; exact values remain available.',
          }
      }
    const geometry = timeGeometry(shares, 'stacked_area')
    if (geometry.error) return geometry
    const tolerance = Number.EPSILON * 100 * Math.max(1, series.length) * 4
    for (const samples of [...geometry.upper, ...geometry.lower])
      for (let i = 0; i < samples.length; i++) {
        const value = samples[i]
        if (value === null) continue
        if (value > 100 + tolerance)
          return {
            upper,
            lower,
            error: 'Percentage basis does not cover the selected observations.',
          }
        if (value > 100) samples[i] = 100 // Coordinate rounding only; never source data.
      }
    return geometry
  }
  const sums = new Map<string, { positive: number[]; negative: number[] }>()
  for (const [index, entry] of series.entries()) {
    let sum = sums.get(entry.stackGroup ?? 'current')
    if (!sum) {
      sum = { positive: [], negative: [] }
      sums.set(entry.stackGroup ?? 'current', sum)
    }
    for (const [sample, value] of entry.values.entries()) {
      if (value === null) continue
      if (!Number.isFinite(value))
        return { upper, lower, error: 'A plotted value cannot be represented numerically.' }
      if (style === 'line' || entry.emphasis === 'total') continue
      if (style === 'stacked_columns') {
        const interval = entry.intervals?.[sample]
        if (
          !interval ||
          !Number.isFinite(interval[0]) ||
          !Number.isFinite(interval[1]) ||
          interval[1] <= interval[0]
        )
          return {
            upper,
            lower,
            error:
              'Bucket intervals are unavailable for these columns. Run a fresh query; exact values remain available.',
          }
      }
      const accumulator = value < 0 ? sum.negative : sum.positive
      const base = accumulator[sample] ?? 0
      const top = base + value
      if (!Number.isFinite(top))
        return {
          upper,
          lower,
          error: 'Stacked coordinates overflow; exact values remain available.',
        }
      lower[index][sample] = base
      upper[index][sample] = top
      accumulator[sample] = top
    }
  }
  return { upper, lower, error: undefined }
}

export function timeValueRange(
  values: (number | null)[][],
  positive: boolean,
): [number, number] | undefined {
  let min = Infinity,
    max = -Infinity
  for (const samples of values)
    for (const value of samples) {
      if (value === null || !Number.isFinite(value) || (positive && value <= 0)) continue
      min = Math.min(min, value)
      max = Math.max(max, value)
    }
  if (!Number.isFinite(min)) return undefined
  if (!positive) {
    min = Math.min(0, min)
    max = Math.max(0, max)
  }
  if (max === min)
    return positive ? [min / 10 || min, Number.isFinite(max * 10) ? max * 10 : max] : [0, 1]
  return [min, max]
}
