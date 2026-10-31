// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { FlowExplorerResult, FlowResultRow } from '../api/flowExplorer'
import type { TimeSeriesInput } from '../components/TimeSeries'
import {
  timeGeometry,
  timeValueRange,
  type TimeInterval,
  type TimeStyle,
} from '../lib/timeGeometry'
import { flowGroupKey, flowGroupLabel } from './flowResults'

const MAX_RENDER_CELLS = 250000

export interface FlowPlotSeries extends TimeSeriesInput {
  groupKey: string
  total?: boolean
}

export const FLOW_TOTAL_KEY = 'total:all-matching-inputs'

export function flowChartGroups(
  current: FlowExplorerResult,
  previous?: FlowExplorerResult,
): FlowResultRow[] {
  const groups = new Map<string, FlowResultRow>()
  for (const result of [current, previous]) {
    for (const row of result?.chart_rows ?? []) groups.set(flowGroupKey(row.group, row.other), row)
    if (result?.chart_other) groups.set(flowGroupKey({}, true), result.chart_other)
  }
  return [...groups.values()]
}

/** Sparse zero sentinels preserve arbitrarily long query windows without
 * allocating a point for every absent minute. No numeric value is aggregated
 * here: approximate coordinates accompany authoritative exact readouts. */
export function flowPlot(
  current: FlowExplorerResult,
  previous: FlowExplorerResult | undefined,
  metric: string,
  cellBudget = MAX_RENDER_CELLS,
  options: { total?: boolean; intervals?: boolean } = {},
): { timestamps: number[]; series: FlowPlotSeries[] } {
  const groups = flowChartGroups(current, previous)
  const plottedGroups = options.total
    ? [...groups, { group: {}, other: false, metrics: {} }]
    : groups
  const periodCount = previous ? 2 : 1
  const prepared = [current, previous]
    .filter((result): result is FlowExplorerResult => Boolean(result))
    .map((result, period) => {
      const from = Date.parse(result.query.from ?? '') / 1000
      const to = Date.parse(result.query.to ?? '') / 1000
      const step = result.query.bucket_seconds ?? 60
      if (
        !Number.isFinite(from) ||
        !Number.isFinite(to) ||
        !Number.isFinite(step) ||
        to <= from ||
        step < 60
      )
        throw new Error('Invalid flow plot time bounds.')
      const duration = to - from
      const last = Math.max(0, Math.ceil(duration / step) - 1)
      const present = new Set(
        (result.chart_rows ?? []).map((row) => flowGroupKey(row.group, row.other)),
      )
      if (result.chart_other) present.add(flowGroupKey({}, true))
      if (options.total) {
        if (!result.total_series || (result.total_groups > 0 && !result.total_series.length))
          throw new Error(
            'Total bucket values are unavailable for this snapshot. Run a fresh query to request its total overlay.',
          )
        present.add(FLOW_TOTAL_KEY)
      }
      const values = new Map<string, Map<number, string>>()
      const times = new Map<string, Map<number, string>>()
      const durations = new Map<string, Map<number, number>>()
      const indices = new Set([0, last])
      const points = [...result.series, ...result.other_series].map((point) => ({
        point,
        total: false,
      }))
      if (options.total)
        points.push(...(result.total_series ?? []).map((point) => ({ point, total: true })))
      for (const { point, total } of points) {
        const key = total ? FLOW_TOTAL_KEY : flowGroupKey(point.group, point.other)
        const index = Math.round((Date.parse(point.ts) / 1000 - from) / step)
        const exact = point.metrics[metric]
        const at = Date.parse(point.ts) / 1000
        if (
          !present.has(key) ||
          (total && (point.other || Object.keys(point.group).length > 0)) ||
          !Number.isFinite(index) ||
          index < 0 ||
          index > last ||
          Math.abs(from + index * step - at) > 0.001 ||
          exact === undefined ||
          !Number.isFinite(Number(exact))
        )
          throw new Error(
            'Flow chart metadata is incomplete or cannot be represented numerically. Exact details and CSV remain available.',
          )
        if (options.intervals && !total) {
          const duration = Number(point.duration_seconds)
          if (
            !point.duration_seconds ||
            !Number.isFinite(duration) ||
            duration <= 0 ||
            duration > step ||
            at + duration > to + 0.001
          )
            throw new Error(
              'Bucket intervals are unavailable or invalid for this visualization. Run a fresh query; exact details and CSV remain available.',
            )
          let known = durations.get(key)
          if (!known) {
            known = new Map()
            durations.set(key, known)
          }
          known.set(index, duration)
        }
        let points = values.get(key)
        if (!points) {
          points = new Map()
          values.set(key, points)
        }
        points.set(index, exact)
        let timestamps = times.get(key)
        if (!timestamps) {
          timestamps = new Map()
          times.set(key, timestamps)
        }
        timestamps.set(index, point.ts)
        for (const neighbor of [index - 1, index, index + 1])
          if (neighbor >= 0 && neighbor <= last) indices.add(neighbor)
        if (indices.size * Math.max(1, plottedGroups.length * periodCount) > cellBudget)
          throw new Error(
            'Flow plot rendering budget exceeded. Increase bucket width or reduce plotted groups; exact table pages and CSV remain available.',
          )
      }
      return { from, to, step, duration, present, values, times, durations, indices, period }
    })
  const elapsedSet = new Set<number>()
  for (const period of prepared) {
    for (const index of period.indices) elapsedSet.add(index * period.step)
    elapsedSet.add(period.duration)
  }
  if (elapsedSet.size * Math.max(1, plottedGroups.length * prepared.length) > cellBudget)
    throw new Error(
      'Flow plot rendering budget exceeded. Increase bucket width or reduce plotted groups; exact table pages and CSV remain available.',
    )
  const elapsed = [...elapsedSet].sort((a, b) => a - b)
  const series: FlowPlotSeries[] = []
  for (const period of prepared)
    for (const [colorIndex, group] of plottedGroups.entries()) {
      const total = Boolean(options.total && colorIndex === groups.length)
      const key = total ? FLOW_TOTAL_KEY : flowGroupKey(group.group, group.other)
      const exactValues = elapsed.map((at) => {
        if (!period.present.has(key) || at >= period.duration) return null
        const index = Math.round(at / period.step)
        // Do not manufacture finer samples when two source periods have
        // different bucket widths. Null is an honest unsampled coordinate.
        if (Math.abs(index * period.step - at) > 0.001) return null
        const value = period.values.get(key)?.get(index) ?? '0'
        return period.period === 0
          ? value
          : `${value} (previous ${period.times.get(key)?.get(index) ?? new Date((period.from + at) * 1000).toISOString()})`
      })
      const values = elapsed.map((at, i) =>
        exactValues[i] === null
          ? null
          : Number(period.values.get(key)?.get(Math.round(at / period.step)) ?? '0'),
      )
      series.push({
        label: `${period.period ? 'Previous' : 'Current'} · ${total ? 'Total (all matching inputs)' : flowGroupLabel(group.group, group.other)} · ${metric}`,
        groupKey: key,
        laneKey: key,
        total,
        emphasis: total ? 'total' : undefined,
        colorIndex,
        lineStyle: period.period ? 'previous' : 'solid',
        stackGroup: period.period ? 'previous' : 'current',
        intervals: options.intervals
          ? elapsed.map((at, i): TimeInterval | null => {
              if (values[i] === null) return null
              const duration =
                period.durations.get(key)?.get(Math.round(at / period.step)) ??
                Math.min(period.step, period.duration - at)
              const start = prepared[0].from + at
              return [start, start + duration]
            })
          : undefined,
        values,
        exactValues,
      })
    }
  return { timestamps: elapsed.map((at) => prepared[0].from + at), series }
}

/** One shared numeric axis range across every displayed metric/period. */
export function flowAxisRange(
  series: TimeSeriesInput[],
  positive: boolean,
): [number, number] | undefined {
  return timeValueRange(
    series.map((entry) => entry.values),
    positive,
  )
}

/** Build each metric/facet's stack independently before synchronizing bounds.
 * Mixing metrics first would invent a sum of unrelated measurements. */
export function flowPaintRange(
  plots: TimeSeriesInput[][],
  style: TimeStyle,
  positive: boolean,
): [number, number] | undefined {
  return timeValueRange(
    plots.flatMap((series) => {
      const geometry = timeGeometry(series, style)
      return geometry.error ? [] : [...geometry.upper, ...geometry.lower]
    }),
    positive,
  )
}

export function mergeFlowTuples(row: Record<string, string>, column: Record<string, string>) {
  for (const [field, value] of Object.entries(column))
    if (row[field] !== undefined && row[field] !== value)
      throw new Error('Matrix row and column assert conflicting values for the same field.')
  return { ...row, ...column }
}
