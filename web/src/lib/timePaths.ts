// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type uPlot from 'uplot'
import type { TimeInterval, TimeStyle } from './timeGeometry'
import { horizonBand } from './horizonGeometry'

/** Stepped source intervals keep isolated and partial buckets visible and
 * never invent observations between disjoint defined spans. */
export function intervalAreaPaths(
  self: uPlot,
  values: ArrayLike<number | null | undefined>,
  lower: (number | null)[],
  intervals: (TimeInterval | null)[] | undefined,
  previous: boolean,
) {
  const stroke = new Path2D(),
    fill = new Path2D()
  const inView = (interval: TimeInterval) =>
    !(
      interval[1] <= (self.scales.x.min ?? -Infinity) ||
      interval[0] >= (self.scales.x.max ?? Infinity)
    )
  let segment: { left: number; right: number; upper: number; lower: number }[] = []
  let previousEnd: number | undefined
  const flush = () => {
    if (!segment.length) return
    const first = segment[0]
    stroke.moveTo(first.left, first.upper)
    fill.moveTo(first.left, first.upper)
    for (const point of segment) {
      stroke.lineTo(point.left, point.upper)
      stroke.lineTo(point.right, point.upper)
      fill.lineTo(point.left, point.upper)
      fill.lineTo(point.right, point.upper)
    }
    for (const point of [...segment].reverse()) {
      fill.lineTo(point.right, point.lower)
      fill.lineTo(point.left, point.lower)
      if (previous) {
        stroke.lineTo(point.right, point.lower)
        stroke.lineTo(point.left, point.lower)
      }
    }
    fill.closePath()
    if (previous) stroke.closePath()
    segment = []
  }
  for (let i = 0; i < values.length; i++) {
    const top = values[i],
      base = lower[i],
      interval = intervals?.[i]
    if (top == null || base == null || !interval || !inView(interval)) continue
    const tolerance = Number.EPSILON * Math.max(1, Math.abs(interval[0])) * 4
    if (previousEnd !== undefined && Math.abs(previousEnd - interval[0]) > tolerance) flush()
    const point = {
      left: self.valToPos(interval[0], 'x', true),
      right: self.valToPos(interval[1], 'x', true),
      upper: self.valToPos(top, 'y', true),
      lower: self.valToPos(base, 'y', true),
    }
    if (Object.values(point).every(Number.isFinite)) segment.push(point)
    else flush()
    previousEnd = interval[1]
  }
  flush()
  return { stroke, fill }
}

export function horizonTimePaths(
  values: (number | null)[],
  base: number,
  amplitude: number,
  intervals: (TimeInterval | null)[] | undefined,
  colors: string[],
  previous: boolean,
): uPlot.Series.PathBuilder {
  return (self) => {
    const fill = new Map<string, Path2D>(),
      stroke = new Map<string, Path2D>()
    for (let band = 0; band < 5; band++) {
      const upper = horizonBand(values, amplitude, base, band).map((value) =>
        band > 0 && value === base ? null : value,
      )
      const lower = upper.map((value) => (value === null ? null : base))
      const paths = intervalAreaPaths(self, upper, lower, intervals, previous)
      // uPlot paints maps in insertion order: higher folded bands cover the
      // lower bands, without multiplying the logical readout series.
      if (!previous) fill.set(colors[band], paths.fill)
      stroke.set(colors[band], paths.stroke)
    }
    const clip = new Path2D()
    clip.rect(self.bbox.left, self.bbox.top, self.bbox.width, self.bbox.height)
    return { stroke, fill: previous ? null : fill, clip, flags: 0 }
  }
}

/** uPlot paths use canvas pixels, including the device-pixel ratio. No paint
 * value replaces the logical source observation or its exact readout. */
export function stackedTimePaths(
  style: Exclude<TimeStyle, 'line' | 'horizon'>,
  lower: (number | null)[],
  intervals: (TimeInterval | null)[] | undefined,
  logarithmic: boolean,
  previous: boolean,
): uPlot.Series.PathBuilder {
  return (self, seriesIndex, idx0, idx1) => {
    const stroke = new Path2D()
    const fill = new Path2D()
    const clip = new Path2D()
    clip.rect(self.bbox.left, self.bbox.top, self.bbox.width, self.bbox.height)
    const values = self.data[seriesIndex]
    const y = (value: number) =>
      logarithmic && value <= 0 ? self.bbox.top + self.bbox.height : self.valToPos(value, 'y', true)
    // Interval observations may start well before the first visible union
    // sample (the other period may have a much finer bucket width).
    const intervalStyle = style === 'stacked_columns' || style === 'percent_area'
    const start = intervalStyle ? 0 : Math.max(0, idx0 - 1)
    const end = intervalStyle ? values.length - 1 : Math.min(values.length - 1, idx1 + 1)
    const inView = (interval: TimeInterval) =>
      !(
        interval[1] <= (self.scales.x.min ?? -Infinity) ||
        interval[0] >= (self.scales.x.max ?? Infinity)
      )
    if (style === 'stacked_columns') {
      for (let i = start; i <= end; i++) {
        const top = values[i],
          base = lower[i],
          interval = intervals?.[i]
        if (top == null || base == null || !interval || top === base || !inView(interval)) continue
        const left = self.valToPos(interval[0], 'x', true)
        const right = self.valToPos(interval[1], 'x', true)
        const upperY = y(top),
          lowerY = y(base)
        if (![left, right, upperY, lowerY].every(Number.isFinite)) continue
        // Exact source interval, including a partial final bucket. Never use
        // the distance to a sparse neighbor as an invented bucket width.
        stroke.rect(left, upperY, right - left, lowerY - upperY)
        if (!previous) fill.rect(left, upperY, right - left, lowerY - upperY)
      }
    } else if (style === 'percent_area') {
      const paths = intervalAreaPaths(self, values, lower, intervals, previous)
      return { stroke: paths.stroke, fill: previous ? null : paths.fill, clip, flags: 0 }
    } else {
      let segment: { x: number; upper: number; lower: number }[] = []
      const flush = () => {
        if (!segment.length) return
        stroke.moveTo(segment[0].x, segment[0].upper)
        fill.moveTo(segment[0].x, segment[0].upper)
        for (const point of segment.slice(1)) {
          stroke.lineTo(point.x, point.upper)
          fill.lineTo(point.x, point.upper)
        }
        for (const point of [...segment].reverse()) fill.lineTo(point.x, point.lower)
        fill.closePath()
        if (previous) {
          const last = segment[segment.length - 1]
          stroke.lineTo(last.x, last.lower)
          for (const point of [...segment].reverse()) stroke.lineTo(point.x, point.lower)
          stroke.closePath()
        }
        segment = []
      }
      for (let i = start; i <= end; i++) {
        const top = values[i],
          base = lower[i]
        if (top == null || base == null) {
          flush()
          continue
        }
        const point = {
          x: self.valToPos(self.data[0][i], 'x', true),
          upper: y(top),
          lower: y(base),
        }
        if (Object.values(point).every(Number.isFinite)) segment.push(point)
        else flush()
      }
      flush()
    }
    return { stroke, fill: previous ? null : fill, clip, flags: 0 }
  }
}
