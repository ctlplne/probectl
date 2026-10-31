// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'
// Type-only: the uplot runtime is imported on demand inside the effect, so
// environments without canvas (jsdom) never evaluate it and the engine ships
// as its own lazy chunk rather than inflating the route bundle.
import type uPlot from 'uplot'
import { DateTime } from '../time/DateTime'
import { useTime } from '../time/useTime'
import { formatPlotCoordinate } from '../lib/chartNumbers'
import {
  intervalSamples,
  intervalSampleAt,
  percentageDenominator,
  timeGeometry,
  timeValueRange,
  type TimeInterval,
  type TimeStyle,
  type PercentDenominator,
} from '../lib/timeGeometry'
import { stackedTimePaths, horizonTimePaths } from '../lib/timePaths'
import {
  horizonBasis as makeHorizonBasis,
  type HorizonBasis,
  type HorizonScale,
} from '../lib/horizonGeometry'
import { Button } from './Button'
import styles from './TimeSeries.module.css'

/**
 * TimeSeries (S11/S43 charting layer, first slice): a token-skinned uPlot
 * wrapper that renders inside a ChartShell plot slot. Design contract:
 *
 * - Every visual value comes from design tokens, resolved at runtime with
 *   getComputedStyle, so the light and dark themes (and any deployment override)
 *   restyle the canvas without a code change. A MutationObserver on
 *   <html data-theme> rebuilds the plot on theme swap.
 * - Series carry the non-color encoding too: --viz-series-N-dash patterns
 *   accompany --chart-N, matching the SVG viz grammar.
 * - Accessibility: the canvas is a labeled role="img"; a paged exact-value
 *   table reaches every sample with a bounded DOM, also serving as the visible
 *   rendering when canvas is unavailable (the jsdom test path).
 * - Interactions: crosshair readout, drag x-zoom, double-click reset, and
 *   keyboard crosshair navigation (Arrow/Home/End step samples, Escape
 *   clears) — the gate that lets TimeSeries replace Sparkline everywhere.
 *
 * NOTE: import this module directly (not via the components barrel) so uplot
 * rides only in lazy route chunks and the app-shell entry budget stays flat.
 */

export interface TimeSeriesInput {
  label: string
  values: (number | null)[]
  /** Authoritative readout values; numeric values serve only plot geometry. */
  exactValues?: (string | null)[]
  /** Stable identity in a palette, independent of hiding other series. */
  colorIndex?: number
  /** Explicit period encoding; omitted preserves the legacy token patterns. */
  lineStyle?: 'solid' | 'previous'
  emphasis?: 'total'
  /** Independent populations (for example, current and previous periods). */
  stackGroup?: string
  laneKey?: string
  /** Actual source bucket intervals, aligned with values. */
  intervals?: (TimeInterval | null)[]
}

const SERIES_TOKEN_COUNT = 6
const SAMPLE_PAGE_SIZE = 24

interface VizTheme {
  colors: string[]
  fills: string[]
  horizonColors: string[]
  dashes: (number[] | undefined)[]
  previousDash: number[]
  totalColor: string
  totalWidth: number
  grid: string
  axis: string
  font: string
  axisSpace: number
}

function readVizTheme(): VizTheme {
  const computed = getComputedStyle(document.documentElement)
  const rootPx = Number.parseFloat(computed.fontSize) || 16
  const read = (name: string) => computed.getPropertyValue(name).trim()
  // Colour tokens hold a bare HSL triplet ("28 85% 30%"). uPlot assigns these
  // straight to ctx.strokeStyle, which silently ignores an unparseable value and
  // paints black — so the triplet is wrapped here into a real CSS colour.
  const readColor = (name: string) => {
    const raw = read(name)
    return raw && !raw.startsWith('#') && !raw.includes('(') ? `hsl(${raw})` : raw
  }
  const colors: string[] = []
  const fills: string[] = []
  const dashes: (number[] | undefined)[] = []
  for (let index = 1; index <= SERIES_TOKEN_COUNT; index += 1) {
    colors.push(readColor(`--chart-${index}`))
    fills.push(`hsl(${read(`--chart-${index}`)} / ${read('--viz-stack-fill-alpha')})`)
    const dash = read(`--viz-series-${index}-dash`)
    dashes.push(dash && dash !== 'none' ? dash.split(/\s+/).map(Number) : undefined)
  }
  const captionRem = Number.parseFloat(read('--font-size-2xs'))
  const fontPx = Math.round(Number.isFinite(captionRem) ? captionRem * rootPx : 11)
  return {
    colors,
    fills,
    dashes,
    horizonColors: Array.from({ length: 5 }, (_, index) =>
      readColor(`--viz-horizon-band-${index + 1}`),
    ),
    previousDash: read('--viz-comparison-previous-dash').split(/\s+/).map(Number),
    totalColor: readColor('--viz-total-color'),
    totalWidth: Number(read('--viz-total-width')),
    grid: readColor('--chart-grid'),
    axis: readColor('--chart-axis'),
    font: `${fontPx}px ${read('--font-sans') || 'sans-serif'}`,
    axisSpace: fontPx + (Number.parseFloat(read('--space-2')) || 0) * rootPx,
  }
}

function canvasAvailable(): boolean {
  // jsdom exposes HTMLCanvasElement#getContext as a logging placeholder: even
  // inside try/catch, calling it emits an "unimplemented" error. The context
  // constructor is the browser capability we actually need, so reject that
  // partial surface before invoking the method.
  if (typeof CanvasRenderingContext2D === 'undefined') return false
  try {
    return Boolean(document.createElement('canvas').getContext('2d'))
  } catch {
    return false
  }
}

function toSeconds(ts: string | number): number {
  if (typeof ts === 'number') return ts > 1e12 ? ts / 1000 : ts
  return Date.parse(ts) / 1000
}

export function TimeSeries({
  timestamps,
  series,
  label,
  formatValue,
  formatAxisValue,
  logarithmic: requestedLogarithmic = false,
  yRange,
  plotHeight,
  timeStyle = 'line',
  percentDenominator,
  horizonBasis,
  horizonScale = 'shared',
}: {
  /** Shared x values for every series: ISO strings or unix seconds/millis. */
  timestamps: (string | number)[]
  /** Aligned y series; null marks an honest gap (never interpolated). */
  series: TimeSeriesInput[]
  /** Accessible name for the plot and its data-table twin. */
  label: string
  /** Value renderer for readouts/table; also preserves existing custom axes. */
  formatValue?: (value: number) => string
  /** Compact coordinate labels may differ from exact data readouts. */
  formatAxisValue?: (value: number) => string
  logarithmic?: boolean
  yRange?: [number, number]
  /** Native plots let the inspector grow naturally below a fixed plot slot. */
  plotHeight?: string
  timeStyle?: TimeStyle
  /** Shared basis uses the original input sample order, before timestamp sorting. */
  percentDenominator?: PercentDenominator
  horizonBasis?: HorizonBasis
  horizonScale?: HorizonScale
}) {
  const logarithmic =
    requestedLogarithmic && timeStyle !== 'percent_area' && timeStyle !== 'horizon'
  const intervalStyle =
    timeStyle === 'stacked_columns' || timeStyle === 'percent_area' || timeStyle === 'horizon'
  const targetRef = useRef<HTMLDivElement | null>(null)
  const plotRef = useRef<uPlot | null>(null)
  const cursorIdxRef = useRef<number | null>(null)
  const timeReadoutRef = useRef<HTMLSpanElement | null>(null)
  const valueRefs = useRef<(HTMLSpanElement | null)[]>([])
  const { format: formatTime, timeZone } = useTime()
  const [themeEpoch, setThemeEpoch] = useState(0)
  // Honest failure: if the chart engine cannot load or construct (import
  // failure, hostile Intl locale, …), the paged data table becomes the
  // visible rendering — never a silent empty frame.
  const [engineFailed, setEngineFailed] = useState(false)
  const engineAvailable = useMemo(canvasAvailable, []) && !engineFailed
  const instructionId = useId()
  const [keyboard, setKeyboard] = useState<{ sample: number; series: number } | null>(null)
  const [tableOffset, setTableOffset] = useState<number | null>(null)

  const { data, exactData, intervals, sourceOrder } = useMemo(() => {
    const xs = timestamps.map(toSeconds)
    const order = xs.map((_, index) => index).sort((a, b) => xs[a] - xs[b])
    const sortedXs = order.map((index) => xs[index])
    const ys = series.map((entry) => order.map((index) => entry.values[index] ?? null))
    return {
      data: [sortedXs, ...ys] as uPlot.AlignedData,
      sourceOrder: order,
      exactData: series.map((entry) =>
        entry.exactValues ? order.map((index) => entry.exactValues?.[index] ?? null) : undefined,
      ),
      intervals: series.map((entry) =>
        entry.intervals ? order.map((index) => entry.intervals?.[index] ?? null) : undefined,
      ),
    }
  }, [timestamps, series])
  const hasPositive = useMemo(
    () =>
      series.some((_, i) =>
        (data[i + 1] as (number | null)[]).some((value) => value !== null && value > 0),
      ),
    [data, series],
  )
  const intervalLookups = useMemo(
    () => intervals.map((entry) => intervalSamples(entry ?? [])),
    [intervals],
  )
  const denominator = useMemo(
    () =>
      timeStyle === 'percent_area'
        ? (percentDenominator ?? percentageDenominator(series))
        : undefined,
    [timeStyle, percentDenominator, series],
  )
  const densityBasis = useMemo(
    () => (timeStyle === 'horizon' ? (horizonBasis ?? makeHorizonBasis(series)) : undefined),
    [timeStyle, horizonBasis, series],
  )
  const geometry = useMemo(
    () =>
      timeGeometry(
        series.map((entry, i) => ({
          ...entry,
          values: data[i + 1] as (number | null)[],
          intervals: intervals[i],
        })),
        timeStyle,
        { denominator, sourceOrder, horizonScale, horizonBasis: densityBasis },
      ),
    [series, data, intervals, timeStyle, denominator, sourceOrder, horizonScale, densityBasis],
  )
  const hasPercentage = geometry.upper.some((samples) => samples.some((value) => value !== null))
  const canPlot =
    engineAvailable &&
    !geometry.error &&
    (!logarithmic || hasPositive) &&
    (timeStyle !== 'percent_area' || hasPercentage)
  const effectiveRange = useMemo(
    () =>
      timeStyle === 'horizon'
        ? ([0, geometry.horizon?.keys.length || 1] as [number, number])
        : timeStyle === 'percent_area'
          ? ([0, 100] as [number, number])
          : (yRange ??
            (timeStyle === 'line'
              ? undefined
              : timeValueRange([...geometry.upper, ...geometry.lower], logarithmic))),
    [yRange, timeStyle, geometry, logarithmic],
  )
  const plotData = useMemo(
    () =>
      logarithmic
        ? ([
            data[0],
            ...geometry.upper.map((values) =>
              values.map((value) => (value !== null && value > 0 ? value : null)),
            ),
          ] as uPlot.AlignedData)
        : ([data[0], ...geometry.upper] as uPlot.AlignedData),
    [data, geometry, logarithmic],
  )
  const clipped =
    timeStyle !== 'percent_area' &&
    timeStyle !== 'horizon' &&
    yRange &&
    series.some((_, i) =>
      geometry.upper[i].some((value) => value !== null && (value < yRange[0] || value > yRange[1])),
    )

  // Rebuild on deployment-level theme (or density) swap: canvas strokes are
  // resolved token values, so they must be re-read when tokens change.
  useEffect(() => {
    if (typeof MutationObserver === 'undefined') return undefined
    const observer = new MutationObserver(() => setThemeEpoch((epoch) => epoch + 1))
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme', 'data-density'],
    })
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    void themeEpoch // retrigger: tokens under <html data-theme> changed
    if (!canPlot) return undefined
    const target = targetRef.current
    if (!target) return undefined
    let disposed = false
    let plot: uPlot | null = null
    let observer: ResizeObserver | undefined
    const mount = import('uplot').then(({ default: UPlot }) => {
      if (disposed) return
      const theme = readVizTheme()
      const format = formatValue ?? ((value: number) => String(value))
      const formatAxis =
        timeStyle === 'horizon'
          ? (value: number) => String((geometry.horizon?.keys.length ?? 0) - Math.floor(value))
          : timeStyle === 'percent_area'
            ? (value: number) => `${formatPlotCoordinate(value)}%`
            : (formatAxisValue ?? formatValue ?? formatPlotCoordinate)
      const rect = target.getBoundingClientRect()
      const xs = data[0]
      const singleTimestamp = xs.length > 0 && xs[0] === xs[xs.length - 1]
      // Raw logarithmic minor splits can be less than a pixel apart over a
      // large range. Share readable positions between labels and the grid;
      // the original observations and numeric scale remain untouched.
      const logFilter: uPlot.Axis.Filter | undefined = logarithmic
        ? (self, splits) => {
            const selected: (number | null)[] = splits.map(() => null)
            let previous: number | undefined
            for (let index = splits.length - 1; index >= 0; index--) {
              const position = self.valToPos(splits[index], 'y')
              if (
                Number.isFinite(position) &&
                (previous === undefined || Math.abs(position - previous) >= theme.axisSpace)
              ) {
                selected[index] = splits[index]
                previous = position
              }
            }
            return selected
          }
        : undefined
      const options: uPlot.Options = {
        width: Math.max(240, Math.floor(rect.width)),
        height: Math.max(120, Math.floor(rect.height)),
        legend: { show: false },
        // uPlot's numeric fallback expands a lone Unix timestamp by its
        // magnitude, yielding a years-wide axis. Give it display padding only:
        // the original aligned samples and their timestamps stay untouched.
        scales: {
          ...(singleTimestamp
            ? { x: { range: [xs[0] - 30, xs[0] + 30] as [number, number] } }
            : {}),
          y: { distr: logarithmic ? 3 : 1, ...(effectiveRange ? { range: effectiveRange } : {}) },
        },
        cursor: {
          points: { size: 8 },
          ...(intervalStyle
            ? {
                dataIdx: (_u: uPlot, seriesIndex: number, closest: number, at: number) =>
                  seriesIndex === 0 || series[seriesIndex - 1].emphasis === 'total'
                    ? closest
                    : intervalSampleAt(intervalLookups[seriesIndex - 1], at),
              }
            : {}),
        },
        // Axis labels follow the app's UTC/preferred timezone mode — the axis
        // and the readout must never disagree with the scope card's promise.
        tzDate: (ts) => UPlot.tzDate(new Date(ts * 1000), timeZone),
        series: [
          {},
          ...series.map((entry, index) => ({
            label: entry.label,
            stroke:
              entry.emphasis === 'total'
                ? theme.totalColor
                : theme.colors[(entry.colorIndex ?? index) % theme.colors.length],
            dash:
              entry.lineStyle === 'previous'
                ? theme.previousDash
                : entry.lineStyle === 'solid'
                  ? undefined
                  : theme.dashes[(entry.colorIndex ?? index) % theme.dashes.length],
            width: entry.emphasis === 'total' ? theme.totalWidth : 2,
            ...(timeStyle === 'horizon' && geometry.horizon
              ? {
                  fill: theme.horizonColors[0],
                  paths: horizonTimePaths(
                    data[index + 1] as (number | null)[],
                    geometry.horizon.bases[index],
                    geometry.horizon.amplitudes[index],
                    intervals[index],
                    theme.horizonColors,
                    entry.lineStyle === 'previous',
                  ),
                }
              : timeStyle !== 'line' && timeStyle !== 'horizon' && entry.emphasis !== 'total'
                ? {
                    ...(entry.lineStyle === 'previous'
                      ? {}
                      : { fill: theme.fills[(entry.colorIndex ?? index) % theme.fills.length] }),
                    paths: stackedTimePaths(
                      timeStyle,
                      geometry.lower[index],
                      intervals[index],
                      logarithmic,
                      entry.lineStyle === 'previous',
                    ),
                  }
                : {}),
            spanGaps: false,
            points: {
              show: singleTimestamp && (timeStyle === 'line' || entry.emphasis === 'total'),
            },
            value: (_u: uPlot, raw: number | null) => (raw == null ? '—' : format(raw)),
          })),
        ],
        axes: [
          {
            stroke: theme.axis,
            font: theme.font,
            size: 32,
            grid: { show: false },
            ticks: { stroke: theme.grid, width: 1 },
          },
          {
            stroke: theme.axis,
            font: theme.font,
            size: 60,
            ...(geometry.horizon
              ? {
                  space: theme.axisSpace,
                  splits: () =>
                    geometry
                      .horizon!.keys.map((_, index) => geometry.horizon!.keys.length - index - 0.5)
                      .reverse(),
                }
              : {}),
            ...(logFilter ? { space: theme.axisSpace, filter: logFilter } : {}),
            grid: { stroke: theme.grid, width: 1, ...(logFilter ? { filter: logFilter } : {}) },
            ticks: { show: false },
            values: (_u: uPlot, splits: number[]) =>
              splits.map((split) => (split == null ? '' : formatAxis(split))),
          },
        ],
        hooks: {
          // Crosshair readout: written imperatively into the legend row so a
          // mousemove never re-renders the React tree.
          setCursor: [
            (u: uPlot) => {
              const idx = u.cursor.idx
              cursorIdxRef.current = idx ?? null
              const timeEl = timeReadoutRef.current
              if (timeEl) {
                timeEl.textContent =
                  idx == null
                    ? '—'
                    : formatTime(
                        new Date(
                          (intervalStyle ? u.posToVal(u.cursor.left ?? 0, 'x') : u.data[0][idx]) *
                            1000,
                        ),
                      ).text || '—'
              }
              series.forEach((_, seriesIndex) => {
                const valueEl = valueRefs.current[seriesIndex]
                if (!valueEl) return
                const sample =
                  intervalStyle && series[seriesIndex].emphasis !== 'total'
                    ? (u.cursor.idxs?.[seriesIndex + 1] ?? null)
                    : idx
                const raw = sample == null ? null : (data[seriesIndex + 1][sample] as number | null)
                valueEl.textContent =
                  raw == null
                    ? '—'
                    : ((sample == null ? undefined : exactData[seriesIndex]?.[sample]) ??
                      format(raw))
              })
            },
          ],
        },
      }
      plot = new UPlot(options, plotData, target)
      plotRef.current = plot
      if (typeof ResizeObserver !== 'undefined') {
        observer = new ResizeObserver((entries) => {
          const width = Math.floor(entries[0]?.contentRect.width ?? 0)
          const height = Math.floor(entries[0]?.contentRect.height ?? 0)
          if (width > 0 && height > 0) plot?.setSize({ width, height })
        })
        observer.observe(target)
      }
    })
    void mount.catch(() => {
      if (!disposed) setEngineFailed(true)
    })
    return () => {
      disposed = true
      observer?.disconnect()
      plot?.destroy()
      plotRef.current = null
      cursorIdxRef.current = null
    }
  }, [
    canPlot,
    data,
    plotData,
    geometry,
    intervals,
    intervalLookups,
    timeStyle,
    intervalStyle,
    exactData,
    series,
    formatValue,
    formatAxisValue,
    logarithmic,
    effectiveRange,
    formatTime,
    timeZone,
    themeEpoch,
  ])

  // Keyboard updates a dedicated exact-value status. Pointer movement only
  // updates the imperative legend, avoiding live-region mousemove chatter.
  const handlePlotKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const plot = plotRef.current
    if (!plot) return
    const xs = plot.data[0]
    const count = xs.length
    if (count === 0) return
    const moveTo = (rawIdx: number, seriesIndex = keyboard?.series ?? 0) => {
      const idx = Math.max(0, Math.min(count - 1, rawIdx))
      const left = plot.valToPos(xs[idx], 'x')
      const top = plot.cursor.top != null && plot.cursor.top >= 0 ? plot.cursor.top : 0
      plot.setCursor({ left, top })
      setKeyboard({ sample: idx, series: Math.max(0, Math.min(series.length - 1, seriesIndex)) })
    }
    const current = cursorIdxRef.current
    switch (event.key) {
      case 'ArrowRight':
        moveTo(current == null ? 0 : current + 1)
        break
      case 'ArrowLeft':
        moveTo(current == null ? count - 1 : current - 1)
        break
      case 'Home':
        moveTo(0)
        break
      case 'End':
        moveTo(count - 1)
        break
      case 'ArrowUp':
        moveTo(current ?? 0, (keyboard?.series ?? 0) - 1)
        break
      case 'ArrowDown':
        moveTo(current ?? 0, (keyboard?.series ?? 0) + 1)
        break
      case 'Escape':
        plot.setCursor({ left: -10, top: -10 })
        setKeyboard(null)
        break
      default:
        return
    }
    event.preventDefault()
  }

  const sampleCount = data[0].length
  const tableStart = Math.max(
    0,
    Math.min(tableOffset ?? sampleCount - SAMPLE_PAGE_SIZE, sampleCount - 1),
  )
  const tableEnd = Math.min(sampleCount, tableStart + SAMPLE_PAGE_SIZE)
  const tableRows: { x: number; index: number; values: (number | null)[] }[] = []
  for (let index = tableStart; index < tableEnd; index += 1) {
    tableRows.push({
      x: (data[0] as number[])[index],
      index,
      values: series.map((_, seriesIndex) => (data[seriesIndex + 1] as (number | null)[])[index]),
    })
  }
  const caption =
    sampleCount > SAMPLE_PAGE_SIZE
      ? `${label} (samples ${tableStart + 1}–${tableEnd} of ${sampleCount})`
      : label
  const selectedSample = keyboard && sampleCount ? Math.min(keyboard.sample, sampleCount - 1) : null
  const selectedSeries =
    keyboard && series.length ? Math.min(keyboard.series, series.length - 1) : null
  const keyboardValue =
    selectedSample !== null && selectedSeries !== null
      ? (data[selectedSeries + 1][selectedSample] as number | null)
      : null
  const keyboardReadout =
    selectedSample !== null && selectedSeries !== null
      ? `Sample ${selectedSample + 1} of ${sampleCount}. ${formatTime(new Date(data[0][selectedSample] * 1000)).text}. ${series[selectedSeries].label}: ${keyboardValue == null ? '—' : (exactData[selectedSeries]?.[selectedSample] ?? (formatValue ? formatValue(keyboardValue) : String(keyboardValue)))}`
      : ''

  const table = (
    <>
      {sampleCount > SAMPLE_PAGE_SIZE && (
        <div className={styles.sampleActions} role="group" aria-label={`${label} sample pages`}>
          <Button size="sm" disabled={!tableStart} onClick={() => setTableOffset(0)}>
            First samples
          </Button>
          <Button
            size="sm"
            disabled={!tableStart}
            onClick={() => setTableOffset(Math.max(0, tableStart - SAMPLE_PAGE_SIZE))}
          >
            Earlier samples
          </Button>
          <Button
            size="sm"
            disabled={tableEnd >= sampleCount}
            onClick={() => setTableOffset(tableEnd)}
          >
            Later samples
          </Button>
          <Button
            size="sm"
            disabled={tableEnd >= sampleCount}
            onClick={() => setTableOffset(Math.max(0, sampleCount - SAMPLE_PAGE_SIZE))}
          >
            Latest samples
          </Button>
        </div>
      )}
      <div
        className={styles.fallbackRegion}
        role="region"
        tabIndex={0}
        aria-label={`${label} exact sample values`}
      >
        <table className={styles.fallbackTable}>
          <caption>{caption}</caption>
          <thead>
            <tr>
              <th scope="col">Time</th>
              {series.map((entry) => (
                <th key={entry.label} scope="col">
                  {entry.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {tableRows.map((row) => (
              <tr key={row.x}>
                <th scope="row">
                  <DateTime value={new Date(row.x * 1000)} />
                </th>
                {row.values.map((value, index) => (
                  <td key={series[index].label}>
                    {value == null
                      ? '—'
                      : (exactData[index]?.[row.index] ??
                        (formatValue ? formatValue(value) : String(value)))}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )

  const effectiveHeight = geometry.horizon
    ? `max(${plotHeight ?? 'calc(var(--space-8) * 8)'}, calc(${geometry.horizon.keys.length} * (var(--font-size-2xs) + var(--space-3)) + var(--space-8) * 2))`
    : plotHeight

  return (
    <div className={styles.wrap} style={effectiveHeight ? { height: 'auto' } : undefined}>
      {geometry.error && <p className={styles.instructions}>{geometry.error}</p>}
      {timeStyle === 'percent_area' && !geometry.error && !hasPercentage && (
        <p className={styles.instructions}>
          No percentage is defined for these samples. Exact zeros and missing observations remain in
          the sample table.
        </p>
      )}
      {logarithmic && (
        <p className={styles.instructions}>
          {hasPositive
            ? 'Logarithmic axis: nonpositive values have no plotted coordinate; exact values remain in the sample table.'
            : 'No positive values can be plotted on a logarithmic axis. Every exact sample remains available below.'}
        </p>
      )}
      {clipped && (
        <p className={styles.instructions}>
          Some values fall outside the shared axis range; exact values remain in the sample table.
        </p>
      )}
      {geometry.horizon && !geometry.error && (
        <details className={styles.inspector}>
          <summary>Horizon lanes and five-band scales</summary>
          <p>
            Each lane has five overlaid bands, numbered low to high. Current observations fill the
            bands; previous observations use dashed outlines. Each band spans one fifth of its lane
            amplitude. Zero is a baseline; missing observations are gaps. Amplitudes are approximate
            paint coordinates; source counts stay exact below.
          </p>
          <div className={styles.horizonBands}>
            {[1, 2, 3, 4, 5].map((band) => (
              <span key={band}>
                <i aria-hidden="true" style={{ background: `var(--viz-horizon-band-${band})` }} />
                Band {band}
              </span>
            ))}
          </div>
          <ol>
            {geometry.horizon.keys.map((key, index) => {
              const source = series.findIndex((entry) => entry.laneKey === key)
              return (
                <li key={key}>
                  Lane {index + 1} · {series[source]?.label} · Amplitude{' '}
                  {formatPlotCoordinate(geometry.horizon!.amplitudes[source])} (current and
                  previous)
                </li>
              )
            })}
          </ol>
        </details>
      )}
      {canPlot ? (
        <>
          <div
            ref={targetRef}
            role="img"
            aria-label={`${label}. Use the arrow keys to step through samples.`}
            aria-describedby={instructionId}
            tabIndex={0}
            onKeyDown={handlePlotKeyDown}
            className={styles.plot}
            style={effectiveHeight ? { height: effectiveHeight, flex: '0 0 auto' } : undefined}
          />
          {/* Pointer-only readout; keyboard uses the exact status below. */}
          <div className={styles.readout} aria-hidden="true">
            <span ref={timeReadoutRef} className={styles.readoutTime}>
              —
            </span>
            {series.map((entry, index) => (
              <span key={entry.label} className={styles.readoutSeries}>
                <svg className={styles.swatch} viewBox="0 0 20 8">
                  <line
                    x1="1"
                    y1="4"
                    x2="19"
                    y2="4"
                    style={{
                      stroke:
                        entry.emphasis === 'total'
                          ? 'hsl(var(--viz-total-color))'
                          : `hsl(var(--chart-${((entry.colorIndex ?? index) % SERIES_TOKEN_COUNT) + 1}))`,
                      strokeWidth:
                        entry.emphasis === 'total' ? 'var(--viz-total-width)' : undefined,
                      strokeDasharray:
                        entry.lineStyle === 'previous'
                          ? 'var(--viz-comparison-previous-dash)'
                          : entry.lineStyle === 'solid'
                            ? 'none'
                            : `var(--viz-series-${((entry.colorIndex ?? index) % SERIES_TOKEN_COUNT) + 1}-dash)`,
                    }}
                  />
                </svg>
                {geometry.horizon
                  ? `Lane ${geometry.horizon.keys.indexOf(entry.laneKey ?? '') + 1} · `
                  : ''}
                {entry.label}
                <span
                  ref={(el) => {
                    valueRefs.current[index] = el
                  }}
                  className={styles.readoutValue}
                >
                  —
                </span>
              </span>
            ))}
          </div>
          <p id={instructionId} className={styles.instructions}>
            Left/right: samples. Up/down: series. Home/End: first/last sample. Escape: clear.
          </p>
          <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
            {keyboardReadout}
          </div>
        </>
      ) : null}
      {canPlot ? (
        <details className={styles.inspector}>
          <summary>Inspect all {sampleCount} plotted samples</summary>
          {table}
        </details>
      ) : (
        table
      )}
    </div>
  )
}
