// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
// Type-only: the uplot runtime is imported on demand inside the effect, so
// environments without canvas (jsdom) never evaluate it and the engine ships
// as its own lazy chunk rather than inflating the route bundle.
import type uPlot from 'uplot'
import { DateTime } from '../time/DateTime'
import { useTime } from '../time/useTime'
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
 * - Accessibility: the canvas is a labeled role="img"; a sampled sr-only
 *   table exposes the same data to assistive tech, and becomes the visible
 *   rendering when canvas is unavailable (also the jsdom test path).
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
}

const SERIES_TOKEN_COUNT = 6
const FALLBACK_ROW_CAP = 24

interface VizTheme {
  colors: string[]
  dashes: (number[] | undefined)[]
  grid: string
  axis: string
  font: string
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
  const dashes: (number[] | undefined)[] = []
  for (let index = 1; index <= SERIES_TOKEN_COUNT; index += 1) {
    colors.push(readColor(`--chart-${index}`))
    const dash = read(`--viz-series-${index}-dash`)
    dashes.push(dash && dash !== 'none' ? dash.split(/\s+/).map(Number) : undefined)
  }
  const captionRem = Number.parseFloat(read('--font-size-2xs'))
  const fontPx = Math.round(Number.isFinite(captionRem) ? captionRem * rootPx : 11)
  return {
    colors,
    dashes,
    grid: readColor('--chart-grid'),
    axis: readColor('--chart-axis'),
    font: `${fontPx}px ${read('--font-sans') || 'sans-serif'}`,
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
}: {
  /** Shared x values for every series: ISO strings or unix seconds/millis. */
  timestamps: (string | number)[]
  /** Aligned y series; null marks an honest gap (never interpolated). */
  series: TimeSeriesInput[]
  /** Accessible name for the plot and its data-table twin. */
  label: string
  /** Value renderer shared by the y axis, cursor readout, and table. */
  formatValue?: (value: number) => string
}) {
  const targetRef = useRef<HTMLDivElement | null>(null)
  const plotRef = useRef<uPlot | null>(null)
  const cursorIdxRef = useRef<number | null>(null)
  const timeReadoutRef = useRef<HTMLSpanElement | null>(null)
  const valueRefs = useRef<(HTMLSpanElement | null)[]>([])
  const { format: formatTime, timeZone } = useTime()
  const [themeEpoch, setThemeEpoch] = useState(0)
  // Honest failure: if the chart engine cannot load or construct (import
  // failure, hostile Intl locale, …), the sampled data table becomes the
  // visible rendering — never a silent empty frame.
  const [engineFailed, setEngineFailed] = useState(false)
  const canPlot = useMemo(canvasAvailable, []) && !engineFailed

  const data = useMemo<uPlot.AlignedData>(() => {
    const xs = timestamps.map(toSeconds)
    const order = xs.map((_, index) => index).sort((a, b) => xs[a] - xs[b])
    const sortedXs = order.map((index) => xs[index])
    const ys = series.map((entry) => order.map((index) => entry.values[index] ?? null))
    return [sortedXs, ...ys] as uPlot.AlignedData
  }, [timestamps, series])

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
      const rect = target.getBoundingClientRect()
      const options: uPlot.Options = {
        width: Math.max(240, Math.floor(rect.width)),
        height: Math.max(120, Math.floor(rect.height)),
        legend: { show: false },
        cursor: { points: { size: 8 } },
        // Axis labels follow the app's UTC/preferred timezone mode — the axis
        // and the readout must never disagree with the scope card's promise.
        tzDate: (ts) => UPlot.tzDate(new Date(ts * 1000), timeZone),
        series: [
          {},
          ...series.map((entry, index) => ({
            label: entry.label,
            stroke: theme.colors[index % theme.colors.length],
            dash: theme.dashes[index % theme.dashes.length],
            width: 2,
            spanGaps: false,
            points: { show: false },
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
            grid: { stroke: theme.grid, width: 1 },
            ticks: { show: false },
            values: (_u: uPlot, splits: number[]) =>
              splits.map((split) => (split == null ? '' : format(split))),
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
                  idx == null ? '—' : formatTime(new Date(u.data[0][idx] * 1000)).text || '—'
              }
              series.forEach((_, seriesIndex) => {
                const valueEl = valueRefs.current[seriesIndex]
                if (!valueEl) return
                const raw = idx == null ? null : (u.data[seriesIndex + 1][idx] as number | null)
                valueEl.textContent = raw == null ? '—' : format(raw)
              })
            },
          ],
        },
      }
      plot = new UPlot(options, data, target)
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
  }, [canPlot, data, series, formatValue, formatTime, timeZone, themeEpoch])

  // Keyboard crosshair: arrows step samples, Home/End jump, Escape clears.
  // Runs through uPlot's setCursor so the pointer hook updates the readout.
  const handlePlotKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const plot = plotRef.current
    if (!plot) return
    const xs = plot.data[0]
    const count = xs.length
    if (count === 0) return
    const moveTo = (rawIdx: number) => {
      const idx = Math.max(0, Math.min(count - 1, rawIdx))
      const left = plot.valToPos(xs[idx], 'x')
      const top = plot.cursor.top != null && plot.cursor.top >= 0 ? plot.cursor.top : 0
      plot.setCursor({ left, top })
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
      case 'Escape':
        plot.setCursor({ left: -10, top: -10 })
        break
      default:
        return
    }
    event.preventDefault()
  }

  const sampleCount = data[0].length
  const tableStart = Math.max(0, sampleCount - FALLBACK_ROW_CAP)
  const tableRows: { x: number; values: (number | null)[] }[] = []
  for (let index = tableStart; index < sampleCount; index += 1) {
    tableRows.push({
      x: (data[0] as number[])[index],
      values: series.map((_, seriesIndex) => (data[seriesIndex + 1] as (number | null)[])[index]),
    })
  }
  const caption =
    sampleCount > FALLBACK_ROW_CAP
      ? `${label} (most recent ${FALLBACK_ROW_CAP} of ${sampleCount} samples)`
      : label

  return (
    <div className={styles.wrap}>
      {canPlot ? (
        <>
          <div
            ref={targetRef}
            role="img"
            aria-label={`${label}. Use the arrow keys to step through samples.`}
            tabIndex={0}
            onKeyDown={handlePlotKeyDown}
            className={styles.plot}
          />
          {/* Series legend + crosshair readout. Pointer affordance only:
              assistive tech reads the sampled table twin below, so this row is
              hidden from it to avoid announcing every cursor move. */}
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
                      stroke: `hsl(var(--chart-${(index % SERIES_TOKEN_COUNT) + 1}))`,
                      strokeDasharray: `var(--viz-series-${(index % SERIES_TOKEN_COUNT) + 1}-dash)`,
                    }}
                  />
                </svg>
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
        </>
      ) : null}
      <table className={canPlot ? 'sr-only' : styles.fallbackTable}>
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
                  {value == null ? '—' : formatValue ? formatValue(value) : String(value)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
