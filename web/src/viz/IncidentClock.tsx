// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo } from 'react'
import type { Severity } from '../api/incidents'
import { DateTime } from '../time/DateTime'
import { useTime } from '../time/useTime'
import styles from './IncidentClock.module.css'

/**
 * IncidentClock (S43): the "one incident clock" as a real timeline — one
 * absolute time axis, one lane per plane with evidence, candidate changes on
 * the same axis. Signals are circles toned by severity; changes are neutral
 * diamonds (shape is the non-color encoding). Markers are real buttons, so
 * selection, keyboard access, and the X3 evidence coordination are the same
 * contract the flat clock list had: aria-pressed follows the shared
 * selection, and activating a marker selects that evidence everywhere.
 *
 * Lanes render only for planes that actually produced evidence — coverage
 * gaps stay in the five-plane evidence panel, which states them explicitly
 * ("a coverage gap, not a healthy zero"); an empty lane here would just
 * whisper what that panel says out loud.
 */

export interface IncidentClockLane {
  id: string
  label: string
}

export interface IncidentClockItem {
  id: string
  laneID: string
  /** Raw plane identifier (or "change") — exposed to assistive tech. */
  meta: string
  title: string
  occurredAt: string
  severity?: Severity
  kind: 'signal' | 'change'
}

const MIN_SPAN_MS = 60_000

function toneClass(item: IncidentClockItem): string {
  if (item.kind === 'change') return styles.toneNeutral
  if (item.severity === 'critical') return styles.toneDanger
  if (item.severity === 'warning') return styles.toneWarning
  return styles.toneInfo
}

export function IncidentClock({
  lanes,
  items,
  selectedID,
  onSelect,
  label,
  windowStart,
  windowEnd,
}: {
  lanes: IncidentClockLane[]
  items: IncidentClockItem[]
  selectedID?: string
  onSelect: (id: string) => void
  /** Accessible name for the timeline list. */
  label: string
  /** Incident window bounds; widen the axis beyond the markers themselves. */
  windowStart?: string
  windowEnd?: string
}) {
  const { format: formatTime } = useTime()

  const scale = useMemo(() => {
    const stamps = items
      .map((item) => Date.parse(item.occurredAt))
      .filter((value) => Number.isFinite(value))
    for (const bound of [windowStart, windowEnd]) {
      const parsed = bound ? Date.parse(bound) : Number.NaN
      if (Number.isFinite(parsed)) stamps.push(parsed)
    }
    if (stamps.length === 0) return null
    let start = Math.min(...stamps)
    let end = Math.max(...stamps)
    const pad = Math.max((end - start) * 0.08, MIN_SPAN_MS)
    start -= pad
    end += pad
    return { start, end, span: end - start }
  }, [items, windowStart, windowEnd])

  if (!scale || items.length === 0) return null

  const position = (occurredAt: string): number => {
    const parsed = Date.parse(occurredAt)
    if (!Number.isFinite(parsed)) return 0
    return ((parsed - scale.start) / scale.span) * 100
  }

  const visibleLanes = lanes.filter((lane) => items.some((item) => item.laneID === lane.id))
  const ticks = [scale.start, scale.start + scale.span / 2, scale.end]

  return (
    <div className={styles.clock}>
      <ol className={styles.lanes} aria-label={label}>
        {visibleLanes.map((lane) => (
          <li key={lane.id} className={styles.lane}>
            <span className={styles.laneLabel}>{lane.label}</span>
            <span className={styles.track}>
              {items
                .filter((item) => item.laneID === lane.id)
                .map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`${styles.marker} ${selectedID === item.id ? styles.selected : ''}`}
                    style={{ insetInlineStart: `${position(item.occurredAt)}%` }}
                    aria-pressed={selectedID === item.id}
                    onClick={() => onSelect(item.id)}
                    title={`${item.title} · ${formatTime(item.occurredAt).text}`}
                  >
                    <span
                      className={`${styles.shape} ${
                        item.kind === 'change' ? styles.shapeChange : styles.shapeSignal
                      } ${toneClass(item)}`}
                      aria-hidden="true"
                    />
                    <span className="sr-only">{item.title}</span>
                    <span className="sr-only">{item.meta}</span>
                    <span className="sr-only">
                      <DateTime value={item.occurredAt} />
                    </span>
                  </button>
                ))}
            </span>
          </li>
        ))}
      </ol>
      <div className={styles.axis} aria-hidden="true">
        <span className={styles.axisSpacer} />
        <span className={styles.axisTicks}>
          {ticks.map((tick) => (
            <span key={tick} className={styles.tick}>
              {formatTime(new Date(tick)).text}
            </span>
          ))}
        </span>
      </div>
    </div>
  )
}
