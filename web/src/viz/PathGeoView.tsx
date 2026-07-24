// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMemo, type KeyboardEvent } from 'react'
import styles from './PathGeoView.module.css'
import { landPathD, project, MAP_W, MAP_H } from './geo/geoData'
import { layoutPath, lossTone, summarizePathForGraph, type VizNode } from './layout'
import type { Path } from '../api/paths'
import { useI18n } from '../i18n/useI18n'
import { formatPercentValue, formatUnit } from '../i18n/number'

function fmtMs(ms: number, locale: string) {
  return ms >= 0 ? formatUnit(ms, 'ms', locale, { maximumFractionDigits: ms < 10 ? 1 : 0 }) : '—'
}
function fmtLoss(loss: number, locale: string) {
  return formatPercentValue(loss * 100, locale, { maximumFractionDigits: 0 })
}

/**
 * The geographic read of the same merged path: located responders on a
 * self-contained world outline (vendored Natural Earth — no tiles, no
 * third-party call, air-gap identical), arcs in TTL order, loss tones and
 * selection shared with the topology and profile views. Honesty rules:
 * private/unresolved hops are COUNTED, never invented on the map, and with
 * fewer than two located hops the view says why instead of drawing.
 */
export default function PathGeoView({
  path,
  selectedId,
  onSelect,
}: {
  path: Path
  selectedId?: string
  onSelect: (node: VizNode) => void
}) {
  const { locale } = useI18n()
  const summarized = useMemo(() => summarizePathForGraph(path, selectedId), [path, selectedId])
  const { nodes } = useMemo(
    () => layoutPath(summarized.path, summarized.branchLabels),
    [summarized],
  )
  const land = useMemo(() => landPathD(), [])

  const located = useMemo(
    () =>
      nodes
        .filter((n) => !n.isSource && n.node?.geo)
        .sort((a, b) => a.ttl - b.ttl || a.ip.localeCompare(b.ip)),
    [nodes],
  )
  const unlocated = useMemo(() => nodes.filter((n) => !n.isSource && !n.node?.geo).length, [nodes])

  if (located.length < 2) {
    return (
      <div className={styles.blocked} data-data-state="blocked">
        <p>
          Geographic positions are not available for this path: responders carry no location data.
          Hop geolocation uses an operator-supplied location table (PROBECTL_HOP_GEO_FILE) — nothing
          is ever fetched from a geolocation service. Unmapped and private-range hops stay
          unlocated; the topology view shows every responder.
        </p>
      </div>
    )
  }

  function activate(node: VizNode, e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect(node)
    }
  }

  const arcs = located.slice(1).map((to, i) => {
    const from = located[i]
    const [x1, y1] = project(from.node!.geo!.lon, from.node!.geo!.lat)
    const [x2, y2] = project(to.node!.geo!.lon, to.node!.geo!.lat)
    const mx = (x1 + x2) / 2
    const my = (y1 + y2) / 2 - Math.min(60, Math.hypot(x2 - x1, y2 - y1) * 0.2)
    return { id: `${from.id}->${to.id}`, d: `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}` }
  })

  return (
    <div className={styles.geo} role="group" aria-label={`Geographic path to ${path.target}`}>
      <svg viewBox={`0 0 ${MAP_W} ${MAP_H}`} className={styles.svg}>
        <path className={styles.land} d={land} fillRule="evenodd" />
        {[-60, -30, 0, 30, 60].map((lat) => (
          <line
            key={`lat${lat}`}
            className={styles.graticule}
            x1={0}
            x2={MAP_W}
            y1={project(0, lat)[1]}
            y2={project(0, lat)[1]}
          />
        ))}
        {arcs.map((arc) => (
          <path key={arc.id} className={styles.arc} d={arc.d} />
        ))}
        {located.map((n) => {
          const geo = n.node!.geo!
          const [cx, cy] = project(geo.lon, geo.lat)
          const tone = lossTone(n.lossRatio)
          const cls = [styles.marker, styles[tone], n.id === selectedId ? styles.selected : '']
            .filter(Boolean)
            .join(' ')
          const place = [geo.city, geo.country].filter(Boolean).join(', ')
          const ariaLabel = `Hop ${n.ttl}, ${n.ip}${place ? `, ${place}` : ''}, ${fmtMs(
            n.node?.rtt_avg_ms ?? -1,
            locale,
          )}, ${fmtLoss(n.lossRatio, locale)} loss`
          return (
            <g
              key={n.id}
              className={cls}
              transform={`translate(${cx} ${cy})`}
              tabIndex={0}
              role="button"
              aria-pressed={n.id === selectedId}
              aria-label={ariaLabel}
              onClick={() => onSelect(n)}
              onKeyDown={(e) => activate(n, e)}
            >
              <circle r={6} />
              <text className={styles.markerLabel} x={9} y={4}>
                {place || n.ip}
              </text>
            </g>
          )
        })}
      </svg>
      {unlocated > 0 ? (
        <p className={styles.caption}>
          {unlocated} responder{unlocated === 1 ? '' : 's'} without location (private or unresolved)
          — every responder appears in the topology view.
        </p>
      ) : null}
    </div>
  )
}
