// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMemo, type KeyboardEvent } from 'react'
import styles from './PathProfile.module.css'
import { layoutPath, lossTone, NODE_W, summarizePathForGraph, type VizNode } from './layout'
import type { Path } from '../api/paths'
import { useI18n } from '../i18n/useI18n'
import { formatPercentValue, formatUnit } from '../i18n/number'

function fmtMs(ms: number, locale: string) {
  return ms >= 0 ? formatUnit(ms, 'ms', locale, { maximumFractionDigits: ms < 10 ? 1 : 0 }) : '—'
}
function fmtLoss(loss: number, locale: string) {
  return formatPercentValue(loss * 100, locale, { maximumFractionDigits: 0 })
}

const PLOT_H = 180
const TOP = 18
const AXIS_H = 34

/**
 * PathProfile is the latency elevation view of the same merged traceroute the
 * topology graph draws: x = TTL columns (identical layout/ids, so selection is
 * shared), y = per-responder RTT, dots loss-toned, a mean line showing where
 * the latency cliff happens. The topology view stays primary; this answers
 * "where does it get slow" in one glance.
 */
export function PathProfile({
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
  const { nodes, width } = useMemo(
    () => layoutPath(summarized.path, summarized.branchLabels),
    [summarized],
  )

  const measured = useMemo(() => nodes.filter((n) => (n.node?.rtt_avg_ms ?? -1) >= 0), [nodes])
  const maxRtt = useMemo(
    () => Math.max(1, ...measured.map((n) => n.node?.rtt_avg_ms ?? 0)),
    [measured],
  )
  const yFor = (rtt: number) => TOP + (1 - rtt / maxRtt) * PLOT_H
  const cxFor = (n: VizNode) => n.x + NODE_W / 2

  const columns = useMemo(() => {
    const byX = new Map<number, { x: number; label: string; rtts: number[] }>()
    for (const node of nodes) {
      const entry = byX.get(node.x) ?? {
        x: node.x,
        label: node.isSource ? 'Source' : `TTL ${node.ttl}`,
        rtts: [],
      }
      const rtt = node.node?.rtt_avg_ms
      if (rtt !== undefined && rtt >= 0) entry.rtts.push(rtt)
      byX.set(node.x, entry)
    }
    return [...byX.values()].sort((a, b) => a.x - b.x)
  }, [nodes])

  const meanPoints = columns
    .filter((c) => c.rtts.length > 0)
    .map((c) => {
      const mean = c.rtts.reduce((sum, v) => sum + v, 0) / c.rtts.length
      return `${c.x + NODE_W / 2},${yFor(mean)}`
    })
    .join(' ')

  const height = TOP + PLOT_H + AXIS_H

  function activate(node: VizNode, e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect(node)
    }
  }

  return (
    <div className={styles.profile} role="group" aria-label={`Latency by hop to ${path.target}`}>
      <svg viewBox={`0 0 ${width} ${height}`} className={styles.svg}>
        {[0, 0.5, 1].map((fraction) => (
          <g key={fraction}>
            <line
              className={styles.grid}
              x1={0}
              x2={width}
              y1={yFor(maxRtt * fraction)}
              y2={yFor(maxRtt * fraction)}
            />
            <text className={styles.gridLabel} x={4} y={yFor(maxRtt * fraction) - 4}>
              {fmtMs(maxRtt * fraction, locale)}
            </text>
          </g>
        ))}

        {meanPoints.length > 0 ? (
          <polyline className={styles.meanLine} points={meanPoints} />
        ) : null}

        {measured.map((n) => {
          const tone = lossTone(n.lossRatio)
          const cls = [styles.dot, styles[tone], n.id === selectedId ? styles.selected : '']
            .filter(Boolean)
            .join(' ')
          const rtt = n.node?.rtt_avg_ms ?? 0
          const ariaLabel = n.isSource
            ? undefined
            : `Hop ${n.ttl}, ${n.branchLabel}, ${n.ip}, ${fmtMs(rtt, locale)}, ${fmtLoss(
                n.lossRatio,
                locale,
              )} loss`
          return (
            <g
              key={n.id}
              className={cls}
              transform={`translate(${cxFor(n)} ${yFor(rtt)})`}
              tabIndex={n.isSource ? -1 : 0}
              role={n.isSource ? undefined : 'button'}
              aria-pressed={n.isSource ? undefined : n.id === selectedId}
              aria-label={ariaLabel}
              onClick={() => !n.isSource && onSelect(n)}
              onKeyDown={(e) => !n.isSource && activate(n, e)}
            >
              <circle r={6} />
            </g>
          )
        })}

        {columns.map((c) => (
          <text
            key={c.x}
            className={styles.axisLabel}
            x={c.x + NODE_W / 2}
            y={TOP + PLOT_H + 22}
            textAnchor="middle"
          >
            {c.label}
          </text>
        ))}
      </svg>
    </div>
  )
}
