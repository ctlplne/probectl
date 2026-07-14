// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import styles from './LossByHop.module.css'
import { ChartShell } from '../components'
import { lossByHop, lossTone } from './layout'
import { layoutPath, type VizNode } from './layout'
import type { Path } from '../api/paths'
import type { KeyboardEvent } from 'react'

/** LossByHop is the per-hop loss sparkline — a tall, danger-toned bar pinpoints
 *  the hop where drops occur (the Done-when: localize the lossy hop). */
export function LossByHop({
  path,
  selectedId,
  onSelect,
}: {
  path: Path
  selectedId?: string
  onSelect: (node: VizNode) => void
}) {
  const series = lossByHop(path)
  const nodes = new Map(layoutPath(path).nodes.map((node) => [node.id, node]))
  const selectedTTL = nodes.get(selectedId ?? '')?.ttl
  const h = 110
  const barW = 18
  const gap = 10
  const w = Math.max(series.length * (barW + gap) + gap, 120)
  const worst = series.reduce((m, s) => Math.max(m, s.loss), 0)

  function select(id: string) {
    const node = nodes.get(id)
    if (node) onSelect(node)
  }

  function selectByKeyboard(id: string, event: KeyboardEvent<SVGGElement>) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      select(id)
    }
  }

  return (
    <ChartShell
      title="Loss by hop"
      height={150}
      legend={
        worst > 0 ? (
          <span>Worst hop: {Math.round(worst * 100)}% loss</span>
        ) : (
          <span>No loss observed</span>
        )
      }
    >
      <svg
        className={styles.svg}
        viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="xMinYMid meet"
        role="group"
        aria-label="Packet loss by hop"
      >
        {series.map((s, i) => {
          const x = gap + i * (barW + gap)
          const bh = Math.max(2, s.loss * (h - 22))
          return (
            <g
              key={s.ttl}
              role="button"
              tabIndex={0}
              aria-pressed={selectedTTL === s.ttl}
              aria-label={`Hop ${s.ttl}, ${s.branchLabel}, ${s.ip}, ${Math.round(s.loss * 100)}% loss`}
              className={selectedTTL === s.ttl ? styles.selected : undefined}
              onClick={() => select(s.id)}
              onKeyDown={(event) => selectByKeyboard(s.id, event)}
            >
              <rect
                className={[styles.bar, styles[lossTone(s.loss)]].join(' ')}
                x={x}
                y={h - 18 - bh}
                width={barW}
                height={bh}
                rx={2}
              >
                <title>{`Hop ${s.ttl} (${s.ip}): ${Math.round(s.loss * 100)}% loss`}</title>
              </rect>
              <text className={styles.value} x={x + barW / 2} y={h - 22 - bh} textAnchor="middle">
                {Math.round(s.loss * 100)}%
              </text>
              <text className={styles.label} x={x + barW / 2} y={h - 4} textAnchor="middle">
                {s.ttl}
              </text>
            </g>
          )
        })}
      </svg>
    </ChartShell>
  )
}
