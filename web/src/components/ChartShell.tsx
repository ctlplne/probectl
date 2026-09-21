// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import styles from './ChartShell.module.css'

export function ChartShell({
  title,
  toolbar,
  legend,
  height = 180,
  children,
}: {
  title: ReactNode
  toolbar?: ReactNode
  legend?: ReactNode
  height?: number
  children: ReactNode
}) {
  return (
    <figure className={styles.shell}>
      <figcaption className={styles.head}>
        <span className={styles.title}>{title}</span>
        {toolbar ? <div className={styles.toolbar}>{toolbar}</div> : null}
      </figcaption>
      <div className={styles.plot} style={{ height }}>
        {children}
      </div>
      {legend ? <div className={styles.legend}>{legend}</div> : null}
    </figure>
  )
}

/**
 * Sparkline is a minimal, dependency-free, token-driven line+area chart — enough
 * to validate the chart-shell frame. The flagship visualizations (S11/S43) build
 * on this shell with a real charting layer.
 */
export function Sparkline({ data, label }: { data: number[]; label: string }) {
  const w = 600
  const h = 160

  // Honesty: one sample is a point, not a trend. The old code drew a filled
  // wedge across the full plot from a single value — misleading by geometry.
  if (data.length === 1) {
    return (
      <svg
        className={styles.spark}
        viewBox={`0 0 ${w} ${h}`}
        role="img"
        aria-label={`${label} (single sample)`}
      >
        <circle className={styles.dot} cx={w / 2} cy={h / 2} r={6} />
      </svg>
    )
  }

  const max = Math.max(...data, 1)
  const min = Math.min(...data, 0)
  const span = max - min || 1
  const step = data.length > 1 ? w / (data.length - 1) : w
  const points = data.map((v, i) => [i * step, h - ((v - min) / span) * h] as const)
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  const area = `0,${h} ${line} ${w},${h}`

  return (
    <svg
      className={styles.spark}
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      <polygon className={styles.area} points={area} />
      <polyline className={styles.line} points={line} />
    </svg>
  )
}
