// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Badge, type BadgeTone } from './Badge'

export interface ModuleKpi {
  /** Stable key; also the test hook. */
  id: string
  label: string
  /** The number or short string. Set in mono so columns of digits align. */
  value: ReactNode
  /** One line of context: what the number is measured over. */
  detail?: ReactNode
  tone?: BadgeTone
  /** A short qualifier chip, e.g. "last 24h" or "demo data". */
  qualifier?: string
}

/**
 * The at-a-glance strip at the top of a module. Deliberately austere: four or
 * five numbers, each with the window it was measured over, because a KPI without
 * its denominator is decoration.
 *
 * It is a <dl>: each item is a term and its value, which is what a screen reader
 * needs to read the pair together. The tone colours the value, never the label,
 * and every tone is paired with text so colour is not the only signal.
 */
export function ModuleKpiStrip({
  items,
  caption,
  className,
}: {
  items: ModuleKpi[]
  /** Names the group for assistive tech, e.g. "Fleet summary". */
  caption: string
  className?: string
}) {
  if (items.length === 0) return null
  return (
    <dl aria-label={caption} className={cn('grid gap-3 sm:grid-cols-2 lg:grid-cols-4', className)}>
      {items.map((kpi) => (
        <div
          key={kpi.id}
          data-kpi={kpi.id}
          className="rounded-panel border border-border bg-card px-4 py-3 shadow-elevation1"
        >
          <div className="flex items-start justify-between gap-2">
            <dt className="text-caption font-semibold uppercase tracking-wide text-muted-foreground">
              {kpi.label}
            </dt>
            {kpi.qualifier ? <Badge tone={kpi.tone ?? 'neutral'}>{kpi.qualifier}</Badge> : null}
          </div>
          <dd
            className={cn(
              'mt-1 font-mono text-heading font-semibold tabular-nums',
              kpi.tone === 'success' && 'text-status-success',
              kpi.tone === 'warning' && 'text-status-warning',
              kpi.tone === 'danger' && 'text-destructive',
              kpi.tone === 'info' && 'text-status-info',
              kpi.tone === 'accent' && 'text-brand-accent',
              (!kpi.tone || kpi.tone === 'neutral') && 'text-foreground',
            )}
          >
            {kpi.value}
          </dd>
          {kpi.detail ? (
            <dd className="mt-0.5 text-caption text-muted-foreground">{kpi.detail}</dd>
          ) : null}
        </div>
      ))}
    </dl>
  )
}
