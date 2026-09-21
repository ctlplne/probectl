// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Table, type Column, type TableProps } from './Table'

/**
 * DataGridToolbar is the chrome above a list: filters on the left, view and
 * density controls on the right, and a row count that states what is being
 * shown out of what exists. The count is not decoration — a list that silently
 * shows the first page looks identical to a list that is complete.
 *
 * It wraps at narrow widths instead of scrolling horizontally, because a filter
 * an operator cannot see is a filter they will not use.
 */
export function DataGridToolbar({
  filters,
  actions,
  total,
  shown,
  className,
}: {
  filters?: ReactNode
  actions?: ReactNode
  /** How many rows exist server-side, when the server reports it. */
  total?: number
  /** How many are on screen right now. */
  shown?: number
  className?: string
}) {
  const showsCount = typeof shown === 'number'
  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-3 border-b border-border px-panel-padding py-3',
        className,
      )}
      data-grid-toolbar
    >
      <div className="flex min-w-0 flex-wrap items-center gap-2">{filters}</div>
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        {showsCount ? (
          <p className="text-caption text-muted-foreground" data-grid-count>
            {typeof total === 'number' && total !== shown
              ? `Showing ${shown} of ${total}`
              : `${shown} ${shown === 1 ? 'row' : 'rows'}`}
          </p>
        ) : null}
        {actions}
      </div>
    </div>
  )
}

export interface DataGridProps<Row> extends TableProps<Row> {
  /** Filter controls rendered into the toolbar. */
  filters?: ReactNode
  /** Saved views, exports, density — the right-hand toolbar slot. */
  actions?: ReactNode
  /** Server-side total, when known, so the count can be honest about paging. */
  total?: number
  /** Rendered above the toolbar: a KPI strip, a warning, a coverage caveat. */
  banner?: ReactNode
  className?: string
}

/**
 * DataGrid is the standard list surface: one panel containing a toolbar and a
 * table, so every list screen in the product has the same shape and the same
 * keyboard path. It composes Table rather than reimplementing it, which keeps
 * the semantic markup, the sticky header and the UX-004 DOM-row ceiling.
 */
export function DataGrid<Row>({
  filters,
  actions,
  total,
  banner,
  className,
  ...table
}: DataGridProps<Row>) {
  return (
    <section
      className={cn('overflow-hidden rounded-panel border border-border bg-card', className)}
      data-grid
      aria-label={table.caption}
    >
      {banner ? <div className="border-b border-border px-panel-padding py-3">{banner}</div> : null}
      <DataGridToolbar
        filters={filters}
        actions={actions}
        total={total}
        shown={table.rows.length}
      />
      <Table {...table} />
    </section>
  )
}

export type { Column }
