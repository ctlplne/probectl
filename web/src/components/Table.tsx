// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { ReactNode } from 'react'
import { cn } from '../lib/cn'

export interface Column<Row> {
  key: string
  header: ReactNode
  render: (row: Row) => ReactNode
  align?: 'start' | 'end'
  numeric?: boolean
}

export interface TableProps<Row> {
  caption: string
  columns: Column<Row>[]
  rows: Row[]
  rowKey: (row: Row) => string
  empty?: ReactNode
  /**
   * UX-004: hard cap on the number of <tr> actually rendered into the DOM. The
   * caller pages the data in (cursor pagination), but this is the safety bound
   * so a single over-large response can never blow up the DOM at fleet scale.
   * Defaults to MAX_RENDERED_ROWS.
   */
  maxRows?: number
}

/** The default DOM-row ceiling for any single table render (UX-004). */
export const MAX_RENDERED_ROWS = 200

/** A semantic, accessible data table (the base for the data-dense screens). */
export function Table<Row>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
  maxRows = MAX_RENDERED_ROWS,
}: TableProps<Row>) {
  const rendered = rows.length > maxRows ? rows.slice(0, maxRows) : rows
  const truncated = rows.length - rendered.length
  return (
    <div
      className="max-h-[70vh] overflow-auto rounded-panel border border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
      tabIndex={0}
      aria-label={`${caption} table region`}
    >
      <table className="w-full border-collapse text-data">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                className={cn(
                  'sticky top-0 z-sticky border-b border-border bg-muted px-cell-inline py-cell-block',
                  'text-left text-caption font-semibold uppercase tracking-wide text-muted-foreground',
                  (c.align === 'end' || c.numeric) && 'text-right',
                )}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                className="px-cell-inline py-6 text-center text-data text-muted-foreground"
                colSpan={columns.length}
              >
                {empty ?? 'No data.'}
              </td>
            </tr>
          ) : (
            <>
              {rendered.map((row) => (
                <tr
                  key={rowKey(row)}
                  className="h-row transition-colors duration-fast hover:bg-muted/60"
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={cn(
                        'border-b border-border px-cell-inline py-cell-block align-middle',
                        (c.align === 'end' || c.numeric) && 'text-right',
                        c.numeric && 'font-mono tabular-nums',
                      )}
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              ))}
              {truncated > 0 && (
                <tr>
                  <td
                    className="px-cell-inline py-6 text-center text-data text-muted-foreground"
                    colSpan={columns.length}
                  >
                    Showing {rendered.length} of {rows.length} — load more or refine to see the
                    rest.
                  </td>
                </tr>
              )}
            </>
          )}
        </tbody>
      </table>
    </div>
  )
}
