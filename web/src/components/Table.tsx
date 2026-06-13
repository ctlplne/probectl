import type { ReactNode } from 'react'
import styles from './Table.module.css'

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
    <div className={styles.scroll}>
      <table className={styles.table}>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                className={c.align === 'end' || c.numeric ? styles.end : undefined}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td className={styles.emptyCell} colSpan={columns.length}>
                {empty ?? 'No data.'}
              </td>
            </tr>
          ) : (
            <>
              {rendered.map((row) => (
                <tr key={rowKey(row)}>
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={[
                        c.align === 'end' || c.numeric ? styles.end : '',
                        c.numeric ? styles.numeric : '',
                      ]
                        .filter(Boolean)
                        .join(' ')}
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              ))}
              {truncated > 0 && (
                <tr>
                  <td className={styles.emptyCell} colSpan={columns.length}>
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
