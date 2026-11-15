// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { Button, Table } from '../components'
import { MAX_RENDERED_ROWS, type Column } from '../components/Table'
import styles from './flowExplorer.module.css'

export function CompleteSLATable<Row>({
  caption,
  rows,
  columns,
  rowKey,
}: {
  caption: string
  rows: Row[]
  columns: Column<Row>[]
  rowKey: (row: Row) => string
}) {
  const [selection, setSelection] = useState(0)
  const last = Math.max(0, Math.ceil(rows.length / MAX_RENDERED_ROWS) - 1)
  const page = Math.min(selection, last)
  const first = page * MAX_RENDERED_ROWS
  return (
    <div className={styles.stack}>
      <p>
        {caption}: {rows.length} rows; showing {rows.length ? first + 1 : 0}–
        {Math.min(rows.length, first + MAX_RENDERED_ROWS)}.
      </p>
      <Table
        caption={caption}
        rows={rows.slice(first, first + MAX_RENDERED_ROWS)}
        columns={columns}
        rowKey={rowKey}
      />
      <div className={styles.actions}>
        <Button
          disabled={page === 0}
          onClick={() => setSelection(0)}
          aria-label={`${caption}: first page`}
        >
          First page
        </Button>
        <Button
          disabled={page === 0}
          onClick={() => setSelection(page - 1)}
          aria-label={`${caption}: previous page`}
        >
          Previous page
        </Button>
        <Button
          disabled={page === last}
          onClick={() => setSelection(page + 1)}
          aria-label={`${caption}: next page`}
        >
          Next page
        </Button>
        <Button
          disabled={page === last}
          onClick={() => setSelection(last)}
          aria-label={`${caption}: last page`}
        >
          Last page
        </Button>
      </div>
    </div>
  )
}
