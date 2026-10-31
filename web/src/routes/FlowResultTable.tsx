// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { Button, Table, type Column } from '../components'
import {
  flowGroupKey,
  flowGroupLabel,
  isFlowComparison,
  type NativeFlowResult,
  type FlowDrillAction,
} from './flowResults'
import type { FlowResultRow } from '../api/flowExplorer'
import styles from './flowExplorer.module.css'

interface DetailRow {
  key: string
  group: Record<string, string>
  other: boolean
  values: Record<string, string>
}

function exactDetails(result: NativeFlowResult): { rows: DetailRow[]; keys: string[] } {
  if (!isFlowComparison(result)) {
    const rows = result.flow?.rows ?? []
    const keys =
      result.flow?.query.metrics?.map((metric) => `${metric.measure}:${metric.calculation}`) ?? []
    return {
      keys,
      rows: rows.map((row) => ({
        key: flowGroupKey(row.group, row.other),
        group: row.group,
        other: row.other,
        values: row.metrics,
      })),
    }
  }
  const grouped = new Map<string, DetailRow>()
  const columnKeys = new Set<string>()
  for (const row of result.rows) {
    // The global Other population has its own summary, outside detail paging.
    if (row.other) continue
    const key = flowGroupKey(row.group)
    let detail = grouped.get(key)
    if (!detail) {
      detail = { key, group: row.group, other: false, values: {} }
      grouped.set(key, detail)
    }
    for (const [name, value] of [
      ['current', row.current_value_str ?? 'Missing'],
      ['previous', row.previous_value_str ?? 'Missing'],
      ['delta', row.delta_str ?? row.delta_state.replace(/_/g, ' ')],
      ['change %', row.percent_change_str ?? row.delta_state.replace(/_/g, ' ')],
    ]) {
      const column = `${row.measure} ${name}`
      columnKeys.add(column)
      detail.values[column] = value
    }
  }
  return { keys: [...columnKeys], rows: [...grouped.values()] }
}

export function FlowResultTable({
  result,
  onDrill,
}: {
  result: NativeFlowResult
  onDrill: FlowDrillAction
}) {
  const [window, setWindow] = useState(0)
  const { rows, keys } = exactDetails(result)
  const size = 100
  const start = Math.min(window * size, Math.max(0, Math.ceil(rows.length / size) - 1) * size)
  const visible = rows.slice(start, start + size)
  const columns: Column<DetailRow>[] = [
    { key: 'group', header: 'Group', render: (row) => flowGroupLabel(row.group, row.other) },
    ...keys.map((key) => ({
      key,
      header: key,
      numeric: true,
      render: (row: DetailRow) => row.values[key] ?? 'Missing',
    })),
    {
      key: 'drill',
      header: 'Explore',
      render: (row) =>
        !row.other && (
          <div className={styles.actions}>
            <Button
              onClick={() => onDrill(row.group)}
              aria-label={`Filter to ${flowGroupLabel(row.group)}`}
            >
              Filter to group
            </Button>
            <Button
              onClick={() => onDrill(row.group, 'exclude')}
              aria-label={`Exclude ${flowGroupLabel(row.group)}`}
            >
              Exclude group
            </Button>
          </div>
        ),
    },
  ]
  return (
    <div className={styles.stack}>
      <Table
        caption="Exact flow details"
        columns={columns}
        rows={visible}
        rowKey={(row) => row.key}
      />
      <div className={styles.actions} aria-label="Within-page detail navigation">
        <Button disabled={start === 0} onClick={() => setWindow(Math.max(0, window - 1))}>
          Previous detail rows
        </Button>
        <span role="status">
          {rows.length ? `${start + 1}–${Math.min(start + size, rows.length)}` : '0'} of{' '}
          {rows.length} groups in this snapshot page
        </span>
        <Button disabled={start + size >= rows.length} onClick={() => setWindow(window + 1)}>
          Next detail rows
        </Button>
      </div>
    </div>
  )
}

export function FlowExactSummary({
  title,
  row,
}: {
  title: string
  row: FlowResultRow | undefined
}) {
  if (!row) return null
  return (
    <div>
      <h3>{title}</h3>
      <dl className={styles.summary}>
        {Object.entries(row.metrics).map(([key, value]) => (
          <div key={key}>
            <dt>{key}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
