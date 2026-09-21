// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo, useState } from 'react'
import { Badge, Button, Field, Table, type Column } from '../components'
import type { Path } from '../api/paths'
import { useI18n } from '../i18n/useI18n'
import { formatPercentValue, formatUnit } from '../i18n/number'
import { layoutPath, type VizNode } from './layout'
import styles from './PathHopTable.module.css'

function milliseconds(value: number, locale: string) {
  return formatUnit(value, 'ms', locale, { maximumFractionDigits: value < 10 ? 1 : 0 })
}

/** Exact, searchable text companion to the bounded SVG path graph. */
export function PathHopTable({
  path,
  selectedId,
  onSelect,
}: {
  path: Path
  selectedId?: string
  onSelect: (node: VizNode) => void
}) {
  const { locale } = useI18n()
  const [query, setQuery] = useState('')
  const rows = useMemo(() => layoutPath(path).nodes.filter((node) => !node.isSource), [path])
  const needle = query.trim().toLowerCase()
  const filtered = useMemo(
    () =>
      needle
        ? rows.filter((node) =>
            [
              node.ttl,
              node.ip,
              node.branchLabel,
              node.node?.loss_ratio,
              node.node?.rtt_avg_ms,
              ...(node.node?.mpls?.map((label) => label.label) ?? []),
            ]
              .join(' ')
              .toLowerCase()
              .includes(needle),
          )
        : rows,
    [needle, rows],
  )

  const columns: Column<VizNode>[] = [
    {
      key: 'select',
      header: 'Selection',
      render: (node) => (
        <Button
          size="sm"
          variant={node.id === selectedId ? 'primary' : 'ghost'}
          aria-pressed={node.id === selectedId}
          onClick={() => onSelect(node)}
        >
          {node.id === selectedId ? 'Selected' : 'Select'}
        </Button>
      ),
    },
    { key: 'hop', header: 'Hop', numeric: true, render: (node) => node.ttl },
    { key: 'branch', header: 'Branch', render: (node) => node.branchLabel },
    {
      key: 'responder',
      header: 'Responder',
      render: (node) => (
        <span className={styles.responder}>
          <code>{node.ip}</code>
          {node.isDestination ? <Badge tone="accent">destination</Badge> : null}
        </span>
      ),
    },
    {
      key: 'loss',
      header: 'Loss',
      numeric: true,
      render: (node) => {
        const loss = node.node?.loss_ratio ?? 0
        return (
          <Badge tone={loss === 0 ? 'success' : loss < 0.3 ? 'warning' : 'danger'}>
            {formatPercentValue(loss * 100, locale, { maximumFractionDigits: 0 })}
          </Badge>
        )
      },
    },
    {
      key: 'latency',
      header: 'Avg RTT',
      numeric: true,
      render: (node) => milliseconds(node.node?.rtt_avg_ms ?? 0, locale),
    },
    {
      key: 'mpls',
      header: 'MPLS labels',
      render: (node) =>
        node.node?.mpls?.length
          ? node.node.mpls.map((label) => `${label.label}${label.s ? ' (bottom)' : ''}`).join(', ')
          : '—',
    },
  ]

  return (
    <section className={styles.stack} aria-label="Exact searchable hop data">
      <div className={styles.searchRow}>
        <Field
          label="Search all responders"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="IP, hop, branch, loss, or MPLS label"
        />
        <p role="status" className={styles.coverage}>
          {filtered.length} matching {filtered.length === 1 ? 'responder' : 'responders'} of{' '}
          {rows.length} exact path responders
        </p>
      </div>
      <Table
        caption={`Path to ${path.target} by hop`}
        columns={columns}
        rows={filtered}
        rowKey={(node) => node.id}
        empty="No responders match this search."
      />
    </section>
  )
}
