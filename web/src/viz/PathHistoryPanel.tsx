// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { Badge, Field, Select, Table, type Column } from '../components'
import type { HopNode, PathSnapshot } from '../api/paths'
import { DateTime } from '../time/DateTime'
import { layoutPath } from './layout'
import styles from './PathHistoryPanel.module.css'

type DiffState = 'common' | 'changed' | 'unique to selected' | 'unique to comparison'

interface DiffRow {
  key: string
  ttl: number
  ip: string
  branch: string
  state: DiffState
  selected?: HopNode
  comparison?: HopNode
}

function nodeValue(node: HopNode | undefined) {
  if (!node) return '—'
  const labels = node.mpls?.map((label) => label.label).join('/')
  return `${Math.round(node.loss_ratio * 100)}% loss · ${node.rtt_avg_ms} ms${labels ? ` · MPLS ${labels}` : ''}`
}

function sameMeasurement(left: HopNode, right: HopNode) {
  return (
    left.sent === right.sent &&
    left.received === right.received &&
    left.loss_ratio === right.loss_ratio &&
    left.rtt_min_ms === right.rtt_min_ms &&
    left.rtt_avg_ms === right.rtt_avg_ms &&
    left.rtt_max_ms === right.rtt_max_ms &&
    JSON.stringify(left.mpls ?? []) === JSON.stringify(right.mpls ?? [])
  )
}

function comparePathRounds(selected: PathSnapshot, comparison: PathSnapshot): DiffRow[] {
  const selectedNodes = layoutPath(selected.path).nodes.filter((node) => !node.isSource)
  const comparisonNodes = layoutPath(comparison.path).nodes.filter((node) => !node.isSource)
  const left = new Map(selectedNodes.map((node) => [node.id, node]))
  const right = new Map(comparisonNodes.map((node) => [node.id, node]))
  const keys = Array.from(new Set([...left.keys(), ...right.keys()])).sort((a, b) => {
    const aNode = left.get(a) ?? right.get(a)!
    const bNode = left.get(b) ?? right.get(b)!
    return aNode.ttl - bNode.ttl || aNode.ip.localeCompare(bNode.ip)
  })
  return keys.map((key) => {
    const selectedNode = left.get(key)
    const comparisonNode = right.get(key)
    let state: DiffState
    if (!comparisonNode) state = 'unique to selected'
    else if (!selectedNode) state = 'unique to comparison'
    else state = sameMeasurement(selectedNode.node!, comparisonNode.node!) ? 'common' : 'changed'
    return {
      key,
      ttl: (selectedNode ?? comparisonNode)!.ttl,
      ip: (selectedNode ?? comparisonNode)!.ip,
      branch: selectedNode?.branchLabel ?? comparisonNode?.branchLabel ?? 'Primary',
      state,
      selected: selectedNode?.node,
      comparison: comparisonNode?.node,
    }
  })
}

function tone(state: DiffState): 'neutral' | 'warning' | 'accent' | 'info' {
  if (state === 'changed') return 'warning'
  if (state === 'unique to selected') return 'accent'
  if (state === 'unique to comparison') return 'info'
  return 'neutral'
}

export function PathHistoryPanel({
  rounds,
  selected,
  comparison,
  onSelect,
  onCompare,
}: {
  rounds: PathSnapshot[]
  selected?: PathSnapshot
  comparison?: PathSnapshot
  onSelect: (round: PathSnapshot) => void
  onCompare: (id?: string) => void
}) {
  const selectedIndex = Math.max(
    0,
    selected ? rounds.findIndex((round) => round.id === selected.id) : 0,
  )
  const diff = selected && comparison ? comparePathRounds(selected, comparison) : []
  const columns: Column<DiffRow>[] = [
    {
      key: 'state',
      header: 'State',
      render: (row) => <Badge tone={tone(row.state)}>{row.state}</Badge>,
    },
    {
      key: 'hop',
      header: 'Hop / responder',
      render: (row) => (
        <span>
          Hop {row.ttl} · {row.branch} · <code>{row.ip}</code>
        </span>
      ),
    },
    {
      key: 'selected',
      header: 'Selected round',
      render: (row) => nodeValue(row.selected),
    },
    {
      key: 'comparison',
      header: 'Comparison round',
      render: (row) => nodeValue(row.comparison),
    },
  ]

  return (
    <section className={styles.stack} aria-label="Path history and comparison">
      <div className={styles.controls}>
        <Field
          label="Path history round"
          type="range"
          min={0}
          max={Math.max(0, rounds.length - 1)}
          step={1}
          value={selectedIndex}
          disabled={rounds.length < 2}
          onChange={(event) => {
            const round = rounds[Number(event.target.value)]
            if (round) onSelect(round)
          }}
          hint={selected ? `Selected ${selectedIndex + 1} of ${rounds.length}` : 'No stored rounds'}
        />
        <Select
          label="Compare with"
          value={comparison?.id ?? ''}
          onChange={(event) => onCompare(event.target.value || undefined)}
          options={[
            { value: '', label: 'No comparison' },
            ...rounds
              .filter((round) => round.id !== selected?.id)
              .map((round, index) => ({
                value: round.id,
                label: `Round ${index + 1} · ${new Date(round.observed_at).toISOString()}`,
              })),
          ]}
        />
        <dl className={styles.rounds}>
          <div>
            <dt>Selected</dt>
            <dd>{selected ? <DateTime value={selected.observed_at} /> : '—'}</dd>
          </div>
          <div>
            <dt>Comparison</dt>
            <dd>{comparison ? <DateTime value={comparison.observed_at} /> : '—'}</dd>
          </div>
        </dl>
      </div>

      {selected && comparison ? (
        <div className={styles.comparison}>
          <div className={styles.summary} role="status" aria-label="Path comparison summary">
            {(
              ['common', 'changed', 'unique to selected', 'unique to comparison'] as DiffState[]
            ).map((state) => (
              <Badge key={state} tone={tone(state)}>
                {diff.filter((row) => row.state === state).length} {state}
              </Badge>
            ))}
          </div>
          <Table
            caption="Side-by-side selected path round comparison"
            columns={columns}
            rows={diff}
            rowKey={(row) => row.key}
            empty="The selected rounds contain no responders."
          />
        </div>
      ) : (
        <p className={styles.empty}>
          Choose a comparison round to distinguish common, changed, and unique hops.
        </p>
      )}
    </section>
  )
}
