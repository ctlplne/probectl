// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { apiFetch } from '../api/client'
import type {
  BGPASPathEvent,
  BGPASPathHistory as PathHistory,
  BGPASPathStage,
} from '../api/sdk.gen'
import { Badge, Button, DetailDrawer, ErrorState, LoadingState, Select, Table } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './planes.module.css'

const sourceOptions = [
  { value: '', label: 'All accessible sources' },
  { value: 'router_bmp', label: 'Owned BMP routers' },
  { value: 'public_mrt', label: 'Public collectors' },
]
const timeOptions = [
  { value: '24', label: 'Last 24 hours' },
  { value: '168', label: 'Last 7 days' },
  { value: '720', label: 'Last 30 days' },
  { value: 'all', label: 'All retained observations' },
]

const eventNames = {
  baseline: 'Baseline',
  announcement: 'Announcement',
  withdrawal: 'Withdrawal',
  path_change: 'Path change',
  coverage_gap: 'Coverage gap',
} as const

function vantageLabel(event: BGPASPathEvent) {
  if (event.public_source) {
    const source = event.public_source
    if (source.coverage) return source.collector
    return `${source.collector} · AS${source.peer_asn} · ${source.peer_address}`
  }
  return `${event.router_view?.replace(/_/g, ' ') ?? 'BMP router'} · ${event.router_id ?? event.vantage}`
}

function changeLabels(event: BGPASPathEvent): string[] {
  const changes = event.changes
  if (!changes) return []
  return [
    changes.origin_changed && 'Origin changed',
    changes.origin_evidence_changed && 'Origin evidence changed',
    changes.upstream_changed && 'Upstream changed',
    changes.length_changed && 'Path length changed',
  ].filter((item): item is string => typeof item === 'string')
}

function pathSourceQuery(cursor: string, source: string, vantage: string, hours: string) {
  if (cursor) return new URLSearchParams({ cursor })
  const query = new URLSearchParams({ limit: '100' })
  if (source) query.set('source', source)
  if (vantage) query.set('vantage', vantage)
  const from = hours === 'all' ? new Date(0) : new Date(Date.now() - Number(hours) * 60 * 60 * 1000)
  query.set('from', from.toISOString())
  return query
}

export function BGPASPathHistory({
  tenant,
  monitorID,
  prefix,
}: {
  tenant: string
  monitorID: string
  prefix: string
}) {
  const [source, setSource] = useState('')
  const [hours, setHours] = useState('720')
  const [vantage, setVantage] = useState({ value: '', label: 'All vantages' })
  const [selected, setSelected] = useState<string>()
  const history = useInfiniteQuery({
    queryKey: ['bgp', 'visibility', tenant, monitorID, 'paths', source, vantage.value, hours],
    initialPageParam: '',
    queryFn: ({ pageParam, signal }) =>
      apiFetch<PathHistory>(
        `/bgp/visibility/${encodeURIComponent(monitorID)}/paths?${pathSourceQuery(pageParam, source, vantage.value, hours)}`,
        { signal },
      ),
    getNextPageParam: (page) => page.next_cursor,
  })
  const rows = history.data?.pages.flatMap((page) => page.items) ?? []
  const current = rows.find((row) => row.id === selected)
  const vantages = new Map(rows.map((row) => [row.vantage, vantageLabel(row)]))
  if (vantage.value) vantages.set(vantage.value, vantage.label)
  const pivot = (value: string) => {
    setVantage({ value, label: vantages.get(value) ?? 'All vantages' })
    setSelected(undefined)
  }

  return (
    <section aria-label="AS-path history" className={styles.visualStack}>
      <div className={styles.filters}>
        <Select
          label="Path source"
          value={source}
          options={sourceOptions}
          onChange={(event) => {
            setSource(event.target.value)
            pivot('')
          }}
        />
        <Select
          label="History range"
          value={hours}
          options={timeOptions}
          onChange={(event) => {
            setHours(event.target.value)
            setSelected(undefined)
          }}
        />
        <Select
          label="Vantage"
          value={vantage.value}
          options={[
            { value: '', label: 'All vantages' },
            ...Array.from(vantages, ([value, label]) => ({ value, label })),
          ]}
          onChange={(event) => pivot(event.target.value)}
        />
      </div>
      {history.isLoading && <LoadingState label="Loading AS paths…" />}
      {history.isError && (
        <ErrorState description="Could not load the authorized AS-path history." />
      )}
      {history.data && (
        <Table
          caption={`AS-path timeline for ${prefix}`}
          rows={rows}
          rowKey={(row) => row.id}
          empty="No retained AS paths in this selection."
          columns={[
            {
              key: 'time',
              header: 'Observed',
              render: (row) => <DateTime value={row.original_clock ?? row.observed_at} />,
            },
            { key: 'vantage', header: 'Vantage', render: vantageLabel },
            {
              key: 'change',
              header: 'Change',
              render: (row) => (
                <div>
                  <Button variant="ghost" onClick={() => setSelected(row.id)}>
                    {eventNames[row.kind]}
                  </Button>
                  <span>{changeLabels(row).join(' · ')}</span>
                </div>
              ),
            },
          ]}
        />
      )}
      {history.hasNextPage && (
        <Button
          variant="secondary"
          disabled={history.isFetchingNextPage}
          onClick={() => void history.fetchNextPage()}
        >
          Load earlier AS paths
        </Button>
      )}
      {current && (
        <DetailDrawer
          open
          title={eventNames[current.kind]}
          subtitle={vantageLabel(current)}
          onClose={() => setSelected(undefined)}
        >
          <div className={styles.visualStack}>
            <PathStage title="Previous AS path" stage={current.previous} />
            <PathStage title="Current AS path" stage={current.current} />
            <p>
              Source clock <DateTime value={current.original_clock ?? current.observed_at} />
            </p>
            {current.public_source && (
              <div className={styles.asPathEvidence}>
                {current.public_source.archive_record > 0 && (
                  <p>
                    Archive record {current.public_source.archive_record}, operation{' '}
                    {current.public_source.operation_index}
                  </p>
                )}
                <p>
                  Archive SHA-256 <code>{current.public_source.archive_sha256}</code>
                </p>
              </div>
            )}
            {current.change_event_id && (
              <Link to={changeTimelineHref(current)}>Open recorded routing change</Link>
            )}
            {current.incidents && current.incidents.length > 0 && (
              <ul>
                {current.incidents.map((incident) => (
                  <li key={incident.id}>
                    <Link to={`/incidents?incident=${encodeURIComponent(incident.id)}`}>
                      {incident.relation === 'same_public_archive'
                        ? 'Visibility incident'
                        : 'Nearby router incident'}{' '}
                      {incident.id}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </DetailDrawer>
      )}
    </section>
  )
}

const segmentNames: Record<number, string> = {
  1: 'AS set',
  2: 'AS sequence',
  3: 'Confederation sequence',
  4: 'Confederation set',
}

function PathStage({ title, stage }: { title: string; stage?: BGPASPathStage }) {
  return (
    <section className={styles.visualStack}>
      <h3 className="text-title">{title}</h3>
      {stage ? (
        <>
          {stage.segments.length === 0 ? (
            <p>Empty AS path</p>
          ) : (
            <ol className={styles.asPathSegments} aria-label={title}>
              {stage.segments.map((segment, index) => (
                <li key={index}>
                  <Badge tone="info">{segmentNames[segment.Kind]}</Badge>
                  <span>
                    {segment.Values.map((asn) => `AS${asn}`).join(
                      segment.Kind === 1 || segment.Kind === 4 ? ', ' : ' → ',
                    )}
                  </span>
                </li>
              ))}
            </ol>
          )}
          <p>
            Path length {stage.facts.selection_length}
            {stage.facts.upstream_asn ? ` · Upstream AS${stage.facts.upstream_asn}` : ''}
            {stage.facts.origin_ambiguous ? ' · Origin uncertain' : ''}
          </p>
        </>
      ) : (
        <p>Path evidence unavailable.</p>
      )}
    </section>
  )
}

function changeTimelineHref(event: BGPASPathEvent) {
  const observed = Date.parse(event.observed_at)
  const params = new URLSearchParams({
    view: 'changes',
    change_id: event.change_event_id ?? '',
    changes_from: new Date(observed - 1).toISOString(),
    changes_to: new Date(observed + 1).toISOString(),
  })
  return `/incidents?${params.toString()}`
}
