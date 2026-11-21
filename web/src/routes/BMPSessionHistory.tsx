// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../api/client'
import type { BMPSessionHistory as History, BMPSessionPoint } from '../api/sdk.gen'
import { useAuth } from '../auth/useAuth'
import {
  Button,
  Badge,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Table,
} from '../components'
import type { Column } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './planes.module.css'

const labels = {
  statistics: 'Statistics',
  neighbor: 'Peer transition',
  update_churn: 'Observed updates',
  initiation: 'BMP connected',
  termination: 'BMP terminated',
  transport_closed: 'Transport closed',
}
const reasons: Record<number, string> = {
  1: 'Local BGP notification',
  2: 'Local BGP state machine',
  3: 'Remote BGP notification',
  4: 'Remote peer closed',
  5: 'Monitoring withdrawn',
  6: 'Local system closed',
}

function BmpSessionObservation({ point }: { point: BMPSessionPoint }) {
  const { neighbor, update_churn: churn, statistics, lifecycle } = point
  if (neighbor) {
    const reason = neighbor.down_reason
    return (
      <div className={styles.visualStack}>
        <span>
          {neighbor.state === 'up' ? 'Up' : reason === 5 ? 'Monitoring withdrawn' : 'Down'}
        </span>
        {reason !== undefined && (
          <span>
            {reasons[reason]} (reason {reason})
          </span>
        )}
        {neighbor.fsm_event !== undefined && <span>FSM event {neighbor.fsm_event}</span>}
        {neighbor.notification_code !== undefined && (
          <span>
            BGP notification {neighbor.notification_code}/{neighbor.notification_subcode}
          </span>
        )}
      </div>
    )
  }
  if (churn) {
    return (
      <div className={styles.visualStack}>
        <span>{churn.updates} UPDATE frames</span>
        <span>
          <DateTime value={churn.first_observed_at} /> to{' '}
          <DateTime value={churn.last_observed_at} />
        </span>
      </div>
    )
  }
  if (statistics) {
    return statistics.samples.length ? (
      <ul className={styles.asPathSegments}>
        {statistics.samples.map((sample) => (
          <li key={`${sample.type}/${sample.afi ?? 0}/${sample.safi ?? 0}`}>
            <span>
              Type {sample.type}
              {sample.afi !== undefined && ` · AFI ${sample.afi}/SAFI ${sample.safi}`}
              {sample.view && ` · ${sample.view.replace(/_/g, ' ')}`}
            </span>
            <span>
              {sample.value}
              {sample.counter ? ' cumulative' : ''}
            </span>
          </li>
        ))}
      </ul>
    ) : (
      'No recognized statistics'
    )
  }
  if (lifecycle?.terminated) {
    return lifecycle.reason_known
      ? `Termination reason ${lifecycle.reason}`
      : `Unknown termination reason ${lifecycle.reason}`
  }
  return point.kind === 'transport_closed'
    ? 'Peer state is unknown after disconnect'
    : 'Connection-level observation'
}

const columns: Column<BMPSessionPoint>[] = [
  {
    key: 'time',
    header: 'Listener observed',
    render: (point) => <DateTime value={point.observed_at} />,
  },
  {
    key: 'peer',
    header: 'Neighbor',
    render: (point) => {
      const peer = point.neighbor?.peer ?? point.statistics?.peer ?? point.update_churn?.peer
      if (!peer) return 'Router connection'
      return (
        <div className={styles.visualStack}>
          <span>
            {peer.peer_address ?? 'Router RIB'} · AS{peer.peer_asn}
          </span>
          {peer.original_clock && (
            <span>
              Router clock <DateTime value={peer.original_clock} />
            </span>
          )}
        </div>
      )
    },
  },
  {
    key: 'observation',
    header: 'Observation',
    render: (point) => (
      <div className={styles.visualStack}>
        <strong>{labels[point.kind]}</strong>
        <BmpSessionObservation point={point} />
      </div>
    ),
  },
  {
    key: 'continuity',
    header: 'Coverage',
    render: (point) => (
      <div className={styles.visualStack}>
        {point.coverage_gap && <Badge tone="warning">Observation gap</Badge>}
        {point.range_status && <span>{point.range_status.replace(/_/g, ' ')}</span>}
        <details>
          <summary>Original evidence</summary>
          <dl>
            <dt>Connection</dt>
            <dd className="break-all">{point.connection_id}</dd>
            <dt>Sequence</dt>
            <dd>{point.sequence}</dd>
            <dt>Evidence SHA-256</dt>
            <dd className="break-all">{point.evidence_digest}</dd>
          </dl>
        </details>
      </div>
    ),
  },
]

const sourceFields = [
  { name: 'router_id', label: 'Router ID', required: true },
  { name: 'context_id', label: 'Routing context ID', required: true },
  { name: 'collector_agent_id', label: 'Listener agent ID', required: true },
  { name: 'source_ref', label: 'Router source reference', required: true },
] as const
const filterFields = [
  { name: 'peer', label: 'Neighbor IP address' },
  { name: 'from', label: 'Start time (RFC 3339)' },
  { name: 'to', label: 'End time (RFC 3339)' },
] as const
const rangeFields = [
  { name: 'statistic', label: 'BMP gauge type' },
  { name: 'afi', label: 'Address family (AFI)' },
  { name: 'safi', label: 'Subsequent address family (SAFI)' },
  { name: 'expected_min', label: 'Expected minimum' },
  { name: 'expected_max', label: 'Expected maximum' },
] as const

function SessionHistoryControls({ tenant }: { tenant: string }) {
  const [selection, setSelection] = useState<{
    router: string
    scope: string
    filters: string
    submission: number
  } | null>(null)
  const [pages, setPages] = useState([''])
  const cursor = pages.at(-1) ?? ''
  const history = useQuery({
    queryKey: ['bmp-session-history', tenant, selection, cursor],
    enabled: selection !== null,
    queryFn: ({ signal }) => {
      if (!selection) throw new Error('Select a router source')
      const query = new URLSearchParams(selection.scope)
      if (cursor) query.set('cursor', cursor)
      else new URLSearchParams(selection.filters).forEach((value, key) => query.set(key, value))
      return apiFetch<History>(`/bgp/sessions/${encodeURIComponent(selection.router)}?${query}`, {
        signal,
      })
    },
  })
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const input = new FormData(event.currentTarget)
    const value = (key: string) => {
      const field = input.get(key)
      return typeof field === 'string' ? field.trim() : ''
    }
    const scope = new URLSearchParams({
      context_id: value('context_id'),
      collector_agent_id: value('collector_agent_id'),
      source_ref: value('source_ref'),
    })
    const filters = new URLSearchParams()
    for (const field of [...filterFields, ...rangeFields]) {
      const filter = value(field.name)
      if (filter) filters.set(field.name, filter)
    }
    setPages([''])
    const router = value('router_id')
    setSelection((previous) => ({
      router,
      scope: scope.toString(),
      filters: filters.toString(),
      submission: (previous?.submission ?? 0) + 1,
    }))
  }
  return (
    <div className={styles.visualStack}>
      <form className={styles.visualStack} onSubmit={submit}>
        <div className={styles.panelGrid}>
          {[...sourceFields, ...filterFields].map((field) => (
            <Field key={field.name} {...field} />
          ))}
        </div>
        <details>
          <summary>Compare a RIB gauge with an expected range</summary>
          <div className={styles.panelGrid}>
            {rangeFields.map((field) => (
              <Field key={field.name} {...field} inputMode="numeric" pattern="[0-9]+" />
            ))}
          </div>
        </details>
        <Button type="submit">Load session history</Button>
      </form>
      {selection && history.isLoading && <LoadingState label="Loading BMP session history…" />}
      {history.isError && (
        <ErrorState description="Could not read session history for this router and filter." />
      )}
      {pages.length > 1 && (
        <Button variant="secondary" onClick={() => setPages((current) => current.slice(0, -1))}>
          Previous page
        </Button>
      )}
      {history.data && (
        <>
          <Table
            caption="BMP session history"
            columns={columns}
            rows={history.data.items}
            rowKey={(point) => `${point.connection_id}/${point.sequence}`}
            empty="No retained observations in this time window."
          />
          {history.data.next_cursor && (
            <Button
              variant="secondary"
              onClick={() => {
                const next = history.data?.next_cursor
                if (next) setPages((current) => [...current, next])
              }}
            >
              Next page
            </Button>
          )}
        </>
      )}
    </div>
  )
}

export function BMPSessionHistory() {
  const { tenant, permissions } = useAuth()
  const [open, setOpen] = useState(false)
  if (!permissions.includes('events.read') || !permissions.includes('entities.read')) return null
  return (
    <Card>
      <CardHeader title="BMP session history" />
      <CardBody>
        <div className={styles.visualStack}>
          <Button variant="secondary" aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? 'Hide session history' : 'Open session history'}
          </Button>
          {open && <SessionHistoryControls key={tenant.id} tenant={tenant.id} />}
        </div>
      </CardBody>
    </Card>
  )
}
