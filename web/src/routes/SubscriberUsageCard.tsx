// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useSubscriberUsage } from '../api/subscriberUsage'
import { useTagDefinitions } from '../api/tags'
import type { SavedFlowQueryView, SubscriberLatency, SubscriberUsageReport } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select, Table } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './flowExplorer.module.css'

export function SubscriberUsageCard({
  view,
  tenantID,
  canReadLatency,
}: {
  view: Pick<SavedFlowQueryView, 'id' | 'version'>
  tenantID: string
  canReadLatency: boolean
}) {
  const [open, setOpen] = useState(false)
  const [tagID, setTagID] = useState('')
  const [value, setValue] = useState('')
  const [includeLatency, setIncludeLatency] = useState(false)
  const definitions = useTagDefinitions(open ? tenantID : '')
  const report = useSubscriberUsage(tenantID, view.id)
  const choices = definitions.data?.items ?? []
  const tag = choices.find((item) => item.id === tagID)

  function run(event: FormEvent) {
    event.preventDefault()
    if (!tag || !value.trim() || report.isPending) return
    report.mutate({
      version: view.version,
      tag_id: tag.id,
      tag_key: tag.key,
      subscriber: value.trim(),
      include_latency: canReadLatency && includeLatency,
    })
  }

  return (
    <Card>
      <CardHeader title="Subscriber usage" />
      <CardBody>
        {!open ? (
          <Button variant="secondary" onClick={() => setOpen(true)}>
            Open subscriber usage
          </Button>
        ) : (
          <>
            <form className={styles.actions} onSubmit={run}>
              <Select
                label="Subscriber prefix tag"
                value={tagID}
                options={[
                  { value: '', label: 'Choose a tag' },
                  ...choices.map((item) => ({ value: item.id, label: item.key })),
                ]}
                disabled={report.isPending}
                onChange={(event) => {
                  report.reset()
                  setTagID(event.target.value)
                }}
              />
              <Field
                label="Subscriber tag value"
                value={value}
                maxLength={128}
                disabled={report.isPending}
                onChange={(event) => {
                  report.reset()
                  setValue(event.target.value)
                }}
              />
              {canReadLatency ? (
                <label>
                  <input
                    type="checkbox"
                    checked={includeLatency}
                    disabled={report.isPending}
                    onChange={(event) => {
                      report.reset()
                      setIncludeLatency(event.target.checked)
                    }}
                  />{' '}
                  Include original ICMP latency
                </label>
              ) : null}
              <Button type="submit" disabled={!tag || !value.trim() || report.isPending}>
                Run subscriber report
              </Button>
            </form>
            {definitions.isError ? (
              <ErrorState
                title="Subscriber tags unavailable"
                description={definitions.error.message}
              />
            ) : null}
            {report.isPending ? <p role="status">Measuring subscriber usage…</p> : null}
            {report.isError ? (
              <ErrorState
                title="Subscriber report unavailable"
                description={report.error.message}
              />
            ) : null}
            {report.data ? <SubscriberUsageEvidence value={report.data} /> : null}
          </>
        )}
      </CardBody>
    </Card>
  )
}

function SubscriberUsageEvidence({ value }: { value: SubscriberUsageReport }) {
  const measures = [
    ['Total', value.total],
    ['Download', value.download],
    ['Upload', value.upload],
    ['Within subscriber', value.internal],
  ] as const
  return (
    <>
      <h3>Observed usage for {value.subscriber}</h3>
      <p>
        <DateTime value={value.from} /> to <DateTime value={value.to} />
      </p>
      <dl>
        {measures.map(([label, traffic]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>
              {traffic.bytes} bytes · {traffic.packets} packets
            </dd>
          </div>
        ))}
      </dl>
      <Table
        caption="Remote services"
        rows={value.top_services}
        rowKey={(row) => JSON.stringify([row.direction, row.status, row.provider, row.service])}
        columns={[
          { key: 'direction', header: 'Direction', render: (row) => row.direction },
          {
            key: 'service',
            header: 'Service',
            render: (row) => row.service ?? (row.status === 'ambiguous' ? 'Ambiguous' : 'Unknown'),
          },
          { key: 'provider', header: 'Provider', render: (row) => row.provider ?? '—' },
          { key: 'bytes', header: 'Bytes', render: (row) => row.traffic.bytes },
          { key: 'packets', header: 'Packets', render: (row) => row.traffic.packets },
        ]}
      />
      {value.other_services.bytes !== '0' || value.other_services.packets !== '0' ? (
        <p>
          Other services · {value.other_services.bytes} bytes · {value.other_services.packets}{' '}
          packets
        </p>
      ) : null}
      {value.latency_included && <SubscriberLatencyEvidence rows={value.latency ?? []} />}
    </>
  )
}

const latencyCoverage: Record<SubscriberLatency['coverage'], string> = {
  no_retained_observations: 'No retained observations',
  observed_original_round_trips_only: 'Original round trips',
  partial_original_round_trip_coverage: 'Partial round-trip coverage',
  no_successful_replies: 'No successful replies',
  unavailable_original_round_trips: 'Original round trips unavailable',
}

function SubscriberLatencyEvidence({ rows }: { rows: SubscriberLatency[] }) {
  if (rows.length === 0) return <p>No configured ICMP tests carry this subscriber tag.</p>
  return (
    <Table
      caption="Observed ICMP latency"
      rows={rows}
      rowKey={(row) => JSON.stringify([row.context_id, row.entity_id, row.test_id, row.agent_id])}
      columns={[
        { key: 'test', header: 'Test', render: (row) => row.test },
        { key: 'target', header: 'Target', render: (row) => row.target },
        { key: 'agent', header: 'Measuring agent', render: (row) => row.agent_id },
        { key: 'count', header: 'Replies measured', render: (row) => row.samples ?? '—' },
        { key: 'mean', header: 'Mean RTT (ns)', render: (row) => row.mean_nanos ?? '—' },
        { key: 'min', header: 'Minimum RTT (ns)', render: (row) => row.minimum_nanos ?? '—' },
        { key: 'max', header: 'Maximum RTT (ns)', render: (row) => row.maximum_nanos ?? '—' },
        { key: 'coverage', header: 'Coverage', render: (row) => latencyCoverage[row.coverage] },
      ]}
    />
  )
}
