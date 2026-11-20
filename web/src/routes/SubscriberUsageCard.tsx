// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { useSubscriberUsage } from '../api/subscriberUsage'
import { useTagDefinitions } from '../api/tags'
import type { SavedFlowQueryView, SubscriberUsageReport } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select, Table } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './flowExplorer.module.css'

export function SubscriberUsageCard({
  view,
  tenantID,
}: {
  view: Pick<SavedFlowQueryView, 'id' | 'version'>
  tenantID: string
}) {
  const [open, setOpen] = useState(false)
  const [tagID, setTagID] = useState('')
  const [value, setValue] = useState('')
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
    </>
  )
}
