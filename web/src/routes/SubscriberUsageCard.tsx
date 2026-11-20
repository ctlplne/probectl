// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useEntityContexts } from '../api/entities'
import { incidentDDoSReceiptReference, useIncident, useIncidents } from '../api/incidents'
import { useSubscriberUsage } from '../api/subscriberUsage'
import { useTagDefinitions } from '../api/tags'
import type {
  SavedFlowQueryView,
  SubscriberIncidentEvidence,
  SubscriberIncidentSelection,
  SubscriberLatency,
  SubscriberExchangePreview,
  SubscriberExchangeRequest,
  SubscriberUsageReport,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select, Table } from '../components'
import { DateTime } from '../time/DateTime'
import styles from './flowExplorer.module.css'

export function SubscriberUsageCard({
  view,
  tenantID,
  identity,
  canReadLatency,
  canReadIncident,
}: {
  view: Pick<SavedFlowQueryView, 'id' | 'version'>
  tenantID: string
  identity: string
  canReadLatency: boolean
  canReadIncident: boolean
}) {
  const [open, setOpen] = useState(false)
  const [tagID, setTagID] = useState('')
  const [value, setValue] = useState('')
  const [includeLatency, setIncludeLatency] = useState(false)
  const [includeIncident, setIncludeIncident] = useState(false)
  const [incident, setIncident] = useState<SubscriberIncidentSelection>()
  const [exchangeTarget, setExchangeTarget] = useState<SubscriberExchangeRequest['target'] | ''>('')
  const [externalID, setExternalID] = useState('')
  const definitions = useTagDefinitions(open ? tenantID : '')
  const report = useSubscriberUsage(tenantID, view.id)
  const choices = definitions.data?.items ?? []
  const tag = choices.find((item) => item.id === tagID)
  const attachIncident = canReadIncident && includeIncident
  const canRun =
    !!tag &&
    !!value.trim() &&
    !report.isPending &&
    (!attachIncident || !!incident) &&
    (!exchangeTarget || !!externalID.trim())

  function run(event: FormEvent) {
    event.preventDefault()
    if (!tag || !canRun) return
    report.mutate({
      version: view.version,
      tag_id: tag.id,
      tag_key: tag.key,
      subscriber: value.trim(),
      include_latency: canReadLatency && includeLatency,
      incident: attachIncident ? incident : undefined,
      exchange: exchangeTarget
        ? { target: exchangeTarget, external_id: externalID.trim() }
        : undefined,
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
              {canReadIncident && (
                <label>
                  <input
                    type="checkbox"
                    checked={includeIncident}
                    disabled={report.isPending}
                    onChange={(event) => {
                      report.reset()
                      setIncident(undefined)
                      setIncludeIncident(event.target.checked)
                    }}
                  />{' '}
                  Include a DDoS incident
                </label>
              )}
              {attachIncident && (
                <SubscriberIncidentPicker
                  identity={identity}
                  disabled={report.isPending}
                  onChange={(selection) => {
                    report.reset()
                    setIncident(selection)
                  }}
                />
              )}
              <Select
                label="ISP exchange preview"
                value={exchangeTarget}
                options={[
                  { value: '', label: 'Usage report only' },
                  { value: 'splynx', label: 'Splynx' },
                  { value: 'sonar', label: 'Sonar' },
                  { value: 'uisp', label: 'UISP' },
                ]}
                disabled={report.isPending}
                onChange={(event) => {
                  report.reset()
                  setExchangeTarget(event.target.value as SubscriberExchangeRequest['target'] | '')
                  setExternalID('')
                }}
              />
              {exchangeTarget && (
                <Field
                  label="External service or account ID"
                  hint="Use the identifier in your vendor export."
                  value={externalID}
                  maxLength={128}
                  disabled={report.isPending}
                  onChange={(event) => {
                    report.reset()
                    setExternalID(event.target.value)
                  }}
                />
              )}
              <Button type="submit" disabled={!canRun}>
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
      {value.incident && <SubscriberDDoSEvidence value={value.incident} />}
      {value.exchange && <SubscriberExchangeDownload value={value.exchange} />}
    </>
  )
}

function SubscriberExchangeDownload({ value }: { value: SubscriberExchangePreview }) {
  function download() {
    const href = URL.createObjectURL(new Blob([value.csv], { type: 'text/csv;charset=utf-8' }))
    try {
      const link = document.createElement('a')
      link.href = href
      link.download = value.target + '-subscriber-usage-preview.csv'
      link.click()
    } finally {
      URL.revokeObjectURL(href)
    }
  }
  return (
    <>
      <p>Exchange preview. Validate the mapping in your vendor sandbox before billing.</p>
      <Button variant="secondary" onClick={download}>
        Download exchange CSV
      </Button>
    </>
  )
}

function SubscriberIncidentPicker({
  identity,
  disabled,
  onChange,
}: {
  identity: string
  disabled: boolean
  onChange: (selection?: SubscriberIncidentSelection) => void
}) {
  const [contextID, setContextID] = useState('')
  const [incidentID, setIncidentID] = useState('')
  const [fingerprint, setFingerprint] = useState('')
  const contexts = useEntityContexts(identity)
  const incidents = useIncidents(true, identity)
  const incident = useIncident(incidentID || undefined, identity)
  const sources =
    incident.data?.signals?.flatMap((signal) => {
      const receipt = incidentDDoSReceiptReference(signal)
      return receipt ? [{ ...receipt, title: signal.title, time: signal.occurred_at }] : []
    }) ?? []

  function select(context: string, selectedIncident: string, selectedFingerprint: string) {
    const receipt = sources.find((item) => item.fingerprint === selectedFingerprint)
    onChange(
      context && selectedIncident === incident.data?.id && receipt
        ? {
            context_id: context,
            incident_id: selectedIncident,
            rule_id: receipt.rule,
            receipt_fingerprint: receipt.fingerprint,
          }
        : undefined,
    )
  }

  const error = contexts.error ?? incidents.error ?? incident.error
  return (
    <>
      <Select
        label="Incident routing context"
        options={[
          { value: '', label: 'Choose a context' },
          ...(contexts.data?.pages.flatMap((page) =>
            page.items.map((item) => ({
              value: item.context_id,
              label: `${item.site_label} · ${item.vrf_label}`,
            })),
          ) ?? []),
        ]}
        value={contextID}
        disabled={disabled}
        onChange={(event) => {
          setContextID(event.target.value)
          select(event.target.value, incidentID, fingerprint)
        }}
      />
      {contexts.hasNextPage && (
        <Button
          variant="secondary"
          disabled={disabled || contexts.isFetchingNextPage}
          onClick={() => void contexts.fetchNextPage()}
        >
          Load more contexts
        </Button>
      )}
      <Select
        label="Incident"
        options={[
          { value: '', label: 'Choose an incident' },
          ...(incidents.data?.map((item) => ({ value: item.id, label: item.title })) ?? []),
        ]}
        value={incidentID}
        disabled={disabled}
        onChange={(event) => {
          setIncidentID(event.target.value)
          setFingerprint('')
          onChange()
        }}
      />
      {sources.length > 0 && (
        <Select
          label="DDoS observation"
          options={[
            { value: '', label: 'Choose an observation' },
            ...sources.map((item) => ({
              value: item.fingerprint,
              label: `${item.title} · ${item.time}`,
            })),
          ]}
          value={fingerprint}
          disabled={disabled}
          onChange={(event) => {
            setFingerprint(event.target.value)
            select(contextID, incidentID, event.target.value)
          }}
        />
      )}
      {incident.isSuccess && !sources.length && (
        <p>No retained DDoS observation in this incident.</p>
      )}
      {error && <ErrorState title="Incident choices unavailable" description={error.message} />}
    </>
  )
}

function SubscriberDDoSEvidence({ value }: { value: SubscriberIncidentEvidence }) {
  return (
    <>
      <h3>DDoS incident</h3>
      <p>
        <Link to={`/incidents?incident=${encodeURIComponent(value.incident_id)}`}>
          Open incident
        </Link>{' '}
        · {value.prefix} · {value.direction}
      </p>
      <p>
        <DateTime value={value.from} /> to <DateTime value={value.to} />
      </p>
      {value.actions_visible ? (
        value.actions?.length ? (
          <Table
            caption="Recorded incident decisions"
            rows={value.actions}
            rowKey={(row) => row.proposal_id}
            columns={[
              { key: 'kind', header: 'Action', render: (row) => row.kind.replace(/_/g, ' ') },
              { key: 'state', header: 'State', render: (row) => row.state },
              {
                key: 'created',
                header: 'Opened',
                render: (row) => <DateTime value={row.created_at} />,
              },
              {
                key: 'decided',
                header: 'Decided',
                render: (row) => (row.decided_at ? <DateTime value={row.decided_at} /> : '—'),
              },
            ]}
          />
        ) : (
          <p>No recorded decisions in this routing context.</p>
        )
      ) : (
        <p>Recorded decisions require incident audit or review access.</p>
      )}
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
