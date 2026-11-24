// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState, type FormEvent } from 'react'
import {
  topologyWhatIfExportHref,
  useWhatIf,
  type TopoEdge,
  type TopoNode,
  type TopologyTrafficRequest,
} from '../api/topology'
import type { TopologyFailurePortSeries, TopologyFailureTraffic } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, ErrorState, Field, Select } from '../components'
import { CompleteSLATable } from './CompleteSLATable'
import styles from './topology.module.css'

const explanations: Record<string, string> = {
  parallel_link_requires_interface:
    'This graph edge covers parallel links. Select the interface ID for the link you want to fail.',
  canonical_device_unresolved:
    'The selected element has no verified device mapping in this routing context.',
  physical_link_unresolved: 'Physical link evidence is unavailable for the selected element.',
  physical_port_evidence_incomplete: 'Some physical port mappings are unavailable.',
  traffic_or_capacity_coverage_incomplete:
    'Some flow, route, or counter evidence is missing. The table shows where a projection is available.',
  topology_traversal_incomplete: 'The graph simulation exceeded its traversal budget.',
}

function utcInput(timestamp: number) {
  return new Date(timestamp).toISOString().slice(0, 16)
}

function utcTimestamp(input: string): string | undefined {
  const value = new Date(`${input}Z`)
  return input && Number.isFinite(value.getTime()) ? value.toISOString() : undefined
}

export function TopologyTrafficWhatIf({
  contextID,
  node,
  edges,
  nodeLabels,
}: {
  contextID: string
  node: TopoNode | null
  edges: TopoEdge[]
  nodeLabels: ReadonlyMap<string, string>
}) {
  const simulation = useWhatIf()
  const [end] = useState(() => Math.floor(Date.now() / 300_000) * 300_000)
  const [from, setFrom] = useState(() => utcInput(end - 900_000))
  const [to, setTo] = useState(() => utcInput(end))
  const [until, setUntil] = useState('')
  const [gap, setGap] = useState('2m')
  const [choice, setChoice] = useState('')
  const [interfaceID, setInterfaceID] = useState('')
  const [validation, setValidation] = useState('')
  const target = choice || node?.id || ''
  const linked = new Map(
    edges
      .filter(
        (edge) =>
          (edge.from === node?.id || edge.to === node?.id) &&
          (edge.kind === 'physical' ||
            (edge.kind === 'path' && edge.from.startsWith('hop:') && edge.to.startsWith('hop:'))),
      )
      .map((edge) => [
        `${edge.from}|${edge.kind}|${edge.to}`,
        `${nodeLabels.get(edge.from) ?? edge.from} → ${nodeLabels.get(edge.to) ?? edge.to} (${edge.kind})`,
      ]),
  )
  const eligibleNode = node && (node.kind === 'device' || node.kind === 'hop')

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const trafficFrom = utcTimestamp(from)
    const trafficTo = utcTimestamp(to)
    const runoutUntil = utcTimestamp(until)
    if (
      !trafficFrom ||
      !trafficTo ||
      trafficFrom >= trafficTo ||
      (until && (!runoutUntil || runoutUntil <= trafficTo))
    ) {
      setValidation('Enter an increasing observation window and an optional later runout horizon.')
      return
    }
    setValidation('')
    simulation.mutate({
      target,
      context_id: contextID,
      failure_interface_id: choice ? interfaceID.trim() || undefined : undefined,
      traffic_from: trafficFrom,
      traffic_to: trafficTo,
      maximum_poll_gap: gap.trim(),
      runout_until: runoutUntil,
    })
  }

  const traffic = !simulation.isError ? simulation.data?.traffic : undefined
  const variables = simulation.variables
  const exportOptions: TopologyTrafficRequest | undefined =
    variables?.context_id &&
    variables.traffic_from &&
    variables.traffic_to &&
    variables.maximum_poll_gap
      ? {
          context_id: variables.context_id,
          traffic_from: variables.traffic_from,
          traffic_to: variables.traffic_to,
          maximum_poll_gap: variables.maximum_poll_gap,
          failure_interface_id: variables.failure_interface_id,
          runout_until: variables.runout_until,
        }
      : undefined

  return (
    <Card>
      <CardHeader
        title="Traffic what-if"
        description="Estimate how a device or link failure shifts observed traffic."
      />
      <CardBody>
        {!contextID || !eligibleNode ? (
          <p>Select a routing context and a device or hop on the live topology.</p>
        ) : (
          <form aria-label="Traffic simulation inputs" className="grid gap-4" onSubmit={submit}>
            <div className="grid gap-3 md:grid-cols-2">
              <Select
                label="Failed element"
                value={choice}
                options={[
                  { value: '', label: `Device or hop · ${node.label}` },
                  ...Array.from(linked, ([value, label]) => ({ value, label })),
                ]}
                onChange={(event) => {
                  setChoice(event.target.value)
                  setInterfaceID('')
                }}
              />
              {choice ? (
                <Field
                  label="Failed interface ID"
                  hint="Select an exact interface for parallel links."
                  value={interfaceID}
                  onChange={(event) => setInterfaceID(event.target.value)}
                />
              ) : null}
              <Field
                label="Traffic window start (UTC)"
                type="datetime-local"
                value={from}
                required
                onChange={(event) => setFrom(event.target.value)}
              />
              <Field
                label="Traffic window end (UTC)"
                type="datetime-local"
                value={to}
                required
                onChange={(event) => setTo(event.target.value)}
              />
              <Field
                label="Maximum counter poll gap"
                hint="For example, 2m."
                value={gap}
                required
                onChange={(event) => setGap(event.target.value)}
              />
              <Field
                label="Runout horizon (UTC)"
                type="datetime-local"
                value={until}
                onChange={(event) => setUntil(event.target.value)}
              />
            </div>
            {validation ? <p role="alert">{validation}</p> : null}
            <div>
              <Button type="submit" disabled={simulation.isPending}>
                {simulation.isPending ? 'Simulating traffic…' : 'Simulate traffic impact'}
              </Button>
            </div>
          </form>
        )}
        {simulation.isError ? <ErrorState description={simulation.error.message} /> : null}
        {traffic && traffic.context_id === contextID ? (
          <div className="grid gap-3">
            <TrafficResult traffic={traffic} />
            {exportOptions && variables ? (
              <a
                className={styles.exportLink}
                href={topologyWhatIfExportHref(variables.target, undefined, exportOptions)}
                download
              >
                Export audited traffic simulation
              </a>
            ) : null}
          </div>
        ) : null}
      </CardBody>
    </Card>
  )
}

function TrafficResult({ traffic }: { traffic: TopologyFailureTraffic }) {
  const result = traffic.projection
  return (
    <section aria-label="Traffic simulation results" className="grid gap-3" aria-live="polite">
      <p>
        Observation window {traffic.from} to {traffic.to}. Five-minute flow and interface counter
        samples.
      </p>
      {traffic.reason ? (
        <p>
          {explanations[traffic.reason] ??
            'The traffic projection is unavailable for this selection.'}
        </p>
      ) : null}
      {traffic.unattributed_rows ? (
        <p>{traffic.unattributed_rows} flow records lack usable original attribution.</p>
      ) : null}
      {result ? (
        <>
          <dl className={styles.detailList}>
            <dt>Affected</dt>
            <dd>{result.affected_bytes} bytes</dd>
            <dt>Rerouted</dt>
            <dd>{result.rerouted_bytes} bytes</dd>
            <dt>Unrouted</dt>
            <dd>{result.unrouted_bytes} bytes</dd>
            <dt>Unresolved</dt>
            <dd>{result.unresolved_bytes} bytes</dd>
          </dl>
          <CompleteSLATable<TopologyFailurePortSeries>
            caption="Directional link traffic projection"
            rows={result.ports}
            rowKey={(row) => `${row.interface_id}:${row.direction}`}
            columns={[
              {
                key: 'interface',
                header: 'Interface',
                render: (row) => <code>{row.interface_id}</code>,
              },
              { key: 'direction', header: 'Direction', render: (row) => row.direction },
              {
                key: 'measured',
                header: 'Measured',
                numeric: true,
                render: (row) => rate(row.current.measured_bps),
              },
              {
                key: 'projected',
                header: 'Projected',
                numeric: true,
                render: (row) =>
                  row.current.status === 'failed' ? 'Failed' : rate(row.current.projected_bps),
              },
              {
                key: 'utilization',
                header: 'Utilization',
                numeric: true,
                render: (row) => percent(row.current.utilization_ratio),
              },
              {
                key: 'peak',
                header: 'Projected peak',
                numeric: true,
                render: (row) =>
                  row.projected_peak ? (
                    <span title={`${row.projected_peak.from} to ${row.projected_peak.to}`}>
                      {rate(row.projected_peak.bps)}
                    </span>
                  ) : (
                    'Unavailable'
                  ),
              },
              { key: 'runout', header: 'Runout', render: (row) => runout(row) },
            ]}
          />
        </>
      ) : null}
    </section>
  )
}

function rate(value?: string) {
  return value === undefined ? 'Unavailable' : `${value} bit/s`
}

function percent(ratio?: string) {
  if (!ratio) return 'Unavailable'
  const [numerator, denominator = '1'] = ratio.split('/')
  try {
    const scaled = (BigInt(numerator) * 1000n) / BigInt(denominator)
    return `${scaled / 10n}.${scaled % 10n}%`
  } catch {
    return 'Unavailable'
  }
}

function runout(row: TopologyFailurePortSeries) {
  if (row.current.status === 'failed') return 'Failed'
  if (row.at_capacity) return 'At or above capacity'
  if (row.runout?.central.reached) {
    return (
      <span
        title={`Earliest ${row.runout.earliest.from ?? 'unavailable'} · latest ${row.runout.latest.to ?? 'unavailable'}`}
      >
        {row.runout.central.from} to {row.runout.central.to}
      </span>
    )
  }
  if (row.runout?.trained) return 'Below capacity within the horizon'
  return row.runout_status.replace(/_/g, ' ')
}
