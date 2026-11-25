// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
import type {
  CapacityAgreement,
  CapacityBillResult,
  CapacityPercentileResult,
  CapacityPhysicalBound,
  RoutingTransferBillingSelection,
  RoutingTransferInput,
  RoutingTransferProbeComparisonInput,
  RoutingTransferResponse,
  RoutingTransferUpstreamPerformance,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field, Select, Table } from '../components'
import { useAuth } from '../auth/useAuth'
import { DateTime } from '../time/DateTime'
import styles from './flowExplorer.module.css'

type Execute = <T>(
  path: string,
  init: RequestInit | undefined,
  accept: (value: T) => void,
) => Promise<void>

type HandoffAgreement = {
  id: string
  version: string
  name: string
  target: CapacityAgreement['definition']['target']
}

type Handoff = {
  agreement?: HandoffAgreement
  egress: string
  bounds: CapacityPhysicalBound[]
}

function emptyHandoff(agreement?: HandoffAgreement): Handoff {
  const target = agreement?.target
  const egress = target?.interface_id ?? ''
  return {
    agreement,
    egress,
    bounds: [
      {
        context_id: target?.context_id ?? '',
        interface_id: egress,
        max_bps: '',
      },
    ],
  }
}

export function CapacityRoutingTransfer({
  agreements,
  busy,
  execute,
}: {
  agreements: CapacityAgreement[]
  busy: boolean
  execute: Execute
}) {
  const { permissions } = useAuth()
  const mayCompareProbes = permissions.includes('test.read') && permissions.includes('agent.read')
  const [source, setSource] = useState(() => emptyHandoff())
  const [candidate, setCandidate] = useState(() => emptyHandoff())
  const [context, setContext] = useState('')
  const [prefix, setPrefix] = useState('')
  const [preference, setPreference] = useState('')
  const [gap, setGap] = useState('5m')
  const [mode, setMode] = useState('bill')
  const [at, setAt] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [compareProbes, setCompareProbes] = useState(false)
  const [probe, setProbe] = useState<RoutingTransferProbeComparisonInput>({
    source: { test_id: '', agent_id: '' },
    candidate: { test_id: '', agent_id: '' },
    from: '',
    to: '',
    mode: 'improve_performance',
    maximum_candidate_loss_ppm: 0,
    maximum_candidate_p95_rtt_nanos: '',
    maximum_added_charge: '0',
  })
  const [completed, setCompleted] = useState<{
    estimate: RoutingTransferInput
    result: RoutingTransferResponse
  }>()
  const result = completed?.result
  const [expired, setExpired] = useState(false)
  const revised = [source.agreement, candidate.agreement].some((selected) => {
    const visible = agreements.find((agreement) => agreement.id === selected?.id)
    return visible && (visible.current_version !== selected?.version || !visible.target_present)
  })
  useEffect(() => {
    if (!result) return
    function expire() {
      setCompleted(undefined)
      setExpired(!revised)
    }
    const remaining = revised ? 0 : Date.parse(result.source_valid_until) - Date.now()
    const timer = window.setTimeout(expire, Math.min(Math.max(0, remaining), 2147483647))
    return () => window.clearTimeout(timer)
  }, [result, revised])

  function change<T>(set: (value: T) => void, value: T) {
    set(value)
    setCompleted(undefined)
    setExpired(false)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    if (
      revised ||
      !source.agreement ||
      !candidate.agreement ||
      source.agreement.id === candidate.agreement.id
    )
      return
    setCompleted(undefined)
    setExpired(false)
    const input: RoutingTransferInput = {
      context_id: context,
      destination_prefix: prefix,
      local_preference: Number(preference),
      maximum_poll_gap: gap,
      source: transferSelection(source.agreement, source),
      candidate: transferSelection(candidate.agreement, candidate),
      ...(mode === 'bill' ? { billing_at: at } : { observed_from: from, observed_to: to }),
      ...(mayCompareProbes && compareProbes ? { probe_comparison: probe } : {}),
    }
    void execute<RoutingTransferResponse>(
      '/flows/routing-transfer-estimate',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      },
      (result) => setCompleted({ estimate: input, result }),
    )
  }

  return (
    <Card data-routing-transfer>
      <CardHeader
        title="Routing transfer estimate"
        description="Compare two recorded handoffs for one destination prefix before changing router policy."
      />
      <CardBody className={styles.stack}>
        <form className={styles.stack} aria-label="Routing transfer estimate" onSubmit={submit}>
          <fieldset className={styles.stack} disabled={busy}>
            <div className={styles.grid}>
              <Field
                label="Routing context ID"
                required
                value={context}
                onChange={(e) => change(setContext, e.target.value)}
              />
              <Field
                label="Exact destination prefix"
                required
                value={prefix}
                onChange={(e) => change(setPrefix, e.target.value)}
              />
              <Field
                label="Proposed local preference"
                required
                type="number"
                min={1}
                max={4294967295}
                step={1}
                value={preference}
                onChange={(e) => change(setPreference, e.target.value)}
              />
              <Field
                label="Maximum counter poll gap"
                required
                value={gap}
                onChange={(e) => change(setGap, e.target.value)}
              />
              <Select
                label="Comparison window"
                options={[
                  { value: 'bill', label: 'Complete common billing period' },
                  { value: 'observed', label: 'Closed observation window' },
                ]}
                value={mode}
                onChange={(e) => change(setMode, e.target.value)}
              />
              {mode === 'bill' ? (
                <Field
                  label="Instant in both billing periods"
                  required
                  hint="RFC3339 with timezone."
                  value={at}
                  onChange={(e) => change(setAt, e.target.value)}
                />
              ) : (
                <>
                  <Field
                    label="Observation start"
                    required
                    hint="Inclusive RFC3339 instant."
                    value={from}
                    onChange={(e) => change(setFrom, e.target.value)}
                  />
                  <Field
                    label="Observation end"
                    required
                    hint="Exclusive RFC3339 instant."
                    value={to}
                    onChange={(e) => change(setTo, e.target.value)}
                  />
                </>
              )}
            </div>
            <HandoffFields
              label="Current handoff"
              handoff={source}
              agreements={agreements}
              onChange={(value) => change(setSource, value)}
            />
            <HandoffFields
              label="Candidate handoff"
              handoff={candidate}
              agreements={agreements}
              onChange={(value) => change(setCandidate, value)}
            />
            {mayCompareProbes && (
              <Select
                label="Upstream performance"
                options={[
                  { value: 'off', label: 'Skip probe comparison' },
                  { value: 'on', label: 'Compare registered upstream probes' },
                ]}
                value={compareProbes ? 'on' : 'off'}
                onChange={(e) => change(setCompareProbes, e.target.value === 'on')}
              />
            )}
            {mayCompareProbes && compareProbes && (
              <ProbeComparisonFields probe={probe} onChange={(value) => change(setProbe, value)} />
            )}
            <div className={styles.actions}>
              <Button
                type="submit"
                disabled={
                  revised ||
                  !source.agreement ||
                  !candidate.agreement ||
                  source.agreement.id === candidate.agreement.id
                }
              >
                Estimate transfer
              </Button>
            </div>
          </fieldset>
        </form>
        {revised && (
          <p role="status">An agreement changed. Choose its current revision before estimating.</p>
        )}
        {expired && <p role="status">The source validity window elapsed. Run a fresh estimate.</p>}
        {result && !revised && <TransferResult result={result} />}
      </CardBody>
    </Card>
  )
}

function ProbeComparisonFields({
  probe,
  onChange,
}: {
  probe: RoutingTransferProbeComparisonInput
  onChange: (probe: RoutingTransferProbeComparisonInput) => void
}) {
  return (
    <fieldset className={styles.grid}>
      <legend>Paired upstream probes</legend>
      {(['source', 'candidate'] as const).map((side) => {
        const label = side === 'source' ? 'Current' : 'Candidate'
        return (
          <div className={styles.stack} key={side}>
            <Field
              label={`${label} probe test ID`}
              required
              value={probe[side].test_id}
              onChange={(e) =>
                onChange({ ...probe, [side]: { ...probe[side], test_id: e.target.value } })
              }
            />
            <Field
              label={`${label} probe agent ID`}
              required
              value={probe[side].agent_id}
              onChange={(e) =>
                onChange({ ...probe, [side]: { ...probe[side], agent_id: e.target.value } })
              }
            />
          </div>
        )
      })}
      <Field
        label="Probe window start"
        required
        hint="Inclusive RFC3339 instant."
        value={probe.from}
        onChange={(e) => onChange({ ...probe, from: e.target.value })}
      />
      <Field
        label="Probe window end"
        required
        hint="Exclusive RFC3339 instant."
        value={probe.to}
        onChange={(e) => onChange({ ...probe, to: e.target.value })}
      />
      <Select
        label="Routing objective"
        options={[
          { value: 'improve_performance', label: 'Improve performance' },
          { value: 'reduce_cost', label: 'Reduce cost' },
        ]}
        value={probe.mode}
        onChange={(e) =>
          onChange({
            ...probe,
            mode: e.target.value === 'reduce_cost' ? 'reduce_cost' : 'improve_performance',
          })
        }
      />
      <Field
        label="Maximum candidate loss"
        required
        type="number"
        min={0}
        max={1000000}
        step={1}
        hint="Parts per million."
        value={probe.maximum_candidate_loss_ppm}
        onChange={(e) => onChange({ ...probe, maximum_candidate_loss_ppm: Number(e.target.value) })}
      />
      <Field
        label="Maximum candidate p95 RTT"
        required
        inputMode="numeric"
        pattern="[1-9][0-9]{0,18}"
        hint="Nanoseconds."
        value={probe.maximum_candidate_p95_rtt_nanos}
        onChange={(e) => onChange({ ...probe, maximum_candidate_p95_rtt_nanos: e.target.value })}
      />
      <Field
        label="Maximum added charge"
        required
        inputMode="decimal"
        hint="In the agreements’ common currency."
        value={probe.maximum_added_charge}
        onChange={(e) => onChange({ ...probe, maximum_added_charge: e.target.value })}
      />
    </fieldset>
  )
}

function transferSelection(
  agreement: HandoffAgreement,
  handoff: Handoff,
): RoutingTransferBillingSelection {
  return {
    agreement_id: agreement.id,
    agreement_version: agreement.version,
    egress_interface_id: handoff.egress,
    physical_bounds: handoff.bounds,
  }
}

function agreementOption(agreement: HandoffAgreement) {
  return `${agreement.id}:${agreement.version}`
}

function HandoffFields({
  label,
  handoff,
  agreements,
  onChange,
}: {
  label: string
  handoff: Handoff
  agreements: CapacityAgreement[]
  onChange: (value: Handoff) => void
}) {
  // Keep only the catalog reference and inventory target when a selection
  // stays visible across pagination. Financial terms stay in the catalog.
  const available: HandoffAgreement[] = agreements
    .filter((item) => item.target_present)
    .map((item) => ({
      id: item.id,
      version: item.current_version,
      name: item.definition.name,
      target: item.definition.target,
    }))
  const selected = handoff.agreement
  const selectedOption = selected ? agreementOption(selected) : ''
  if (selected && !available.some((item) => agreementOption(item) === selectedOption))
    available.unshift(selected)
  function changeBound(index: number, key: keyof CapacityPhysicalBound, value: string) {
    onChange({
      ...handoff,
      bounds: handoff.bounds.map((bound, i) => (i === index ? { ...bound, [key]: value } : bound)),
    })
  }
  return (
    <fieldset className={styles.stack}>
      <legend>{label}</legend>
      <div className={styles.grid}>
        <Select
          label={`${label} agreement`}
          required
          value={selectedOption}
          options={[
            { value: '', label: 'Choose an agreement' },
            ...available.map((item) => ({
              value: agreementOption(item),
              label: `${item.name} · revision ${item.version} · ${item.target.interface_id ?? item.target.tag_value ?? item.id}`,
            })),
          ]}
          onChange={(e) =>
            onChange(
              emptyHandoff(available.find((item) => agreementOption(item) === e.target.value)),
            )
          }
        />
        {selected && (
          <Field
            label={`${label} egress interface ID`}
            required
            value={handoff.egress}
            readOnly={selected.target.kind === 'interface'}
            onChange={(e) => onChange({ ...handoff, egress: e.target.value })}
          />
        )}
      </div>
      {selected &&
        handoff.bounds.map((bound, index) => (
          <div key={index} className={styles.grid}>
            <Field
              label={`${label} member ${index + 1} context ID`}
              required
              value={bound.context_id}
              readOnly={selected.target.kind === 'interface'}
              onChange={(e) => changeBound(index, 'context_id', e.target.value)}
            />
            <Field
              label={`${label} member ${index + 1} interface ID`}
              required
              value={bound.interface_id}
              readOnly={selected.target.kind === 'interface'}
              onChange={(e) => changeBound(index, 'interface_id', e.target.value)}
            />
            <Field
              label={`${label} member ${index + 1} physical bound (bps)`}
              required
              inputMode="numeric"
              pattern="[1-9][0-9]*"
              value={bound.max_bps}
              onChange={(e) => changeBound(index, 'max_bps', e.target.value)}
            />
            {handoff.bounds.length > 1 && (
              <Button
                onClick={() =>
                  onChange({
                    ...handoff,
                    bounds: handoff.bounds.filter((_, i) => i !== index),
                  })
                }
              >
                Remove {label.toLowerCase()} member {index + 1}
              </Button>
            )}
          </div>
        ))}
      {selected?.target.kind === 'circuit' && (
        <div className={styles.actions}>
          <Button
            onClick={() =>
              onChange({
                ...handoff,
                bounds: [...handoff.bounds, { context_id: '', interface_id: '', max_bps: '' }],
              })
            }
          >
            Add {label.toLowerCase()} circuit member
          </Button>
        </div>
      )}
    </fieldset>
  )
}

function charge(bill: CapacityBillResult) {
  if (!bill.complete || !bill.charge_numerator || !bill.charge_denominator) return 'Unavailable'
  const amount =
    bill.charge_denominator === '1'
      ? bill.charge_numerator
      : `${bill.charge_numerator}/${bill.charge_denominator}`
  return `${amount} ${bill.currency}`
}

function percentileRate({ complete, bps_numerator, bps_denominator }: CapacityPercentileResult) {
  if (!complete || !bps_numerator || !bps_denominator) return 'Unavailable'
  const rate = bps_denominator === '1' ? bps_numerator : `${bps_numerator}/${bps_denominator}`
  return `${rate} bps`
}

function TransferResult({ result }: { result: RoutingTransferResponse }) {
  const { estimate, policy } = result
  const rows = []
  if (estimate.source) rows.push({ name: 'Current', bill: estimate.source })
  if (estimate.candidate) rows.push({ name: 'Candidate', bill: estimate.candidate })
  return (
    <section className={styles.stack} aria-label="Routing transfer result">
      <p role="status">
        {estimate.status === 'estimated' ? 'Transfer calculated' : 'Transfer unavailable'} for{' '}
        {result.destination_prefix}.
      </p>
      <p>
        {result.estimate_basis === 'complete_billing_period'
          ? 'Complete billing period'
          : 'Observation window priced at recorded rates'}{' '}
        from {estimate.from} to {estimate.to}.
      </p>
      <p>
        Evidence valid until{' '}
        <time dateTime={result.source_valid_until}>{result.source_valid_until}</time>.
      </p>
      {estimate.reason && <p>{estimate.reason.replace(/_/g, ' ')}.</p>}
      {estimate.moved_peak_bps && (
        <p>
          Peak moved traffic {estimate.moved_peak_bps} bps. Candidate projected peak{' '}
          {estimate.candidate_peak_bps} bps.
        </p>
      )}
      {estimate.candidate_egress_speed_bps && (
        <p>
          Candidate line speed {estimate.candidate_egress_speed_bps} bps. Effective ceiling{' '}
          {estimate.candidate_egress_limit_bps} bps.
        </p>
      )}
      {rows.length > 0 && (
        <Table
          caption="Estimated handoff charges and 95th-percentile traffic"
          rows={rows}
          rowKey={(row) => row.name}
          columns={[
            { key: 'name', header: 'Handoff', render: (row) => row.name },
            {
              key: 'before-p95',
              header: 'Before p95',
              render: (row) => percentileRate(row.bill.before_p95),
            },
            {
              key: 'after-p95',
              header: 'After p95',
              render: (row) => percentileRate(row.bill.after_p95),
            },
            {
              key: 'before',
              header: 'Before charge',
              render: (row) => charge(row.bill.before),
            },
            {
              key: 'after',
              header: 'After charge',
              render: (row) => charge(row.bill.after),
            },
          ]}
        />
      )}
      {estimate.net_charge_change && (
        <p>
          Combined charge change {estimate.net_charge_change} {estimate.currency}.
        </p>
      )}
      {result.performance_status === 'no_paired_upstream_measurement' && (
        <p>Comparative upstream performance is unavailable.</p>
      )}
      {result.upstream_performance && (
        <ProbeComparisonResult comparison={result.upstream_performance} />
      )}
      {policy && (
        <p>
          Policy preview for router {policy.router_id}. Set local preference{' '}
          {policy.local_preference} for {policy.exact_prefix} received from {policy.candidate_peer}{' '}
          (AS{policy.candidate_asn}). Current upstream {policy.current_peer}.
        </p>
      )}
    </section>
  )
}

function ProbeComparisonResult({ comparison }: { comparison: RoutingTransferUpstreamPerformance }) {
  const rows = []
  if (comparison.source) rows.push({ name: 'Current', probe: comparison.source })
  if (comparison.candidate) rows.push({ name: 'Candidate', probe: comparison.candidate })
  return (
    <section className={styles.stack} aria-label="Upstream performance">
      <p role="status">
        {comparison.recommendation === 'move_prefix'
          ? 'Transfer meets the selected limits'
          : 'Keep the current upstream'}
        .
      </p>
      {comparison.recommendation_reason !== 'thresholds_met' && (
        <p>{comparison.recommendation_reason.replace(/_/g, ' ')}.</p>
      )}
      {comparison.reason && <p>{comparison.reason.replace(/_/g, ' ')}.</p>}
      <p>
        {comparison.target}, {comparison.paired_rounds} paired rounds from {comparison.from} to{' '}
        {comparison.to}.
      </p>
      <p>
        Candidate limits {comparison.maximum_candidate_loss_ppm} ppm loss and{' '}
        {comparison.maximum_candidate_p95_rtt_nanos} ns p95 RTT. Maximum added charge{' '}
        {comparison.maximum_added_charge}.
      </p>
      {rows.length > 0 && (
        <Table
          caption="Paired upstream measurements"
          rows={rows}
          rowKey={(row) => row.name}
          columns={[
            { key: 'name', header: 'Handoff', render: (row) => row.name },
            { key: 'sent', header: 'Requests', render: (row) => row.probe.transmitted },
            { key: 'received', header: 'Replies', render: (row) => row.probe.replies },
            { key: 'loss', header: 'Loss ratio', render: (row) => row.probe.loss_ratio },
            {
              key: 'latency',
              header: 'p95 RTT (ns)',
              render: (row) => row.probe.p95_rtt_nanos ?? 'Unavailable',
            },
          ]}
        />
      )}
    </section>
  )
}
