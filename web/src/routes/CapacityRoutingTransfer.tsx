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
  RoutingTransferBill,
  RoutingTransferBillingSelection,
  RoutingTransferInput,
  RoutingTransferResponse,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field, Select, Table } from '../components'
import styles from './flowExplorer.module.css'

type Execute = <T>(
  path: string,
  init: RequestInit | undefined,
  accept: (value: T) => void,
) => Promise<void>

type Handoff = {
  agreement?: CapacityAgreement
  egress: string
  bounds: CapacityPhysicalBound[]
}

function emptyHandoff(agreement?: CapacityAgreement): Handoff {
  const target = agreement?.definition.target
  const egress = target?.interface_id ?? ''
  return {
    agreement,
    egress,
    bounds: [{ context_id: target?.context_id ?? '', interface_id: egress, max_bps: '' }],
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
  const [result, setResult] = useState<RoutingTransferResponse>()
  const [expired, setExpired] = useState(false)
  useEffect(() => {
    if (!result) return
    function expire() {
      setResult(undefined)
      setExpired(true)
    }
    const deadline = Date.parse(result.source_valid_until)
    let timer: number | undefined
    function schedule() {
      const remaining = deadline - Date.now()
      if (!Number.isFinite(remaining) || remaining <= 0) {
        expire()
        return
      }
      timer = window.setTimeout(schedule, Math.min(remaining, 2147483647))
    }
    schedule()
    return () => window.clearTimeout(timer)
  }, [result])

  function change<T>(set: (value: T) => void, value: T) {
    set(value)
    setResult(undefined)
    setExpired(false)
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!source.agreement || !candidate.agreement) return
    setResult(undefined)
    setExpired(false)
    const input: RoutingTransferInput = {
      context_id: context,
      destination_prefix: prefix,
      local_preference: Number(preference),
      maximum_poll_gap: gap,
      source: transferSelection(source.agreement, source),
      candidate: transferSelection(candidate.agreement, candidate),
      ...(mode === 'bill' ? { billing_at: at } : { observed_from: from, observed_to: to }),
    }
    void execute<RoutingTransferResponse>(
      '/flows/routing-transfer-estimate',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      },
      setResult,
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
            <div className={styles.actions}>
              <Button type="submit">Estimate transfer</Button>
            </div>
          </fieldset>
        </form>
        {expired && <p role="status">The source validity window elapsed. Run a fresh estimate.</p>}
        {result && <TransferResult result={result} />}
      </CardBody>
    </Card>
  )
}

function transferSelection(
  agreement: CapacityAgreement,
  handoff: Handoff,
): RoutingTransferBillingSelection {
  return {
    agreement_id: agreement.id,
    agreement_version: agreement.current_version,
    egress_interface_id: handoff.egress,
    physical_bounds: handoff.bounds,
  }
}

function agreementKey(agreement: CapacityAgreement) {
  return `${agreement.id}:${agreement.current_version}`
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
  const available = agreements.filter((item) => item.target_present)
  const selected = handoff.agreement
  if (selected && !available.some((item) => agreementKey(item) === agreementKey(selected)))
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
          value={selected ? agreementKey(selected) : ''}
          options={[
            { value: '', label: 'Choose an agreement' },
            ...available.map((item) => ({
              value: agreementKey(item),
              label: `${item.definition.name} · revision ${item.current_version}`,
            })),
          ]}
          onChange={(e) =>
            onChange(emptyHandoff(available.find((item) => agreementKey(item) === e.target.value)))
          }
        />
        {selected && (
          <Field
            label={`${label} egress interface ID`}
            required
            value={handoff.egress}
            readOnly={selected.definition.target.kind === 'interface'}
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
              readOnly={selected.definition.target.kind === 'interface'}
              onChange={(e) => changeBound(index, 'context_id', e.target.value)}
            />
            <Field
              label={`${label} member ${index + 1} interface ID`}
              required
              value={bound.interface_id}
              readOnly={selected.definition.target.kind === 'interface'}
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
                  onChange({ ...handoff, bounds: handoff.bounds.filter((_, i) => i !== index) })
                }
              >
                Remove {label.toLowerCase()} member {index + 1}
              </Button>
            )}
          </div>
        ))}
      {selected?.definition.target.kind === 'circuit' && (
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

function percentile(rate: CapacityPercentileResult) {
  if (!rate.complete || !rate.bps_numerator || !rate.bps_denominator) return 'Unavailable'
  return rate.bps_denominator === '1'
    ? `${rate.bps_numerator} bps`
    : `${rate.bps_numerator}/${rate.bps_denominator} bps`
}

function TransferResult({ result }: { result: RoutingTransferResponse }) {
  const { estimate, policy } = result
  const rows: { name: string; bill: RoutingTransferBill }[] = []
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
          caption="Estimated handoff charges"
          rows={rows}
          rowKey={(row) => row.name}
          columns={[
            { key: 'name', header: 'Handoff', render: (row) => row.name },
            { key: 'before', header: 'Before', render: (row) => charge(row.bill.before) },
            { key: 'after', header: 'After', render: (row) => charge(row.bill.after) },
            {
              key: 'before-p95',
              header: 'Before p95',
              render: (row) => percentile(row.bill.before_p95),
            },
            {
              key: 'after-p95',
              header: 'After p95',
              render: (row) => percentile(row.bill.after_p95),
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
