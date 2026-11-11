// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
import type {
  CapacityAgreement,
  CapacityAgreementBill,
  CapacityBillInput,
  CapacityPhysicalBound,
} from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field } from '../components'
import styles from './flowExplorer.module.css'
import { CapacityMemberAssumptions } from './CapacityMemberAssumptions'

type Execute = <T>(
  path: string,
  init: RequestInit | undefined,
  accept: (value: T) => void,
) => Promise<void>

export function CapacityBillCheck({
  agreement,
  busy,
  execute,
}: {
  agreement: CapacityAgreement
  busy: boolean
  execute: Execute
}) {
  const [at, setAt] = useState('')
  const [gap, setGap] = useState('5m')
  const [invoiced, setInvoiced] = useState('')
  const [bounds, setBounds] = useState<CapacityPhysicalBound[]>([
    {
      context_id: agreement.definition.target.context_id ?? '',
      interface_id: agreement.definition.target.interface_id ?? '',
      max_bps: '',
    },
  ])
  const [result, setResult] = useState<CapacityAgreementBill>()
  const [expired, setExpired] = useState(false)
  useEffect(() => {
    if (!result) return
    const timer = window.setTimeout(
      () => {
        setResult(undefined)
        setExpired(true)
      },
      Math.min(Math.max(0, Date.parse(result.source_valid_until) - Date.now()), 2147483647),
    )
    return () => window.clearTimeout(timer)
  }, [result])
  function changeBound(index: number, key: keyof CapacityPhysicalBound, value: string) {
    setResult(undefined)
    setBounds((old) => old.map((bound, i) => (i === index ? { ...bound, [key]: value } : bound)))
  }
  function check(event: FormEvent) {
    event.preventDefault()
    setResult(undefined)
    setExpired(false)
    const body: CapacityBillInput = {
      version: agreement.version,
      at,
      maximum_poll_gap: gap,
      physical_bounds: bounds,
      ...(invoiced ? { invoiced } : {}),
    }
    void execute<CapacityAgreementBill>(
      `/flows/capacity/agreements/${encodeURIComponent(agreement.id)}/check`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
      setResult,
    )
  }
  return (
    <Card>
      <CardHeader
        title="Measured bill check"
        description="Use the selected recorded revision across one complete billing period. Financial terms do not grant access to counters."
      />
      <CardBody className={styles.stack}>
        <form className={styles.stack} onSubmit={check}>
          <p>
            Revision {agreement.version}; {agreement.definition.direction};{' '}
            {agreement.definition.currency}. The current member set is applied to the whole period;
            historical tag membership is not reconstructed.
          </p>
          <div className={styles.grid}>
            <Field
              label="Instant within billing period"
              required
              disabled={busy}
              hint="RFC3339 with timezone; the complete billing month is selected using the recorded day and timezone."
              value={at}
              onChange={(e) => {
                setAt(e.target.value)
                setResult(undefined)
              }}
            />
            <Field
              label="Maximum counter poll gap"
              required
              disabled={busy}
              hint="For example 5m. Missing intervals remain unknown."
              value={gap}
              onChange={(e) => {
                setGap(e.target.value)
                setResult(undefined)
              }}
            />
            <Field
              label="Invoiced amount to compare"
              disabled={busy}
              inputMode="decimal"
              hint="Optional exact signed decimal in the recorded currency."
              value={invoiced}
              onChange={(e) => {
                setInvoiced(e.target.value)
                setResult(undefined)
              }}
            />
          </div>
          <p>
            Enter a physical upper bound for every current member over the entire period. A
            financial commit or current link speed is not substituted for this assumption.
          </p>
          {bounds.map((bound, index) => (
            <div key={index} className={styles.stack}>
              <div className={styles.grid}>
                <Field
                  label={`Member ${index + 1} routing context ID`}
                  required
                  disabled={busy}
                  value={bound.context_id}
                  onChange={(e) => changeBound(index, 'context_id', e.target.value)}
                />
                <Field
                  label={`Member ${index + 1} canonical interface ID`}
                  required
                  disabled={busy}
                  value={bound.interface_id}
                  onChange={(e) => changeBound(index, 'interface_id', e.target.value)}
                />
                <Field
                  label={`Member ${index + 1} physical upper bound (bps)`}
                  required
                  disabled={busy}
                  inputMode="numeric"
                  value={bound.max_bps}
                  onChange={(e) => changeBound(index, 'max_bps', e.target.value)}
                />
              </div>
              {bounds.length > 1 && (
                <div className={styles.actions}>
                  <Button
                    disabled={busy}
                    onClick={() => {
                      setResult(undefined)
                      setBounds((old) => old.filter((_, i) => i !== index))
                    }}
                  >
                    Remove member {index + 1}
                  </Button>
                </div>
              )}
            </div>
          ))}
          <div className={styles.actions}>
            {agreement.definition.target.kind === 'circuit' && (
              <Button
                disabled={busy}
                onClick={() => {
                  setResult(undefined)
                  setBounds((old) => [...old, { context_id: '', interface_id: '', max_bps: '' }])
                }}
              >
                Add circuit member
              </Button>
            )}
            <Button type="submit" variant="primary" disabled={busy || !agreement.target_present}>
              Check measured bill
            </Button>
          </div>
        </form>
        {expired && <p role="status">Source validity window elapsed. Run a fresh bill check.</p>}
        {result && <CapacityBillResult key={result.as_of} result={result} />}
      </CardBody>
    </Card>
  )
}

function fraction(numerator?: string, denominator?: string) {
  return numerator !== undefined && denominator !== undefined
    ? `${numerator} / ${denominator}`
    : 'Unavailable'
}

function CapacityBillResult({ result }: { result: CapacityAgreementBill }) {
  const values = [
    ['Billing period', `${result.period.from} to ${result.period.to} (end exclusive)`],
    ['Billing timezone', result.period.timezone],
    [
      'Billing day and boundary policy',
      `${result.period.billing_day}; ${result.period.boundary_policy}`,
    ],
    ['Direction', result.percentile.direction],
    ['Counter model', result.percentile.model],
    [
      'Complete coverage',
      result.percentile.complete ? 'Yes' : 'No — no measured percentile or charge',
    ],
    [
      'Expected / observed / missing samples',
      `${result.percentile.expected_samples} / ${result.percentile.observed_samples} / ${result.percentile.missing_samples}`,
    ],
    [
      'Percentile rank',
      result.percentile.rank === undefined ? 'Unavailable' : String(result.percentile.rank),
    ],
    [
      '95th percentile (bps, exact fraction)',
      fraction(result.percentile.bps_numerator, result.percentile.bps_denominator),
    ],
    [
      'Recorded commit (bps, exact fraction)',
      fraction(result.bill.commit_numerator, result.bill.commit_denominator),
    ],
    [
      'Overage (bps, exact fraction)',
      fraction(result.bill.overage_numerator, result.bill.overage_denominator),
    ],
    [
      'Billable units (exact fraction)',
      fraction(result.bill.billable_numerator, result.bill.billable_denominator),
    ],
    [
      `Measured charge (${result.bill.currency}, exact fraction)`,
      fraction(result.bill.charge_numerator, result.bill.charge_denominator),
    ],
    ['Invoice compared', result.bill.invoice_compared ? 'Yes' : 'No'],
    [
      'Invoice difference (invoiced minus measured, exact fraction)',
      fraction(
        result.bill.invoice_difference_numerator,
        result.bill.invoice_difference_denominator,
      ),
    ],
    ['Billing model', result.bill.model],
    ['Incomplete reason', result.bill.reason ?? 'None'],
    ['Maximum poll gap', result.maximum_poll_gap],
    ['Membership basis', 'Current member set applied to the complete period'],
    ['Authority checked at', result.as_of],
    ['Source validity upper bound', result.source_valid_until],
  ]
  return (
    <section aria-label="Measured billing result" className={styles.stack}>
      <dl className={styles.summary}>
        {values.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <CapacityMemberAssumptions members={result.members} />
      <details className={styles.completeResult}>
        <summary>Complete measured result JSON</summary>
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </details>
    </section>
  )
}
