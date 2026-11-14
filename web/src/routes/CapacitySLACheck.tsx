// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
import type { CapacityAgreement, CarrierSLAStatement } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field, Table } from '../components'
import styles from './flowExplorer.module.css'

type Execute = <T>(
  path: string,
  init: RequestInit | undefined,
  accept: (value: T) => void,
) => Promise<void>

export function CapacitySLACheck({
  agreement,
  busy,
  execute,
}: {
  agreement: CapacityAgreement
  busy: boolean
  execute: Execute
}) {
  const [at, setAt] = useState('')
  const [result, setResult] = useState<CarrierSLAStatement>()
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
  function calculate(event: FormEvent) {
    event.preventDefault()
    setResult(undefined)
    setExpired(false)
    void execute<CarrierSLAStatement>(
      `/flows/capacity/agreements/${encodeURIComponent(agreement.id)}/sla`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version: agreement.version, at }),
      },
      setResult,
    )
  }
  return (
    <Card data-capacity-sla>
      <CardHeader
        title="Monthly carrier SLA"
        description="Preview: compare complete original probe populations with the selected recorded terms. Human review is required."
      />
      <CardBody className={styles.stack}>
        <p>
          Execution and packet ratios describe observed samples. Intervals between samples remain
          unmeasured. Repair is the maximum observed failed completion to the next successful
          completion, not physical repair time. Financial terms do not grant telemetry access.
        </p>
        <form className={styles.stack} onSubmit={calculate}>
          <Field
            label="SLA billing-period instant"
            required
            disabled={busy}
            value={at}
            hint="RFC3339 with timezone. The recorded billing day and timezone select the complete month."
            onChange={(event) => {
              setAt(event.target.value)
              setResult(undefined)
            }}
          />
          <div className={styles.actions}>
            <Button
              type="submit"
              variant="primary"
              disabled={
                busy || !agreement.target_present || !agreement.definition.sla?.sources?.length
              }
            >
              Calculate monthly SLA
            </Button>
          </div>
        </form>
        {expired && <p role="status">Source validity elapsed. Run a fresh SLA calculation.</p>}
        {result && (
          <section aria-label="Monthly SLA result" className={styles.stack}>
            <p>
              Period: {result.period.from} to {result.period.to} (end exclusive),{' '}
              {result.period.timezone}.
            </p>
            <p>
              Complete recorded measurement basis:{' '}
              {result.credit.complete
                ? 'Yes'
                : 'No — unknown coverage or an unfinished period withholds exact credit'}
              .
            </p>
            <p>
              Conditional exact credit: {result.credit.exact_credit ?? 'Unavailable'}{' '}
              {result.credit.currency}. Known lower bound: {result.credit.known_credit_lower_bound}.
              This is a review draft, not a payable amount or submitted claim.
            </p>
            <Table aria-label="Complete SLA clause assessments">
              <thead>
                <tr>
                  <th>Clause</th>
                  <th>State</th>
                  <th>Exact measured value</th>
                  <th>Credit ratio</th>
                  <th>Citations</th>
                </tr>
              </thead>
              <tbody>
                {result.credit.assessments.map((item, index) => (
                  <tr key={`${item.rule_id}/${index}`}>
                    <td>{item.rule_id}</td>
                    <td>{item.state}</td>
                    <td>{item.value ?? 'Unknown'}</td>
                    <td>{item.credit_ratio ?? 'Unavailable'}</td>
                    <td>{item.citations.join('\n')}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Table aria-label="Complete SLA original populations">
              <thead>
                <tr>
                  <th>Agent / test</th>
                  <th>Originals</th>
                  <th>Successful / failed / unknown</th>
                  <th>Lost / transmitted</th>
                  <th>Original RTTs</th>
                  <th>Population digest</th>
                </tr>
              </thead>
              <tbody>
                {result.sources.map((source) => (
                  <tr key={source.id}>
                    <td>
                      {source.agent_id} / {source.test_id}
                    </td>
                    <td>{source.originals}</td>
                    <td>
                      {source.successful} / {source.failed} / {source.unknown}
                    </td>
                    <td>
                      {source.lost} / {source.transmitted}
                    </td>
                    <td>{source.rtt_samples}</td>
                    <td>{source.digest}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <p>
              Authority checked at {result.as_of}; source validity upper bound{' '}
              {result.source_valid_until}. {result.coverage_basis}. {result.repair_basis}.
            </p>
            <details className={styles.completeResult}>
              <summary>Complete SLA result JSON</summary>
              <pre tabIndex={0} aria-label="Complete monthly SLA result">
                {JSON.stringify(result, null, 2)}
              </pre>
            </details>
          </section>
        )}
      </CardBody>
    </Card>
  )
}
