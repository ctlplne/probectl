// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
import type { CapacityAgreement, CarrierSLAStatement } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field } from '../components'
import styles from './flowExplorer.module.css'
import { CompleteSLATable } from './CompleteSLATable'

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
            <CompleteSLATable
              caption="Complete SLA clause assessments"
              rows={result.credit.assessments}
              rowKey={(item) => item.rule_id}
              columns={[
                { key: 'clause', header: 'Clause', render: (item) => item.rule_id },
                { key: 'state', header: 'State', render: (item) => item.state },
                {
                  key: 'value',
                  header: 'Exact measured value',
                  render: (item) => item.value ?? 'Unknown',
                },
                {
                  key: 'credit',
                  header: 'Credit ratio',
                  render: (item) => item.credit_ratio ?? 'Unavailable',
                },
                {
                  key: 'citations',
                  header: 'Citations',
                  render: (item) => item.citations.join('\n'),
                },
              ]}
            />
            <CompleteSLATable
              caption="Complete SLA original populations"
              rows={result.sources}
              rowKey={(source) => source.id}
              columns={[
                {
                  key: 'source',
                  header: 'Agent / test',
                  render: (source) => `${source.agent_id} / ${source.test_id}`,
                },
                { key: 'originals', header: 'Originals', render: (source) => source.originals },
                {
                  key: 'outcomes',
                  header: 'Successful / failed / unknown',
                  render: (source) => `${source.successful} / ${source.failed} / ${source.unknown}`,
                },
                {
                  key: 'packets',
                  header: 'Lost / transmitted',
                  render: (source) => `${source.lost} / ${source.transmitted}`,
                },
                { key: 'rtt', header: 'Original RTTs', render: (source) => source.rtt_samples },
                { key: 'digest', header: 'Population digest', render: (source) => source.digest },
              ]}
            />
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
