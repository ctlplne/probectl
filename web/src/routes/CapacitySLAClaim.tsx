// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState, type FormEvent } from 'react'
import { useAuth } from '../auth/useAuth'
import { appPath } from '../lib/links'
import type { DashboardView } from '../api/dashboardReporting'
import type { CapacityAgreement, CarrierSLAClaimDraft, CarrierSLASelection } from '../api/sdk.gen'
import { Button, Card, CardBody, CardHeader, Field } from '../components'
import styles from './flowExplorer.module.css'
import { CompleteSLATable } from './CompleteSLATable'

type Execute = <T>(
  path: string,
  init: RequestInit | undefined,
  accept: (value: T) => void,
) => Promise<void>

export function CapacitySLAClaim({
  selected,
  busy,
  execute,
}: {
  selected?: CapacityAgreement
  busy: boolean
  execute: Execute
}) {
  const { permissions } = useAuth()
  const canSaveReport =
    permissions.includes('metrics.write') && permissions.includes('metrics.read')
  const [savedReport, setSavedReport] = useState<DashboardView>()
  const [reportName, setReportName] = useState('Carrier SLA claim')
  const [selections, setSelections] = useState<CarrierSLASelection[]>([])
  const [result, setResult] = useState<CarrierSLAClaimDraft>()
  const [expired, setExpired] = useState(false)
  useEffect(() => {
    if (!result) return
    const timer = window.setTimeout(
      () => {
        setResult(undefined)
        setSavedReport(undefined)
        setExpired(true)
      },
      Math.min(Math.max(0, Date.parse(result.source_valid_until) - Date.now()), 2147483647),
    )
    return () => window.clearTimeout(timer)
  }, [result])
  function prepare(event: FormEvent) {
    event.preventDefault()
    setResult(undefined)
    setSavedReport(undefined)
    setExpired(false)
    void execute<CarrierSLAClaimDraft>(
      '/flows/capacity/sla-claims',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selections }),
      },
      setResult,
    )
  }
  return (
    <Card>
      <CardHeader
        title="Carrier claim draft"
        description="Preview: group explicitly selected monthly circuit assessments by carrier, currency and billing calendar. Unsigned review draft; no claim is submitted."
      />
      <CardBody className={styles.stack}>
        <p>
          Open an agreement and add its exact recorded revision. Selections remain in this financial
          workspace as you page through agreements. Each period follows its own recorded billing
          calendar; duplicate resolved revisions and periods are refused.
        </p>
        <div className={styles.actions}>
          <Button
            disabled={
              busy || !selected?.target_present || !selected?.definition.sla?.sources?.length
            }
            onClick={() => {
              if (!selected) return
              setResult(undefined)
              setSavedReport(undefined)
              setSelections((old) => [
                ...old,
                { agreement_id: selected.id, version: selected.version, at: '' },
              ])
            }}
          >
            Add selected agreement to claim
          </Button>
        </div>
        <form className={styles.stack} onSubmit={prepare}>
          {selections.map((selection, index) => (
            <div key={index} className={styles.stack}>
              <p>
                Agreement {selection.agreement_id}, revision {selection.version}.
              </p>
              <Field
                label={`Claim selection ${index + 1} billing-period instant`}
                required
                disabled={busy}
                value={selection.at}
                hint="RFC3339 with timezone. Select the complete recorded billing period."
                onChange={(event) => {
                  setResult(undefined)
                  setSavedReport(undefined)
                  setSelections((old) =>
                    old.map((value, i) =>
                      i === index ? { ...value, at: event.target.value } : value,
                    ),
                  )
                }}
              />
              <div className={styles.actions}>
                <Button
                  disabled={busy}
                  onClick={() => {
                    setResult(undefined)
                    setSavedReport(undefined)
                    setSelections((old) => old.filter((_, i) => i !== index))
                  }}
                >
                  Remove claim selection {index + 1}
                </Button>
              </div>
            </div>
          ))}
          <div className={styles.actions}>
            <Button type="submit" variant="primary" disabled={busy || selections.length === 0}>
              Prepare grouped claim draft
            </Button>
          </div>
        </form>
        {canSaveReport && (
          <section aria-label="Signed carrier claim report" className={styles.stack}>
            <Field
              label="Carrier claim report name"
              value={reportName}
              disabled={busy}
              onChange={(event) => setReportName(event.target.value)}
            />
            <p>
              Save these recorded circuit revisions for a signed PDF or CSV in the report inbox. A
              blank period selects the previous complete billing period at generation time, so
              monthly schedules advance using the recorded calendar. Review remains required; no
              claim is submitted.
            </p>
            <Button
              disabled={busy || selections.length === 0 || !reportName.trim()}
              onClick={() => {
                setSavedReport(undefined)
                void execute<DashboardView>(
                  '/dashboards',
                  {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                      name: reportName,
                      preset: 'operator',
                      shared: false,
                      definition: {
                        carrier_claim: {
                          selections: selections.map(({ agreement_id, version, at }) => ({
                            agreement_id,
                            version,
                            ...(at ? { at } : {}),
                          })),
                        },
                        provenance: [
                          'Recorded carrier SLA terms and complete original receipt populations',
                        ],
                        redaction_state: 'Tenant export policy',
                        coverage_limitations: [
                          'Observed probe populations; human review and carrier adjudication required.',
                        ],
                      },
                    }),
                  },
                  setSavedReport,
                )
              }}
            >
              Save signed claim report
            </Button>
            {savedReport && (
              <p role="status">
                Report saved.{' '}
                <a
                  href={`${appPath('/dashboards')}?view=${encodeURIComponent(savedReport.id)}#saved-dashboard`}
                >
                  Generate or schedule the signed claim
                </a>
                .
              </p>
            )}
          </section>
        )}
        {expired && <p role="status">Claim source validity elapsed. Prepare a fresh draft.</p>}
        {result && (
          <section aria-label="Grouped carrier claim draft" className={styles.stack}>
            <p>
              Human review required. This unsigned draft has not been submitted. Unknown circuits
              withhold their group's exact total.
            </p>
            {result.groups.map((group, index) => (
              <section
                key={index}
                aria-label={`Carrier claim group ${index + 1}`}
                className={styles.stack}
              >
                <h3>
                  {group.carrier} — {group.currency}
                </h3>
                <p>
                  {group.period.from} to {group.period.to} (end exclusive); {group.period.timezone},
                  billing day {group.period.billing_day}.
                </p>
                <p>
                  Conditional exact credit: {group.exact_credit ?? 'Unavailable'}. Known lower
                  bound: {group.known_credit_lower_bound} {group.currency}.
                </p>
                <CompleteSLATable
                  caption={`Complete claim group ${index + 1} circuits`}
                  rows={group.circuits}
                  rowKey={(circuit) => `${circuit.agreement.id}/${circuit.agreement.version}`}
                  columns={[
                    {
                      key: 'circuit',
                      header: 'Circuit',
                      render: (circuit) => circuit.agreement.definition.sla?.circuit_id,
                    },
                    {
                      key: 'revision',
                      header: 'Agreement / revision',
                      render: (circuit) => `${circuit.agreement.id} / ${circuit.agreement.version}`,
                    },
                    {
                      key: 'complete',
                      header: 'Complete recorded basis',
                      render: (circuit) => (circuit.credit.complete ? 'Yes' : 'Unknown'),
                    },
                    {
                      key: 'exact',
                      header: 'Conditional exact credit',
                      render: (circuit) => circuit.credit.exact_credit ?? 'Unavailable',
                    },
                    {
                      key: 'known',
                      header: 'Known lower bound',
                      render: (circuit) => circuit.credit.known_credit_lower_bound,
                    },
                  ]}
                />
              </section>
            ))}
            <details className={styles.completeResult}>
              <summary>Complete grouped claim JSON</summary>
              <pre tabIndex={0} aria-label="Complete grouped carrier claim">
                {JSON.stringify(result, null, 2)}
              </pre>
            </details>
          </section>
        )}
      </CardBody>
    </Card>
  )
}
