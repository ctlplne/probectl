// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { getAlertDDoSReceipt } from '../api/alerts'
import { useCreateDashboard } from '../api/dashboardReporting'
import { getIncidentDDoSReport, type Signal } from '../api/incidents'
import type { IncidentDDoSReport } from '../api/sdk.gen'
import { useAuth } from '../auth/useAuth'
import { Button, Card, CardBody, CardHeader, ErrorState, LoadingState } from '../components'
import { DDoSAssessmentEvidence } from './FlowDDoSAssessmentCard'
import { IncidentRoutingProposal } from './IncidentRoutingProposal'
import { DateTime } from '../time/DateTime'

const digest = /^[a-f0-9]{64}$/

export function IncidentDDoSReceipt({
  signal,
  incidentID,
  allowRoutingReview = false,
}: {
  signal?: Signal
  incidentID: string
  allowRoutingReview?: boolean
}) {
  if (signal?.kind !== 'alert.ddos_assessment' || signal.plane !== 'flow') return null
  const rule = signal.attributes?.rule_id
  const fingerprint = signal.attributes?.['probectl.alert.ddos.receipt_fingerprint']
  const episode = signal.attributes?.['probectl.alert.ddos.episode_id']
  if (!rule || !fingerprint || !episode || !digest.test(episode) || !digest.test(fingerprint))
    return null
  return (
    <DDoSReceipt
      key={episode}
      rule={rule}
      fingerprint={fingerprint}
      episode={episode}
      incidentID={incidentID}
      allowRoutingReview={allowRoutingReview}
    />
  )
}

function DDoSReceipt({
  rule,
  fingerprint,
  episode,
  incidentID,
  allowRoutingReview,
}: {
  rule: string
  fingerprint: string
  episode: string
  incidentID: string
  allowRoutingReview: boolean
}) {
  const [open, setOpen] = useState(false)
  const [reviewing, setReviewing] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)
  const { tenant, user, permissions } = useAuth()
  const saveReport = useCreateDashboard()
  const canRead = ['alert.read', 'ai.query', 'flow.read'].every((permission) =>
    permissions.includes(permission),
  )
  const receipt = useQuery({
    queryKey: ['alert-ddos-receipt', tenant.id, user.id, permissions.join(','), rule, fingerprint],
    queryFn: ({ signal }) => getAlertDDoSReceipt(tenant.id, rule, fingerprint, signal),
    enabled: canRead && open,
    gcTime: 0,
  })
  const result = receipt.isSuccess && !receipt.isFetching ? receipt.data : undefined
  const matched = result?.incident_id === incidentID && result.episode_id === episode
  const report = useQuery({
    queryKey: [
      'incident-ddos-report',
      tenant.id,
      user.id,
      permissions.join(','),
      incidentID,
      rule,
      fingerprint,
    ],
    queryFn: ({ signal }) =>
      getIncidentDDoSReport(tenant.id, incidentID, rule, fingerprint, signal),
    enabled: canRead && matched && reportOpen,
    gcTime: 0,
  })
  if (!canRead) return null
  return (
    <Card>
      <CardHeader title="Traffic pressure receipt" />
      <CardBody>
        {!open && <Button onClick={() => setOpen(true)}>Show original traffic evidence</Button>}
        {open && receipt.isFetching && <LoadingState label="Loading original traffic evidence" />}
        {open && receipt.isError && (
          <ErrorState title="Traffic evidence unavailable" description={receipt.error.message} />
        )}
        {open && result && matched && (
          <>
            <h3>First qualifying window</h3>
            <DDoSAssessmentEvidence result={result.previous} />
            <h3>Second qualifying window</h3>
            <DDoSAssessmentEvidence result={result.current} />
            {!reportOpen ? (
              <Button variant="secondary" onClick={() => setReportOpen(true)}>
                Open DDoS incident report
              </Button>
            ) : null}
            {reportOpen && report.isFetching ? (
              <LoadingState label="Loading DDoS incident report" />
            ) : null}
            {reportOpen && report.isError ? (
              <ErrorState title="DDoS report unavailable" description={report.error.message} />
            ) : null}
            {reportOpen && report.isSuccess && !report.isFetching ? (
              <>
                <IncidentTrafficReport report={report.data} />
                {permissions.includes('metrics.write') ? (
                  <Button
                    variant="secondary"
                    disabled={saveReport.isPending || saveReport.isSuccess}
                    onClick={() =>
                      saveReport.mutate({
                        name: `DDoS incident ${incidentID.slice(0, 8)}`,
                        preset: 'operator',
                        shared: false,
                        definition: {
                          ddos_report: {
                            incident_id: incidentID,
                            rule_id: rule,
                            receipt_fingerprint: fingerprint,
                          },
                          provenance: [
                            'Tenant traffic assessment receipt and retained observations.',
                          ],
                          redaction_state: 'Tenant-scoped source data',
                          coverage_limitations: [
                            'Source contributions and rates cover the observed windows.',
                          ],
                        },
                      })
                    }
                  >
                    Save incident report
                  </Button>
                ) : null}
                {saveReport.isSuccess ? <p role="status">Saved to your dashboards.</p> : null}
                {saveReport.isError ? <p role="alert">{saveReport.error.message}</p> : null}
              </>
            ) : null}
            {allowRoutingReview && result.current.direction === 'ingress' ? (
              reviewing ? (
                <IncidentRoutingProposal
                  key={`${tenant.id}:${user.id}:${episode}`}
                  rule={rule}
                  receipt={fingerprint}
                  prefix={result.current.prefix}
                  windowSeconds={
                    (Date.parse(result.current.after.to) - Date.parse(result.current.after.from)) /
                    1000
                  }
                />
              ) : (
                <Button variant="secondary" onClick={() => setReviewing(true)}>
                  Prepare routing proposal
                </Button>
              )
            ) : null}
          </>
        )}
        {open && result && !matched && (
          <ErrorState title="Traffic evidence does not match this incident" />
        )}
      </CardBody>
    </Card>
  )
}

function IncidentTrafficReport({ report }: { report: IncidentDDoSReport }) {
  return (
    <section aria-label="DDoS incident report">
      <h3>DDoS incident report</h3>
      <dl>
        <dt>Observed period</dt>
        <dd>
          <DateTime value={report.from} /> – <DateTime value={report.to} />
        </dd>
        <dt>Observed duration</dt>
        <dd>{report.observed_seconds} seconds</dd>
        <dt>Peak window-average bit rate</dt>
        <dd>{report.peak_bit_rate.per_second} bits per second</dd>
        <dt>Peak window-average packet rate</dt>
        <dd>{report.peak_packet_rate.per_second} packets per second</dd>
      </dl>
      <table>
        <caption>Top observed source addresses by bytes</caption>
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Bytes</th>
            <th scope="col">Packets</th>
          </tr>
        </thead>
        <tbody>
          {report.top_sources.map((source) => (
            <tr key={source.address}>
              <th scope="row">{source.address}</th>
              <td>{source.bytes}</td>
              <td>{source.packets}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>Recorded mitigation decisions</h4>
      {report.actions_visible ? (
        report.actions?.length ? (
          <ul>
            {report.actions.map((action) => (
              <li key={action.proposal_id}>
                {action.kind === 'rtbh_review' ? 'RTBH' : 'FlowSpec'} · {action.state} ·{' '}
                <DateTime value={action.decided_at ?? action.created_at} />
              </li>
            ))}
          </ul>
        ) : (
          <p>No recorded mitigation decisions for this receipt.</p>
        )
      ) : (
        <p>Mitigation decisions require access to remediation proposals.</p>
      )}
    </section>
  )
}
