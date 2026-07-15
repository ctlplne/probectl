// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import styles from './compliance.module.css'
import { Page } from './RoutePage'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  HonestDataState,
  LoadingState,
  Table,
  classifySurfaceTruth,
  type Column,
} from '../components'
import { useCompliance, type RuleResult, type Verdict } from '../api/compliance'
import { apiURL } from '../api/client'
import { DateTime } from '../time/DateTime'

/** CompliancePage (S46): segmentation validation against OBSERVED traffic —
 * pass/fail per declared boundary, with the never-overclaim coverage block
 * and the audit-grade evidence export. */
export function CompliancePage() {
  const { data, isPending, isError, error, refetch } = useCompliance()

  const columns: Column<RuleResult>[] = [
    {
      key: 'rule',
      header: 'Boundary',
      render: (r) => (
        <div>
          <strong>
            {r.from} → {r.to}
          </strong>
          <div className={styles.meta}>
            {r.policy} · {r.rule_id} · {r.ports}
          </div>
          {r.frameworks && (
            <div className={styles.frameworks}>
              {Object.entries(r.frameworks).map(([fw, ref]) => (
                <Badge key={fw} tone="info">
                  {fw}: {ref}
                </Badge>
              ))}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'verdict',
      header: 'Verdict',
      render: (r) => verdictBadge(r.verdict),
    },
    { key: 'violations', header: 'Violations', render: (r) => r.violations },
    { key: 'observed', header: 'Observed conversations', render: (r) => r.observed_pairs },
    {
      key: 'last',
      header: 'Last violated',
      render: (r) => <DateTime value={r.last_violated} />,
    },
  ]

  return (
    <Page
      title="Compliance"
      subtitle="Segmentation validated against observed traffic — verdicts cover what was seen, never more."
    >
      <Card>
        <CardHeader
          title="Segmentation validation"
          description="Declared boundaries (PCI / zero-trust intents) checked against observed eBPF + flow reality. probectl validates; it never enforces."
        />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading validation results…" />
          ) : isError ? (
            <HonestDataState
              state={classifySurfaceTruth({ error })}
              producer="Compliance validator"
              producerReadiness="The tenant-scoped validator response is unavailable"
              lastSuccessfulIngest={null}
              coverageLimitation="No segmentation verdict is shown because coverage could not be established."
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Retry validator status
                </Button>
              }
            />
          ) : !data?.compliance_running ? (
            <HonestDataState
              state="blocked"
              icon="compliance"
              title="Compliance validator not wired"
              producer="Compliance validator"
              producerReadiness="Server reports compliance_running=false"
              lastSuccessfulIngest={null}
              coverageLimitation="No policy or observed-flow verdict exists until PROBECTL_COMPLIANCE_POLICY_DIR is configured."
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Recheck validator status
                </Button>
              }
            />
          ) : data.items.length === 0 ? (
            <HonestDataState
              state="ready-no-data"
              icon="compliance"
              title="No policies declared"
              producer="Compliance validator"
              producerReadiness="Ready; the server returned no declared policies"
              lastSuccessfulIngest={null}
              coverageLimitation="Observed traffic cannot be evaluated until policy YAML is added to PROBECTL_COMPLIANCE_POLICY_DIR."
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Recheck declared policies
                </Button>
              }
            />
          ) : (
            <>
              {(data.coverage?.notes?.length ?? 0) > 0 && (
                <div className={styles.coverage} role="note" aria-label="coverage caveats">
                  {data.coverage?.notes?.map((n) => (
                    <span key={n}>{n}</span>
                  ))}
                </div>
              )}
              <div className={styles.evidenceRow}>
                <Button
                  variant="ghost"
                  onClick={() => {
                    window.location.assign(apiURL('/compliance/evidence'))
                  }}
                >
                  Download audit evidence
                </Button>
              </div>
              <Table
                caption="Segmentation verdicts"
                columns={columns}
                rows={data.items}
                rowKey={(r) => `${r.policy}|${r.rule_id}`}
                empty={<EmptyState icon="compliance" title="No rules" description="—" />}
              />
            </>
          )}
        </CardBody>
      </Card>
    </Page>
  )
}

function verdictBadge(v: Verdict) {
  switch (v) {
    case 'violation':
      return <Badge tone="danger">violation</Badge>
    case 'observed_clean':
      return <Badge tone="success">observed clean</Badge>
    default:
      // The honest verdict: nothing seen ≠ proven isolated.
      return <Badge tone="neutral">not observed</Badge>
  }
}
