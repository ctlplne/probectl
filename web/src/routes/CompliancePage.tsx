import styles from './compliance.module.css'
import { Page } from './pages'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Table,
  type Column,
} from '../components'
import { useCompliance, type RuleResult, type Verdict } from '../api/compliance'
import { apiURL } from '../api/client'

/** CompliancePage (S46): segmentation validation against OBSERVED traffic —
 * pass/fail per declared boundary, with the never-overclaim coverage block
 * and the audit-grade evidence export. */
export function CompliancePage() {
  const { data, isPending, isError } = useCompliance()

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
      render: (r) => (r.last_violated ? new Date(r.last_violated).toLocaleString() : '—'),
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
            <ErrorState description="Could not load compliance results." />
          ) : !data?.compliance_running ? (
            <EmptyState
              icon="compliance"
              title="Compliance validator not wired"
              description="The control plane started without segmentation policies (PROBECTL_COMPLIANCE_POLICY_DIR)."
            />
          ) : data.items.length === 0 ? (
            <EmptyState
              icon="compliance"
              title="No policies declared"
              description="Drop segmentation policy YAML into PROBECTL_COMPLIANCE_POLICY_DIR to start validating."
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
