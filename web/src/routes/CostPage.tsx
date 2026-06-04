import styles from './cost.module.css'
import { Page } from './pages'
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  Table,
  type Column,
} from '../components'
import {
  gib,
  usd,
  useCostSummary,
  type BudgetStatus,
  type ChattyPair,
} from '../api/cost'

/** CostPage (S44): the light native FinOps summary — spend by team/service
 * (showback), chatty cross-AZ conversations, budget status. Deep dashboarding
 * is federated to Grafana via the S40 datasource (the Surface declaration). */
export function CostPage() {
  const { data, isPending, isError } = useCostSummary()
  const s = data?.summary

  const owners: Array<{ name: string; agg: { bytes: number; usd: number } }> = Object.entries(
    s?.by_team ?? {},
  )
    .map(([name, agg]) => ({ name, agg }))
    .sort((a, b) => b.agg.usd - a.agg.usd || b.agg.bytes - a.agg.bytes)

  const teamColumns: Column<(typeof owners)[number]>[] = [
    { key: 'team', header: 'Team', render: (r) => <strong>{r.name}</strong> },
    { key: 'gib', header: 'Egress (GiB)', render: (r) => gib(r.agg.bytes) },
    {
      key: 'usd',
      header: 'Cost',
      render: (r) => (s?.priced ? usd(r.agg.usd) : '—'),
    },
  ]

  const pairColumns: Column<ChattyPair>[] = [
    { key: 'svc', header: 'Service', render: (p) => p.service },
    {
      key: 'pair',
      header: 'Zones',
      render: (p) => (
        <code>
          {p.src_zone} → {p.dst_zone}
        </code>
      ),
    },
    { key: 'class', header: 'Class', render: (p) => p.class },
    { key: 'gib', header: 'GiB', render: (p) => gib(p.bytes) },
    { key: 'usd', header: 'Cost', render: (p) => (s?.priced ? usd(p.usd) : '—') },
    {
      key: 'chatty',
      header: 'Chatty',
      render: (p) =>
        p.chatty ? <Badge tone="warning">chatty</Badge> : <Badge tone="neutral">ok</Badge>,
    },
  ]

  const budgetColumns: Column<BudgetStatus>[] = [
    {
      key: 'target',
      header: 'Budget',
      render: (b) => (
        <span>
          <strong>{b.name}</strong> <span className={styles.kind}>({b.kind})</span>
        </span>
      ),
    },
    { key: 'cap', header: 'Monthly', render: (b) => usd(b.monthly_usd) },
    { key: 'spent', header: 'Spent', render: (b) => usd(b.spent_usd) },
    {
      key: 'state',
      header: 'Status',
      render: (b) =>
        b.exceeded ? <Badge tone="danger">exceeded</Badge> : <Badge tone="success">within</Badge>,
    },
  ]

  return (
    <Page
      title="Cost"
      subtitle="Network egress dollars — volume × public pricing, attributed to services and teams."
    >
      <Card>
        <CardHeader
          title="Egress spend"
          description="Attribution and showback; deep dashboards live in Grafana via the probectl datasource."
        />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading cost summary…" />
          ) : isError ? (
            <ErrorState description="Could not load the cost summary." />
          ) : !data?.cost_running || !s ? (
            <EmptyState
              icon="cost"
              title="Cost engine not wired"
              description="The control plane started without the cost engine."
            />
          ) : (
            <>
              {!s.priced && (
                <div className={styles.notice} role="note" aria-label="volume-only mode">
                  Volume-only mode: no price table is loaded, so byte volumes are attributed but
                  dollars are not invented.
                </div>
              )}
              {!s.zones_mapped && (
                <div className={styles.notice} role="note" aria-label="zones unmapped">
                  No CIDR→zone rules configured (PROBECTL_COST_ZONES) — locality classes are
                  unknown, so cross-AZ detection is inactive.
                </div>
              )}
              <dl className={styles.totals}>
                <div>
                  <dt>Total egress</dt>
                  <dd>{gib(s.total_bytes)} GiB</dd>
                </div>
                <div>
                  <dt>Total cost</dt>
                  <dd>{s.priced ? usd(s.total_usd) : 'volume-only'}</dd>
                </div>
                <div>
                  <dt>Pricing</dt>
                  <dd>
                    {s.priced ? (
                      <span>
                        {s.pricing_source} <span className={styles.kind}>(as of {s.pricing_as_of})</span>
                      </span>
                    ) : (
                      'none'
                    )}
                  </dd>
                </div>
              </dl>
              <Table
                caption="Spend by team (showback)"
                columns={teamColumns}
                rows={owners}
                rowKey={(r) => r.name}
                empty={
                  <EmptyState
                    icon="cost"
                    title="No attributed traffic yet"
                    description="Map service CIDRs with PROBECTL_COST_SERVICES to attribute spend."
                  />
                }
              />
            </>
          )}
        </CardBody>
      </Card>

      {data?.cost_running && s && (
        <>
          <Card>
            <CardHeader
              title="Cross-AZ conversations"
              description="Chatty service pairs paying the inter-AZ/inter-region tax."
            />
            <CardBody>
              <Table
                caption="Chatty zone pairs"
                columns={pairColumns}
                rows={s.chatty_pairs}
                rowKey={(p) => `${p.service}|${p.src_zone}|${p.dst_zone}`}
                empty={
                  <EmptyState
                    icon="cost"
                    title="No paid cross-zone traffic observed"
                    description="Same-zone traffic is free; nothing chatty yet."
                  />
                }
              />
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title="Budgets"
              description="Monthly network budgets; a breach raises a cost-plane incident signal."
            />
            <CardBody>
              <Table
                caption="Budget status"
                columns={budgetColumns}
                rows={s.budgets}
                rowKey={(b) => `${b.kind}:${b.name}`}
                empty={
                  <EmptyState
                    icon="cost"
                    title="No budgets configured"
                    description="Set PROBECTL_COST_BUDGETS, e.g. team:payments=500."
                  />
                }
              />
            </CardBody>
          </Card>
        </>
      )}
    </Page>
  )
}
