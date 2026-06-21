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
import { gib, usd, useCostSummary, type BudgetStatus, type ChattyPair } from '../api/cost'
import { useCarbon, type CarbonAgg } from '../api/carbon'
import { useI18n } from '../i18n/useI18n'
import { formatDecimal, formatUnit } from '../i18n/number'

/** CostPage (S44): the light native FinOps summary — spend by team/service
 * (showback), chatty cross-AZ conversations, budget status. Deep dashboarding
 * is federated to Grafana via the S40 datasource (the Surface declaration).
 * S48 folds the carbon/ESG estimate in below — same traffic, same owners,
 * grams instead of dollars. */
export function CostPage() {
  const { locale } = useI18n()
  const { data, isPending, isError } = useCostSummary()
  const s = data?.summary
  const fmtGiB = (bytes: number) => gib(bytes, locale)
  const fmtUSD = (value: number) => usd(value, locale)

  const owners: Array<{ name: string; agg: { bytes: number; usd: number } }> = Object.entries(
    s?.by_team ?? {},
  )
    .map(([name, agg]) => ({ name, agg }))
    .sort((a, b) => b.agg.usd - a.agg.usd || b.agg.bytes - a.agg.bytes)

  const teamColumns: Column<(typeof owners)[number]>[] = [
    { key: 'team', header: 'Team', render: (r) => <strong>{r.name}</strong> },
    { key: 'gib', header: 'Egress (GiB)', render: (r) => fmtGiB(r.agg.bytes) },
    {
      key: 'usd',
      header: 'Cost',
      render: (r) => (s?.priced ? fmtUSD(r.agg.usd) : '—'),
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
    { key: 'gib', header: 'GiB', render: (p) => fmtGiB(p.bytes) },
    { key: 'usd', header: 'Cost', render: (p) => (s?.priced ? fmtUSD(p.usd) : '—') },
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
    { key: 'cap', header: 'Monthly', render: (b) => fmtUSD(b.monthly_usd) },
    { key: 'spent', header: 'Spent', render: (b) => fmtUSD(b.spent_usd) },
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
                  <dd>{fmtGiB(s.total_bytes)} GiB</dd>
                </div>
                <div>
                  <dt>Total cost</dt>
                  <dd>{s.priced ? fmtUSD(s.total_usd) : 'volume-only'}</dd>
                </div>
                <div>
                  <dt>Pricing</dt>
                  <dd>
                    {s.priced ? (
                      <span>
                        {s.pricing_source}{' '}
                        <span className={styles.kind}>(as of {s.pricing_as_of})</span>
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

      <CarbonCard />
    </Page>
  )
}

/** CarbonCard (S48): the ESG estimate folded into the FinOps page — same
 *  attribution as the dollars above, with the methodology stated plainly. */
function CarbonCard() {
  const { locale } = useI18n()
  const carbon = useCarbon()
  const s = carbon.data?.summary
  const fmtGiB = (bytes: number) => gib(bytes, locale)

  const rows: Array<{ name: string; agg: CarbonAgg }> = Object.entries(s?.by_team ?? {})
    .map(([name, agg]) => ({ name, agg }))
    .sort((x, y) => y.agg.gco2e - x.agg.gco2e)

  const columns: Column<{ name: string; agg: CarbonAgg }>[] = [
    { key: 'team', header: 'Team', render: (r) => r.name },
    { key: 'gb', header: 'Volume (GiB)', numeric: true, render: (r) => fmtGiB(r.agg.bytes) },
    {
      key: 'kwh',
      header: 'Energy (kWh, est.)',
      numeric: true,
      render: (r) =>
        formatDecimal(r.agg.kwh, locale, {
          minimumFractionDigits: 3,
          maximumFractionDigits: 3,
        }),
    },
    {
      key: 'g',
      header: 'Carbon (gCO2e, est.)',
      numeric: true,
      render: (r) =>
        formatDecimal(r.agg.gco2e, locale, {
          minimumFractionDigits: 1,
          maximumFractionDigits: 1,
        }),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Carbon / energy (estimate)"
        description="The ESG view of the same traffic: volume × transmission-energy coefficients × your grid intensity."
      />
      <CardBody>
        {carbon.isPending ? (
          <LoadingState label="Loading carbon estimate…" />
        ) : carbon.isError ? (
          <ErrorState description="Could not load the carbon estimate." />
        ) : !carbon.data?.carbon_running ? (
          <EmptyState
            icon="cost"
            title="Carbon engine not wired"
            description="The control plane started with PROBECTL_CARBON_ENABLED=false."
          />
        ) : (
          <>
            <p role="note" aria-label="carbon methodology" className={styles.notice}>
              <Badge tone="info">estimate</Badge>{' '}
              {formatUnit(s?.total_gco2e ?? 0, 'gCO2e', locale, {
                minimumFractionDigits: 1,
                maximumFractionDigits: 1,
              })}{' '}
              ·{' '}
              {formatUnit(s?.total_kwh ?? 0, 'kWh', locale, {
                minimumFractionDigits: 3,
                maximumFractionDigits: 3,
              })}{' '}
              over{' '}
              {fmtGiB(s?.total_bytes ?? 0)} GiB — coefficient-based estimate, not measured power ·
              grid{' '}
              {formatUnit(s?.methodology.grid_gco2e_per_kwh ?? 0, 'gCO2e/kWh', locale, {
                maximumFractionDigits: 1,
              })}{' '}
              · {s?.methodology.source}
            </p>
            <Table
              caption="Carbon by team"
              columns={columns}
              rows={rows}
              rowKey={(r) => r.name}
              empty={
                <EmptyState
                  icon="cost"
                  title="No traffic observed yet"
                  description="Estimates appear once flow telemetry arrives."
                />
              }
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
