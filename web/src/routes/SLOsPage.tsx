import styles from './slos.module.css'
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
import { pct, useSLOs, type SLOStatus } from '../api/slos'
import { useI18n } from '../i18n/useI18n'
import { formatInteger, formatMultiplier } from '../i18n/number'

/** SLOsPage (S45): the exec-grade reliability view — attainment vs objective,
 * error budgets, and multi-window burn rates per service/team. Definitions
 * are OpenSLO YAML (import/export via the API). */
export function SLOsPage() {
  const { locale } = useI18n()
  const { data, isPending, isError } = useSLOs()

  const columns: Column<SLOStatus>[] = [
    {
      key: 'name',
      header: 'SLO',
      render: (s) => (
        <div>
          <strong>{s.display_name || s.name}</strong>
          <div className={styles.meta}>
            {s.service}
            {s.team ? ` · ${s.team}` : ''} · {s.window}
          </div>
        </div>
      ),
    },
    { key: 'objective', header: 'Objective', render: (s) => pct(s.objective, locale) },
    {
      key: 'attainment',
      header: 'Attainment',
      render: (s) =>
        s.cold_start ? <Badge tone="neutral">cold start</Badge> : pct(s.attainment, locale),
    },
    {
      key: 'budget',
      header: 'Error budget',
      render: (s) => {
        if (s.cold_start) return '—'
        const remaining = Math.max(0, Math.min(1, s.error_budget_remaining))
        const cls = remaining <= 0 ? styles.budgetGone : remaining < 0.25 ? styles.budgetLow : ''
        return (
          <div className={`${styles.budgetCell} ${cls}`}>
            {pct(remaining, locale)} left
            <div
              className={styles.budgetBar}
              role="img"
              aria-label={`${pct(remaining, locale)} of the error budget remains`}
            >
              <div className={styles.budgetFill} style={{ width: `${remaining * 100}%` }} />
            </div>
          </div>
        )
      },
    },
    {
      key: 'burn',
      header: 'Burn rates',
      render: (s) => (
        <div className={styles.burns}>
          {s.burn_rates.map((b) => (
            <Badge key={b.window} tone={b.firing ? 'danger' : 'neutral'}>
              {b.window} {formatMultiplier(b.burn, locale)}
            </Badge>
          ))}
        </div>
      ),
    },
    { key: 'events', header: 'Events', render: (s) => formatInteger(s.total_events, locale) },
  ]

  return (
    <Page
      title="SLOs"
      subtitle="Error budgets and burn rates over the network planes — OpenSLO in, OpenSLO out."
    >
      <Card>
        <CardHeader
          title="Service-level objectives"
          description="Multi-window burn rates (fast 1h/5m, medium 6h/30m, slow 3d/6h); breaches raise incident signals."
        />
        <CardBody>
          {isPending ? (
            <LoadingState label="Loading SLOs…" />
          ) : isError ? (
            <ErrorState description="Could not load SLO statuses." />
          ) : !data?.slo_running ? (
            <EmptyState
              icon="slo"
              title="SLO engine not wired"
              description="The control plane started without the SLO engine."
            />
          ) : (
            <Table
              caption="SLO statuses"
              columns={columns}
              rows={data.items}
              rowKey={(s) => s.name}
              empty={
                <EmptyState
                  icon="slo"
                  title="No SLOs defined"
                  description="Drop OpenSLO YAML definitions into PROBECTL_SLO_DIR to start tracking."
                />
              }
            />
          )}
        </CardBody>
      </Card>
    </Page>
  )
}
