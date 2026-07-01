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
  const { locale, t } = useI18n()
  const { data, isPending, isError } = useSLOs()

  const columns: Column<SLOStatus>[] = [
    {
      key: 'name',
      header: t('slo.column.slo'),
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
    { key: 'objective', header: t('slo.column.objective'), render: (s) => pct(s.objective, locale) },
    {
      key: 'attainment',
      header: t('slo.column.attainment'),
      render: (s) =>
        s.cold_start ? <Badge tone="neutral">{t('slo.coldStart')}</Badge> : pct(s.attainment, locale),
    },
    {
      key: 'budget',
      header: t('slo.column.errorBudget'),
      render: (s) => {
        if (s.cold_start) return '—'
        const remaining = Math.max(0, Math.min(1, s.error_budget_remaining))
        const remainingText = pct(remaining, locale)
        const cls = remaining <= 0 ? styles.budgetGone : remaining < 0.25 ? styles.budgetLow : ''
        return (
          <div className={`${styles.budgetCell} ${cls}`}>
            {t('slo.budget.left', { value: remainingText })}
            <div
              className={styles.budgetBar}
              role="img"
              aria-label={t('slo.budget.aria', { value: remainingText })}
            >
              <div className={styles.budgetFill} style={{ width: `${remaining * 100}%` }} />
            </div>
          </div>
        )
      },
    },
    {
      key: 'burn',
      header: t('slo.column.burnRates'),
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
    { key: 'events', header: t('slo.column.events'), render: (s) => formatInteger(s.total_events, locale) },
  ]

  return (
    <Page
      title={t('slo.page.title')}
      subtitle={t('slo.page.subtitle')}
    >
      <Card>
        <CardHeader
          title={t('slo.card.title')}
          description={t('slo.card.description')}
        />
        <CardBody>
          {isPending ? (
            <LoadingState label={t('slo.loading')} />
          ) : isError ? (
            <ErrorState description={t('slo.error')} />
          ) : !data?.slo_running ? (
            <EmptyState
              icon="slo"
              title={t('slo.unwired.title')}
              description={t('slo.unwired.description')}
            />
          ) : (
            <Table
              caption={t('slo.table.caption')}
              columns={columns}
              rows={data.items}
              rowKey={(s) => s.name}
              empty={
                <EmptyState
                  icon="slo"
                  title={t('slo.empty.title')}
                  description={t('slo.empty.description')}
                />
              }
            />
          )}
        </CardBody>
      </Card>
    </Page>
  )
}
