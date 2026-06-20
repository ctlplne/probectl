import { useMemo } from 'react'
import styles from './outages.module.css'
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
import { useOutages, type FeedHealth, type OutageEvent } from '../api/outages'
import { useI18n } from '../i18n/useI18n'
import type { Locale, MessageKey } from '../i18n/messages'

type T = (key: MessageKey, vars?: Record<string, string | number>) => string

/** OutagesPage (S47a): the collective internet-outage view — public outage
 * feeds + the tenant's own vantage points, correlated with affected tests.
 * The coverage notes keep the view honest: this is NOT a global probe fleet. */
export function OutagesPage() {
  const { data, isPending, isError } = useOutages()
  const { locale, t } = useI18n()
  const eventColumns = useMemo(() => makeEventColumns(t, locale), [locale, t])
  const feedColumns = useMemo(() => makeFeedColumns(t, locale), [locale, t])

  return (
    <Page title={t('outages.page.title')} subtitle={t('outages.page.subtitle')}>
      <Card>
        <CardHeader title={t('outages.card.title')} description={t('outages.card.description')} />
        <CardBody>
          {isPending ? (
            <LoadingState label={t('outages.loading')} />
          ) : isError ? (
            <ErrorState description={t('outages.error')} />
          ) : !data?.outage_running ? (
            <EmptyState
              icon="outage"
              title={t('outages.unwired.title')}
              description={t('outages.unwired.description')}
            />
          ) : (
            <>
              {(data.coverage_notes?.length ?? 0) > 0 && (
                <div
                  className={styles.coverage}
                  role="note"
                  aria-label={t('outages.coverageNotes')}
                >
                  {data.coverage_notes?.map((n) => (
                    <span key={n}>{n}</span>
                  ))}
                </div>
              )}
              {(data.events?.length ?? 0) === 0 && (data.vantage_events?.length ?? 0) === 0 ? (
                <EmptyState
                  icon="outage"
                  title={t('outages.none.title')}
                  description={
                    data.feeds_enabled ? t('outages.none.feedsOn') : t('outages.none.feedsOff')
                  }
                />
              ) : (
                <>
                  {(data.events?.length ?? 0) > 0 && (
                    <Table
                      caption={t('outages.external.caption')}
                      columns={eventColumns}
                      rows={data.events ?? []}
                      rowKey={(e) => e.id}
                      empty={<EmptyState icon="outage" title={t('outages.external.empty')} />}
                    />
                  )}
                  {(data.vantage_events?.length ?? 0) > 0 && (
                    <div className={styles.sectionGap}>
                      <Table
                        caption={t('outages.vantage.caption')}
                        columns={eventColumns}
                        rows={data.vantage_events ?? []}
                        rowKey={(e) => e.id}
                        empty={<EmptyState icon="outage" title={t('outages.vantage.empty')} />}
                      />
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </CardBody>
      </Card>

      {data?.outage_running && data.feeds_enabled && (data.feeds?.length ?? 0) > 0 && (
        <Card>
          <CardHeader
            title={t('outages.feedHealth.title')}
            description={t('outages.feedHealth.description')}
          />
          <CardBody>
            <Table
              caption={t('outages.feeds.caption')}
              columns={feedColumns}
              rows={data.feeds ?? []}
              rowKey={(f) => f.name}
              empty={<EmptyState icon="outage" title={t('outages.feeds.empty')} />}
            />
          </CardBody>
        </Card>
      )}
    </Page>
  )
}

function makeEventColumns(t: T, locale: Locale): Column<OutageEvent>[] {
  return [
    {
      key: 'what',
      header: t('outages.column.outage'),
      render: (e) => (
        <div>
          <strong>{e.title}</strong>
          <div className={styles.meta}>
            {e.summary ?? ''}
            {e.evidence_url ? (
              <>
                {e.summary ? ' · ' : ''}
                <a href={e.evidence_url} target="_blank" rel="noreferrer">
                  {t('outages.link.evidence')}
                </a>
              </>
            ) : null}
          </div>
        </div>
      ),
    },
    {
      key: 'source',
      header: t('outages.column.source'),
      render: (e) => <Badge tone={e.source === 'vantage' ? 'info' : 'neutral'}>{e.source}</Badge>,
    },
    {
      key: 'scope',
      header: t('outages.column.scope'),
      render: (e) => (
        <div>
          {e.scope.code}
          {e.scope.name ? <div className={styles.scopeName}>{e.scope.name}</div> : null}
        </div>
      ),
    },
    {
      key: 'severity',
      header: t('outages.column.severity'),
      render: (e) => severityBadge(t, e.severity),
    },
    {
      key: 'state',
      header: t('outages.column.status'),
      render: (e) =>
        e.ongoing ? (
          <Badge tone="warning">{t('outages.status.ongoing')}</Badge>
        ) : (
          <Badge tone="neutral">{t('outages.status.ended')}</Badge>
        ),
    },
    {
      key: 'start',
      header: t('outages.column.started'),
      render: (e) => new Date(e.start).toLocaleString(locale),
    },
    {
      key: 'impact',
      header: t('outages.column.impact'),
      render: (e) =>
        (e.affected_tests?.length ?? 0) === 0 ? (
          ''
        ) : (
          <div className={styles.affected}>
            {e.affected_tests?.map((affected) => (
              <span key={affected.target}>
                {affected.canary_type} {affected.target} (
                {t('outages.failures', { count: affected.failures })})
              </span>
            ))}
          </div>
        ),
    },
  ]
}

function makeFeedColumns(t: T, locale: Locale): Column<FeedHealth>[] {
  return [
    { key: 'name', header: t('outages.column.feed'), render: (f) => <strong>{f.name}</strong> },
    {
      key: 'status',
      header: t('outages.column.status'),
      render: (f) => feedStatusBadge(t, f.status),
    },
    { key: 'events', header: t('outages.column.events'), render: (f) => f.events },
    {
      key: 'refreshed',
      header: t('outages.column.refreshed'),
      render: (f) => (f.last_success ? new Date(f.last_success).toLocaleString(locale) : ''),
    },
    {
      key: 'aup',
      header: t('outages.column.aup'),
      render: (f) => (
        <div>
          {f.license}
          <div className={styles.feedMeta}>
            {f.attribution ?? ''}
            {f.attribution ? ' · ' : ''}
            {t('outages.feed.commercialUse', { value: f.commercial_use })}
          </div>
        </div>
      ),
    },
  ]
}

function severityBadge(t: T, sev: OutageEvent['severity']) {
  switch (sev) {
    case 'critical':
      return <Badge tone="danger">{t('severity.critical')}</Badge>
    case 'warning':
      return <Badge tone="warning">{t('severity.warning')}</Badge>
    default:
      return <Badge tone="neutral">{t('severity.info')}</Badge>
  }
}

function feedStatusBadge(t: T, status: FeedHealth['status']) {
  switch (status) {
    case 'ok':
      return <Badge tone="success">{t('outages.feed.ok')}</Badge>
    case 'failed':
      return <Badge tone="danger">{t('outages.feed.failed')}</Badge>
    default:
      return <Badge tone="neutral">{t('outages.feed.pending')}</Badge>
  }
}
