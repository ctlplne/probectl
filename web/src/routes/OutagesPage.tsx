// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMemo } from 'react'
import styles from './outages.module.css'
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
import { useOutages, type FeedHealth, type OutageEvent } from '../api/outages'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import { DateTime } from '../time/DateTime'

type T = (key: MessageKey, vars?: Record<string, string | number>) => string

/** OutagesPage (S47a): the collective internet-outage view — public outage
 * feeds + the tenant's own vantage points, correlated with affected tests.
 * The coverage notes keep the view honest: this is NOT a global probe fleet. */
export function OutagesPage() {
  const { data, isPending, isError, error, refetch } = useOutages()
  const { t } = useI18n()
  const eventColumns = useMemo(() => makeEventColumns(t), [t])
  const feedColumns = useMemo(() => makeFeedColumns(t), [t])
  const feedDegraded = data?.feeds?.some((feed) => feed.status === 'failed') ?? false
  const lastSuccessfulIngest = latestTimestamp(
    data?.feeds?.flatMap((feed) => (feed.last_success ? [feed.last_success] : [])) ?? [],
  )

  return (
    <Page title={t('outages.page.title')} subtitle={t('outages.page.subtitle')}>
      <Card>
        <CardHeader title={t('outages.card.title')} description={t('outages.card.description')} />
        <CardBody>
          {isPending ? (
            <LoadingState label={t('outages.loading')} />
          ) : isError ? (
            <HonestDataState
              state={classifySurfaceTruth({ error })}
              producer="Outage correlation service"
              producerReadiness="The tenant-scoped outage response is unavailable"
              lastSuccessfulIngest={null}
              coverageLimitation="Neither public-feed nor tenant-vantage coverage can be established from a failed request."
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Retry outage status
                </Button>
              }
            />
          ) : !data?.outage_running ? (
            <HonestDataState
              state="blocked"
              icon="outage"
              title={t('outages.unwired.title')}
              producer="Outage correlation service"
              producerReadiness="Server reports outage_running=false"
              lastSuccessfulIngest={lastSuccessfulIngest}
              coverageLimitation={t('outages.unwired.description')}
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Recheck outage service
                </Button>
              }
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
                <HonestDataState
                  state={classifySurfaceTruth({
                    producerRunning: true,
                    degraded: feedDegraded,
                    quiet: !feedDegraded,
                  })}
                  icon="outage"
                  title={t('outages.none.title')}
                  producer="Outage correlation service"
                  producerReadiness={
                    feedDegraded
                      ? 'Running, but at least one enabled feed reports failure'
                      : 'Running; no outage events were returned for the observed window'
                  }
                  lastSuccessfulIngest={lastSuccessfulIngest}
                  coverageLimitation={[
                    data.feeds_enabled ? t('outages.none.feedsOn') : t('outages.none.feedsOff'),
                    ...(data.coverage_notes ?? []),
                  ].join(' ')}
                  action={
                    <Button variant="secondary" onClick={() => void refetch()}>
                      Refresh observed window
                    </Button>
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

function latestTimestamp(values: string[]): string | null {
  return values.sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null
}

function makeEventColumns(t: T): Column<OutageEvent>[] {
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
      render: (e) => <DateTime value={e.start} />,
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

function makeFeedColumns(t: T): Column<FeedHealth>[] {
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
      render: (f) => <DateTime value={f.last_success} empty="" />,
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
