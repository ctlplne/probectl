// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { fetchChangeTimelinePage, type ChangeEvent } from '../api/incidents'
import { useAuth } from '../auth/useAuth'
import {
  Badge,
  Button,
  Card,
  CardBody,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Table,
  type Column,
} from '../components'
import { useI18n } from '../i18n/useI18n'
import { DateTime } from '../time/DateTime'
import { Page } from './RoutePage'
import { RoutingChangeMetadata } from './RoutingChangeMetadata'
import { ChangeEffects } from './ChangeEffects'
import styles from './incidents.module.css'
import { pivotHref } from './pivotContext'

export function ChangeTimelinePage() {
  const auth = useAuth()
  const [params] = useSearchParams()
  const key = JSON.stringify([
    auth.tenant.id,
    auth.user.id,
    [...auth.permissions].sort(),
    params.get('changes_from'),
    params.get('changes_to'),
  ])
  return <CurrentChangeTimeline key={key} identity={key} />
}

function CurrentChangeTimeline({ identity }: { identity: string }) {
  const { t } = useI18n()
  const { permissions } = useAuth()
  const [params, setParams] = useSearchParams()
  const [initial] = useState(() => ({
    from: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    to: new Date().toISOString(),
  }))
  const from = params.get('changes_from') ?? initial.from
  const to = params.get('changes_to') ?? initial.to
  const [draft, setDraft] = useState({ from, to })
  const [cursors, setCursors] = useState<string[]>([params.get('changes_cursor') ?? ''])
  const [index, setIndex] = useState(0)
  const [selectedID, setSelectedID] = useState(params.get('change_id') ?? '')
  const cursor = cursors[index] ?? ''
  const query = new URLSearchParams({ limit: '200', from, to, cursor })
  const result = useQuery({
    queryKey: ['change-timeline', identity, from, to, cursor],
    enabled: permissions.includes('change.read'),
    queryFn: ({ signal }) => fetchChangeTimelinePage(query, signal),
    retry: false,
  })
  const selected = result.data?.items.find((item) => item.id === selectedID)
  const columns: Column<ChangeEvent>[] = [
    {
      key: 'time',
      header: t('changes.timeline.time'),
      render: (event) => <DateTime value={event.occurred_at} />,
    },
    {
      key: 'kind',
      header: t('changes.timeline.kind'),
      render: (event) => <Badge tone="info">{event.kind}</Badge>,
    },
    { key: 'source', header: t('changes.timeline.source'), render: (event) => event.source },
    {
      key: 'change',
      header: t('changes.timeline.change'),
      render: (event) => (
        <Button
          variant="ghost"
          aria-pressed={selectedID === event.id}
          onClick={() => setSelectedID(event.id)}
        >
          {event.title || event.id}
        </Button>
      ),
    },
  ]
  const back = () => {
    const next = new URLSearchParams(params)
    next.delete('view')
    next.delete('changes_from')
    next.delete('changes_to')
    next.delete('changes_cursor')
    next.delete('change_id')
    setParams(next)
  }
  const move = (next: number) => {
    setIndex(next)
    setSelectedID('')
  }
  return (
    <Page
      title={t('changes.timeline.title')}
      subtitle={t('changes.timeline.description')}
      actions={<Button onClick={back}>{t('changes.timeline.incidents')}</Button>}
    >
      <div className={styles.layout}>
        <Card>
          <CardBody>
            <form
              onSubmit={(event) => {
                event.preventDefault()
                const next = new URLSearchParams(params)
                next.set('changes_from', draft.from)
                next.set('changes_to', draft.to)
                next.delete('changes_cursor')
                next.delete('change_id')
                setParams(next)
                setCursors([''])
                move(0)
              }}
            >
              <Field
                label={t('changes.timeline.from')}
                value={draft.from}
                onChange={(event) => setDraft({ ...draft, from: event.target.value })}
                required
              />
              <Field
                label={t('changes.timeline.to')}
                value={draft.to}
                onChange={(event) => setDraft({ ...draft, to: event.target.value })}
                required
              />
              <Button type="submit">{t('changes.timeline.apply')}</Button>
            </form>
            <p>{t('changes.timeline.window', { from, to })}</p>
          </CardBody>
        </Card>
        {!permissions.includes('change.read') ? (
          <ErrorState description={t('changes.timeline.denied')} headingLevel={2} />
        ) : result.isLoading ? (
          <LoadingState label={t('changes.timeline.loading')} />
        ) : result.isError ? (
          <ErrorState description={t('changes.timeline.error')} headingLevel={2} />
        ) : result.data ? (
          <>
            <Table
              caption={t('changes.timeline.title')}
              columns={columns}
              rows={result.data.items}
              rowKey={(event) => event.id}
              empty={
                <EmptyState
                  title={t('changes.timeline.empty')}
                  description={t('changes.timeline.emptyDescription')}
                  headingLevel={2}
                />
              }
            />
            <nav aria-label={t('changes.timeline.pages')}>
              <Button onClick={() => move(index - 1)} disabled={index === 0 || result.isFetching}>
                {t('changes.timeline.previous')}
              </Button>
              <span role="status">
                {t('changes.timeline.page', { page: index + 1, count: result.data.items.length })}
              </span>
              <Button
                disabled={!result.data.next_cursor || result.isFetching}
                onClick={() => {
                  const next = result.data?.next_cursor
                  if (!next) return
                  setCursors([...cursors.slice(0, index + 1), next])
                  move(index + 1)
                }}
              >
                {t('changes.timeline.next')}
              </Button>
            </nav>
            {selected ? (
              <Card>
                <CardBody>
                  <h2>{selected.title}</h2>
                  <p>{selected.summary}</p>
                  <p>{selected.target || selected.prefix}</p>
                  {selected.routing ? <RoutingChangeMetadata reference={selected.routing} /> : null}
                  <ChangeEffects id={selected.id} from={from} to={to} />
                  {selected.config ? (
                    <Link
                      to={pivotHref(
                        '/planes/device',
                        {
                          from,
                          to,
                          selection: { kind: 'evidence', id: selected.id },
                          returnTo: `/incidents?${new URLSearchParams({ view: 'changes', changes_from: from, changes_to: to, changes_cursor: cursor, change_id: selected.id }).toString()}`,
                        },
                        {
                          config: selected.config.current_id,
                          previous_config: selected.config.previous_id,
                        },
                      )}
                    >
                      {t('changes.timeline.diff')}
                    </Link>
                  ) : null}
                </CardBody>
              </Card>
            ) : null}
          </>
        ) : null}
      </div>
    </Page>
  )
}
