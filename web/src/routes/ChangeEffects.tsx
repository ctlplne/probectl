// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchChangeEffects } from '../api/incidents'
import type { ChangeEffectTest } from '../api/sdk.gen'
import { useAuth } from '../auth/useAuth'
import { Button, ErrorState, LoadingState, Table, type Column } from '../components'
import { useI18n } from '../i18n/useI18n'

export function ChangeEffects({ id, from, to }: { id: string; from: string; to: string }) {
  const auth = useAuth()
  const identity = JSON.stringify([
    auth.tenant.id,
    auth.user.id,
    [...auth.permissions].sort(),
    id,
    from,
    to,
  ])
  return <CurrentChangeEffects key={identity} identity={identity} id={id} from={from} to={to} />
}

function CurrentChangeEffects({
  identity,
  id,
  from,
  to,
}: {
  identity: string
  id: string
  from: string
  to: string
}) {
  const { t } = useI18n()
  const { permissions } = useAuth()
  const [requested, setRequested] = useState(false)
  const [expired, setExpired] = useState(false)
  const allowed = [
    'change.read',
    'flow.read',
    'entities.read',
    'metrics.read',
    'events.read',
    'test.read',
  ].every((permission) => permissions.includes(permission))
  const query = new URLSearchParams({ from, to })
  const coverage = (value: string) => {
    switch (value) {
      case 'observed_attested_records':
        return t('changes.effects.observed')
      case 'partial_capture_coverage':
        return t('changes.effects.partial')
      case 'unavailable_source':
        return t('changes.effects.noSource')
      case 'no_observed_records':
        return t('changes.effects.noObservations')
      case 'unavailable_original_capture':
        return t('changes.effects.noOriginal')
      default:
        return t('changes.effects.unknown')
    }
  }
  const result = useQuery({
    queryKey: ['change-effects', identity],
    queryFn: ({ signal }) => fetchChangeEffects(id, query, signal),
    enabled: requested && allowed,
    retry: false,
    staleTime: 0,
    gcTime: 0,
  })
  useEffect(() => {
    setExpired(false)
    if (!result.data?.valid_until) return
    const until = Date.parse(result.data.valid_until)
    let timer: ReturnType<typeof setTimeout> | undefined
    const check = () => {
      const remaining = until - Date.now()
      if (!Number.isFinite(remaining) || remaining <= 0) setExpired(true)
      else timer = setTimeout(check, Math.min(remaining, 2_147_483_647))
    }
    check()
    return () => clearTimeout(timer)
  }, [result.data])
  const columns: Column<ChangeEffectTest>[] = [
    {
      key: 'source',
      header: t('changes.effects.test'),
      render: (test) => `${test.context_id} / ${test.entity_id} / ${test.test_id}`,
    },
    {
      key: 'beforeLoss',
      header: t('changes.effects.beforeLoss'),
      render: (test) => test.before.loss_ratio ?? t('changes.effects.unknown'),
    },
    {
      key: 'afterLoss',
      header: t('changes.effects.afterLoss'),
      render: (test) => test.after.loss_ratio ?? t('changes.effects.unknown'),
    },
    {
      key: 'beforeLatency',
      header: t('changes.effects.beforeLatency'),
      render: (test) => test.before.latency?.mean_nanos ?? t('changes.effects.unknown'),
    },
    {
      key: 'afterLatency',
      header: t('changes.effects.afterLatency'),
      render: (test) => test.after.latency?.mean_nanos ?? t('changes.effects.unknown'),
    },
  ]
  const download = () => {
    if (!result.data || expired || result.isFetching || result.isError) return
    const href = URL.createObjectURL(
      new Blob([JSON.stringify(result.data)], { type: 'application/json' }),
    )
    try {
      const link = document.createElement('a')
      link.href = href
      link.download = `probectl-change-${id}-observations.json`
      link.click()
    } finally {
      URL.revokeObjectURL(href)
    }
  }
  return (
    <section aria-label={t('changes.effects.title')}>
      <h3>{t('changes.effects.title')}</h3>
      <p>{t('changes.effects.description')}</p>
      {!allowed ? (
        <p>{t('changes.effects.denied')}</p>
      ) : (
        <Button
          disabled={result.isFetching}
          onClick={() => {
            if (requested) void result.refetch()
            else setRequested(true)
          }}
        >
          {t('changes.effects.compare')}
        </Button>
      )}
      {requested && allowed ? (
        result.isFetching ? (
          <LoadingState label={t('changes.effects.loading')} />
        ) : result.isError || expired ? (
          <ErrorState description={t('changes.effects.error')} headingLevel={4} />
        ) : result.data ? (
          <>
            <p>
              {t('changes.effects.traffic', {
                before:
                  result.data.before.observed_totals?.scaled_bytes ?? t('changes.effects.unknown'),
                after:
                  result.data.after.observed_totals?.scaled_bytes ?? t('changes.effects.unknown'),
              })}
            </p>
            <p>
              {t('changes.effects.coverage', {
                before: coverage(result.data.before.coverage),
                after: coverage(result.data.after.coverage),
              })}
            </p>
            <Table
              caption={t('changes.effects.tests')}
              columns={columns}
              rows={result.data.tests}
              rowKey={(test) =>
                `${test.context_id}/${test.entity_id}/${test.test_id}/${test.agent_id}`
              }
              empty={<p>{t('changes.effects.noTests')}</p>}
            />
            <Button onClick={download}>{t('changes.effects.download')}</Button>
          </>
        ) : null
      ) : null}
    </section>
  )
}
