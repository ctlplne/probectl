// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useEffect, useMemo, useState } from 'react'
import { useEntityContexts, useEntityResolution } from '../api/entities'
import { useAuth } from '../auth/useAuth'
import { Button, Card, CardBody, CardHeader, ErrorState, LoadingState, Select } from '../components'
import { useI18n } from '../i18n/useI18n'
import styles from './EntityCurrentPivot.module.css'

function isIPLiteral(value: string): boolean {
  if (value.length > 64) return false
  if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255)
  }
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false
  try {
    // The URL parser validates bracketed IPv6 locally; no request is made.
    return new URL(`http://[${value}]/`).hostname !== ''
  } catch {
    return false
  }
}

// Only values already present in an authorized row or cited signal become
// options. The 100-option limit bounds a large Explorer result's UI work.
export function observedIPs(rows: ReadonlyArray<Record<string, unknown>>, limit = 100): string[] {
  const found = new Set<string>()
  for (const row of rows) {
    for (const value of Object.values(row)) {
      if (typeof value !== 'string' || !isIPLiteral(value)) continue
      found.add(value)
      if (found.size >= limit) return [...found]
    }
  }
  return [...found]
}

export function EntityCurrentPivot({
  ips,
  source,
}: {
  ips: string[]
  source: 'explorer' | 'incident'
}) {
  const { tenant, permissions } = useAuth()
  if (!permissions.includes('entities.read') || ips.length === 0) return null
  // Remount local selections synchronously when tenant or cited IP set
  // changes. An effect alone leaves one render where the previous context
  // or cited signal's resolution remains visible.
  return (
    <AuthorizedEntityCurrentPivot
      key={`${tenant.id}:${source}:${ips.join('|')}`}
      tenantID={tenant.id}
      ips={ips}
      source={source}
    />
  )
}

function AuthorizedEntityCurrentPivot({
  tenantID,
  ips,
  source,
}: {
  tenantID: string
  ips: string[]
  source: 'explorer' | 'incident'
}) {
  const { t } = useI18n()
  const contexts = useEntityContexts(tenantID)
  const [ip, setIP] = useState('')
  const [contextID, setContextID] = useState('')
  const [submitted, setSubmitted] = useState<{
    tenantID: string
    ip: string
    contextID: string
  } | null>(null)
  // A tenant switch renders once before effects reset local controls. Do not
  // dispatch that transient render's old context to the new tenant's API.
  const active = submitted?.tenantID === tenantID ? submitted : null
  const resolution = useEntityResolution(
    tenantID,
    active?.contextID ?? '',
    'address',
    active?.ip ?? '',
  )
  const contextOptions = useMemo(
    () => [
      { value: '', label: t('entity.pivot.chooseContext') },
      ...(contexts.data?.pages ?? []).flatMap((page) =>
        page.items.map((item) => ({
          value: item.context_id,
          label: `${item.site_label} / ${item.vrf_label}`,
        })),
      ),
    ],
    [contexts.data, t],
  )
  useEffect(() => {
    setIP('')
    setSubmitted(null)
  }, [ips.join('|'), tenantID])
  useEffect(() => {
    setContextID('')
    setSubmitted(null)
  }, [tenantID])

  return (
    <Card data-entity-current-pivot>
      <CardHeader
        title={t('entity.pivot.title')}
        description={t(
          source === 'explorer'
            ? 'entity.pivot.description.explorer'
            : 'entity.pivot.description.incident',
        )}
      />
      <CardBody>
        <div className={styles.controls}>
          <Select
            label={t('entity.pivot.ip')}
            value={ip}
            onChange={(event) => {
              setIP(event.target.value)
              setSubmitted(null)
            }}
            options={[
              { value: '', label: t('entity.pivot.chooseIP') },
              ...ips.map((value) => ({ value, label: value })),
            ]}
          />
          <Select
            label={t('entity.pivot.context')}
            value={contextID}
            onChange={(event) => {
              setContextID(event.target.value)
              setSubmitted(null)
            }}
            options={contextOptions}
          />
          <Button
            disabled={!ip || !contextID}
            onClick={() => setSubmitted({ tenantID, ip, contextID })}
          >
            {t('entity.pivot.resolve')}
          </Button>
          {contexts.hasNextPage ? (
            <Button
              variant="secondary"
              disabled={contexts.isFetchingNextPage}
              onClick={() => void contexts.fetchNextPage()}
            >
              {t('entity.pivot.loadMore')}
            </Button>
          ) : null}
        </div>
        {active && resolution.isPending ? <LoadingState label={t('entity.pivot.loading')} /> : null}
        {active && resolution.isError ? <ErrorState description={t('entity.pivot.error')} /> : null}
        {active && resolution.data ? (
          <div className={styles.result} aria-live="polite">
            <p>
              <strong>
                {t(
                  resolution.data.status === 'resolved'
                    ? 'entity.topology.status.resolved'
                    : resolution.data.status === 'conflict'
                      ? 'entity.topology.status.conflict'
                      : 'entity.topology.status.unresolved',
                )}
              </strong>{' '}
              {t('entity.pivot.result', {
                ip: active.ip,
                context: active.contextID,
                at: new Date(resolution.dataUpdatedAt).toLocaleString(),
              })}
            </p>
            {resolution.data.entity_id ? (
              <p>
                {t('entity.pivot.canonical')}: <code>{resolution.data.entity_id}</code>
              </p>
            ) : null}
            {(resolution.data.candidates ?? []).map((candidate) => (
              <p key={candidate.evidence_id}>
                {t('entity.pivot.candidate', {
                  id: candidate.entity_id,
                  source: candidate.source,
                  evidence: candidate.evidence_id,
                  at: candidate.observed_at,
                })}
              </p>
            ))}
            {resolution.data.more_candidates ? <p>{t('entity.pivot.more')}</p> : null}
          </div>
        ) : null}
      </CardBody>
    </Card>
  )
}
