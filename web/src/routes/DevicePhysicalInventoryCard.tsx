// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useContext, useState, type FormEvent } from 'react'
import { apiFetch, isApiStatus } from '../api/client'
import { useCanonicalEntities, useCanonicalEvidence, useEntityContexts } from '../api/entities'
import type {
  DevicePhysicalInventoryItem,
  DevicePhysicalInventoryPage,
  EntityEvidenceRecord,
} from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Field,
  LoadingState,
  Select,
  Table,
  type Column,
} from '../components'
import { useI18n } from '../i18n/useI18n'
import { DateTime } from '../time/DateTime'
import styles from './planes.module.css'

type Source = { agent_id: string; source_ref: string }
type Selection = Source & { context_id: string; device_entity_id: string }
type Cursor = { observation_id: string; after_index: number }
const configuredSource = 'configured-source'

export function DevicePhysicalInventoryCard() {
  const auth = useContext(AuthContext)
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  if (!auth?.permissions.includes('metrics.read') || !auth.permissions.includes('entities.read'))
    return null
  const identity = JSON.stringify([auth.tenant.id, auth.user.id, auth.permissions])
  return (
    <Card>
      <CardHeader
        title={t('device.inventory.title')}
        actions={
          !open && (
            <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
              {t('device.inventory.open')}
            </Button>
          )
        }
      />
      {open && (
        <CardBody>
          <DeviceInventorySelection key={identity} identity={identity} />
        </CardBody>
      )}
    </Card>
  )
}

function observedSources(items: EntityEvidenceRecord[]) {
  const sources = new Map<string, Source>()
  for (const { current, source_key, source_ref } of items) {
    if (
      !current ||
      source_ref !== 'snmp:physical-inventory' ||
      source_key.source_kind !== 'device_target' ||
      typeof source_key.agent_id !== 'string' ||
      typeof source_key.source_ref !== 'string'
    )
      continue
    const source = {
      agent_id: source_key.agent_id,
      source_ref: source_key.source_ref,
    }
    sources.set(JSON.stringify([source.agent_id, source.source_ref]), source)
  }
  return sources
}

function DeviceInventorySelection({ identity }: { identity: string }) {
  const { t } = useI18n()
  const [context, setContext] = useState('')
  const [device, setDevice] = useState('')
  const [source, setSource] = useState('')
  const [selection, setSelection] = useState<Selection>()
  const contexts = useEntityContexts(identity)
  const devices = useCanonicalEntities(identity, context)
  const evidence = useCanonicalEvidence(identity, context, device)
  const sources = observedSources(
    evidence.isError ? [] : (evidence.data?.pages.flatMap((page) => page.items) ?? []),
  )
  if (contexts.isLoading) return <LoadingState label={t('device.inventory.loadingContexts')} />
  if (contexts.isError) return <ErrorState description={t('device.inventory.contextError')} />

  function changeSource(value: string) {
    setSource(value)
    const selected = sources.get(value)
    setSelection(
      selected && {
        context_id: context,
        device_entity_id: device,
        ...selected,
      },
    )
  }

  function submitSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const agent = form.get('agent_id')
    const target = form.get('source_ref')
    if (typeof agent !== 'string' || typeof target !== 'string') return
    const agentID = agent.trim()
    const sourceRef = target.trim()
    if (agentID && sourceRef)
      setSelection({
        context_id: context,
        device_entity_id: device,
        agent_id: agentID,
        source_ref: sourceRef,
      })
  }

  return (
    <div className={styles.stack}>
      <Select
        label={t('device.inventory.context')}
        id="physical-inventory-context"
        value={context}
        onChange={(event) => {
          setContext(event.target.value)
          setDevice('')
          changeSource('')
        }}
        options={[
          { value: '', label: t('device.inventory.selectContext') },
          ...(contexts.data?.pages
            .flatMap((page) => page.items)
            .map((scope) => ({
              value: scope.context_id,
              label:
                [scope.site_label, scope.vrf_label].filter(Boolean).join(' / ') || scope.context_id,
            })) ?? []),
        ]}
      />
      {contexts.hasNextPage && (
        <Button
          size="sm"
          variant="secondary"
          disabled={contexts.isFetchingNextPage}
          onClick={() => void contexts.fetchNextPage()}
        >
          {t('device.inventory.moreContexts')}
        </Button>
      )}
      {context && devices.isLoading && (
        <LoadingState label={t('device.inventory.loadingDevices')} />
      )}
      {context && devices.isError && <ErrorState description={t('device.inventory.deviceError')} />}
      {devices.data && (
        <Select
          label={t('planes.device.column.device')}
          id="physical-inventory-device"
          value={device}
          onChange={(event) => {
            setDevice(event.target.value)
            changeSource('')
          }}
          options={[
            { value: '', label: t('device.inventory.selectDevice') },
            ...devices.data.pages
              .flatMap((page) => page.items)
              .filter((row) => row.kind === 'device')
              .map((row) => ({ value: row.id, label: row.label || row.id })),
          ]}
        />
      )}
      {devices.hasNextPage && (
        <Button
          size="sm"
          variant="secondary"
          disabled={devices.isFetchingNextPage}
          onClick={() => void devices.fetchNextPage()}
        >
          {t('device.inventory.moreDevices')}
        </Button>
      )}
      {device && evidence.isError && (
        <ErrorState
          description={t('device.inventory.sourceError')}
          action={
            <Button size="sm" variant="secondary" onClick={() => void evidence.refetch()}>
              {t('device.inventory.retrySources')}
            </Button>
          }
        />
      )}
      {device && (
        <Select
          label={t('device.inventory.source')}
          id="physical-inventory-source"
          value={source}
          onChange={(event) => changeSource(event.target.value)}
          options={[
            {
              value: '',
              label: t(
                evidence.isLoading
                  ? 'device.inventory.loadingSources'
                  : 'device.inventory.selectSource',
              ),
            },
            ...Array.from(sources, ([value, target]) => ({
              value,
              label: target.source_ref + ' · ' + target.agent_id,
            })),
            {
              value: configuredSource,
              label: t('device.inventory.enterSource'),
            },
          ]}
        />
      )}
      {evidence.hasNextPage && !evidence.isError && (
        <Button
          size="sm"
          variant="secondary"
          disabled={evidence.isFetchingNextPage}
          onClick={() => void evidence.fetchNextPage()}
        >
          {t('device.inventory.moreSources')}
        </Button>
      )}
      {source === configuredSource && (
        <form className={styles.stack} onSubmit={submitSource}>
          <Field
            label={t('device.inventory.agent')}
            name="agent_id"
            required
            maxLength={128}
            dir="ltr"
          />
          <Field
            label={t('device.inventory.sourceRef')}
            name="source_ref"
            required
            maxLength={1024}
            dir="ltr"
          />
          <Button type="submit" size="sm">
            {t('device.inventory.open')}
          </Button>
        </form>
      )}
      {selection && (
        <InventoryResults
          key={JSON.stringify(selection)}
          identity={identity}
          selection={selection}
        />
      )}
    </div>
  )
}

function InventoryResults({ identity, selection }: { identity: string; selection: Selection }) {
  const { t } = useI18n()
  const [trail, setTrail] = useState<Cursor[]>([])
  const client = useQueryClient()
  const key = ['physical-inventory', identity, selection]
  const last = trail.at(-1)
  const query = useQuery({
    queryKey: [...key, last],
    gcTime: 0,
    staleTime: 0,
    queryFn: ({ signal }) => {
      const query = new URLSearchParams(selection)
      if (last) {
        query.set('observation_id', last.observation_id)
        query.set('after_index', String(last.after_index))
      }
      return apiFetch<DevicePhysicalInventoryPage>(`/device/physical-inventory?${query}`, {
        signal,
      })
    },
    retry: false,
  })
  if (query.isPending) return <LoadingState label={t('device.inventory.loading')} />
  if (query.isError) {
    if (isApiStatus(query.error, 409))
      return (
        <div className={styles.stack}>
          <ErrorState description={t('device.inventory.pollChanged')} />
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              client.removeQueries({ queryKey: [...key, undefined], exact: true })
              setTrail([])
            }}
          >
            {t('device.inventory.latest')}
          </Button>
        </div>
      )
    return <ErrorState description={t('device.inventory.unavailable')} />
  }
  const page = query.data
  const columns: Column<DevicePhysicalInventoryItem>[] = [
    {
      key: 'index',
      header: t('device.inventory.component'),
      render: (row) => (
        <div>
          <strong>{row.index}</strong>
          <div>{t('device.inventory.class', { value: row.class })}</div>
          {row.parent != null && <div>{t('device.inventory.parent', { value: row.parent })}</div>}
        </div>
      ),
    },
    {
      key: 'model',
      header: t('device.inventory.model'),
      render: (row) => (
        <div>
          <strong>{row.model || t('device.inventory.unknown')}</strong>
          {row.manufacturer && <div>{row.manufacturer}</div>}
          {row.serial && (
            <div>
              {t('device.inventory.serial')} <code dir="ltr">{row.serial}</code>
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'versions',
      header: t('device.inventory.revisions'),
      render: (row) => (
        <ul>
          <li>
            {t('device.inventory.hardware')} {row.hardware || t('device.inventory.unknown')}
          </li>
          <li>
            {t('device.inventory.firmware')} {row.firmware || t('device.inventory.unknown')}
          </li>
          <li>
            {t('device.inventory.software')} {row.software || t('device.inventory.unknown')}
          </li>
        </ul>
      ),
    },
    {
      key: 'lifecycle',
      header: t('device.inventory.lifecycle'),
      render: (row) => <LifecycleEvidence row={row} />,
    },
    {
      key: 'cves',
      header: t('device.inventory.vulnerabilities'),
      render: (row) => <VulnerabilityEvidence row={row} />,
    },
  ]
  return (
    <div className={styles.stack}>
      <p>
        {t('device.inventory.observed')} <DateTime value={page.observed_at} />
      </p>
      {page.available ? (
        <Table
          caption={t('device.inventory.title')}
          columns={columns}
          rows={page.items}
          rowKey={(row) => String(row.index)}
          maxRows={16}
          empty={t('device.inventory.noRows')}
        />
      ) : (
        <p role="status">{t('device.inventory.unavailablePoll')}</p>
      )}
      {(trail.length > 0 || page.next_index !== undefined) && (
        <div className={styles.configDiffSummary}>
          {trail.length > 0 && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setTrail((prior) => prior.slice(0, -1))}
            >
              {t('device.inventory.previous')}
            </Button>
          )}
          {page.next_index !== undefined && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => {
                const index = page.next_index
                if (index !== undefined)
                  setTrail((prior) => [
                    ...prior,
                    { observation_id: page.observation_id, after_index: index },
                  ])
              }}
            >
              {t('device.inventory.next')}
            </Button>
          )}
        </div>
      )}
    </div>
  )
}

function LifecycleEvidence({ row }: { row: DevicePhysicalInventoryItem }) {
  const { t } = useI18n()
  const evidence = row.references.lifecycle
  if (!evidence) return t('device.inventory.lifecycleUnknown')
  const { notice, source_date } = evidence
  return (
    <ul>
      {notice.end_of_sale && (
        <li>
          {t('device.inventory.endOfSale')}{' '}
          <time dateTime={notice.end_of_sale}>{notice.end_of_sale}</time>
        </li>
      )}
      {notice.end_of_security_fixes && (
        <li>
          {t('device.inventory.endOfFixes')}{' '}
          <time dateTime={notice.end_of_security_fixes}>{notice.end_of_security_fixes}</time>
        </li>
      )}
      {notice.end_of_support && (
        <li>
          {t('device.inventory.endOfSupport')}{' '}
          <time dateTime={notice.end_of_support}>{notice.end_of_support}</time>
        </li>
      )}
      <li>
        <a className="underline" href={notice.notice_url} rel="noreferrer" target="_blank">
          {t('device.inventory.notice')}
        </a>{' '}
        <time dateTime={notice.notice_published_at}>{notice.notice_published_at}</time>
      </li>
      <li>
        {t('device.inventory.snapshot')} <time dateTime={source_date}>{source_date}</time>
      </li>
    </ul>
  )
}

function VulnerabilityEvidence({ row }: { row: DevicePhysicalInventoryItem }) {
  const { t } = useI18n()
  const refs = row.references
  if (refs.vulnerability_coverage === 'unavailable') return t('device.inventory.coverageUnknown')
  return (
    <div>
      {refs.vulnerability_coverage === 'partial' && <p>{t('device.inventory.coveragePartial')}</p>}
      {refs.nvd_source_date && (
        <p>
          {t('device.inventory.snapshot')} <DateTime value={refs.nvd_source_date} />
        </p>
      )}
      {refs.vulnerabilities?.length ? (
        <ul>
          {refs.vulnerabilities.map((finding) => (
            <li key={JSON.stringify([finding.id, finding.version_field])}>
              <a className="underline" href={finding.nvd_source} rel="noreferrer" target="_blank">
                {finding.id}
              </a>{' '}
              {t(
                finding.version_field === 'firmware'
                  ? 'device.inventory.firmware'
                  : 'device.inventory.software',
              )}{' '}
              <code dir="ltr">{finding.observed_version}</code>
              {finding.kev_source && finding.kev_added_at && (
                <div>
                  <a
                    className="underline"
                    href={finding.kev_source}
                    rel="noreferrer"
                    target="_blank"
                  >
                    {t('device.inventory.kev')}
                  </a>{' '}
                  <time dateTime={finding.kev_added_at}>{finding.kev_added_at}</time>
                  {finding.kev_source_date && (
                    <div>
                      {t('device.inventory.snapshot')} <DateTime value={finding.kev_source_date} />
                    </div>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p>{t('device.inventory.noFindings')}</p>
      )}
      {refs.vulnerabilities_truncated && <p>{t('device.inventory.truncated')}</p>}
    </div>
  )
}
