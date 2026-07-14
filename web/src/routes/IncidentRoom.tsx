// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import styles from './incidentRoom.module.css'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  StatusDot,
  Table,
  useToast,
  type Column,
} from '../components'
import {
  severityTone,
  useCreateIncidentShare,
  useIncident,
  useIncidentChanges,
  useResolveIncident,
  type ChangeCandidate,
  type Incident,
  type Signal,
} from '../api/incidents'
import { useCreateRemediationProposal, useRemediations } from '../api/remediation'
import {
  incidentTarget,
  proposalFromAnswer,
  proposalFromIncident,
  questionForIncident,
} from '../remediation/proposalContext'
import { DateTime } from '../time/DateTime'
import { useI18n } from '../i18n/useI18n'
import type { MessageKey } from '../i18n/messages'
import { replacePivotContext, type PivotContext } from './pivotContext'
import { ExplainView } from './ExplainView'
import type { Answer, Evidence } from '../api/ai'

interface PlaneGroup {
  id: string
  labelKey: MessageKey
  aliases: ReadonlySet<string>
}

const PLANE_GROUPS: PlaneGroup[] = [
  {
    id: 'synthetic',
    labelKey: 'incidents.room.plane.synthetic',
    aliases: new Set(['network', 'synthetic', 'path', 'canary']),
  },
  {
    id: 'routing',
    labelKey: 'incidents.room.plane.routing',
    aliases: new Set(['bgp', 'routing']),
  },
  {
    id: 'flow',
    labelKey: 'incidents.room.plane.flow',
    aliases: new Set(['flow']),
  },
  {
    id: 'device',
    labelKey: 'incidents.room.plane.device',
    aliases: new Set(['device', 'telemetry', 'snmp', 'syslog']),
  },
  {
    id: 'host',
    labelKey: 'incidents.room.plane.host',
    aliases: new Set(['ebpf', 'endpoint', 'host', 'l7']),
  },
]

interface SignalRow {
  id: string
  index: number
  signal: Signal
}

interface ClockItem {
  id: string
  plane: string
  title: string
  occurredAt: string
}

function signalID(incidentID: string, index: number): string {
  // This is the same source row id emitted by incidentEntitiesSource for AI
  // evidence, so one X3 selection coordinates the timeline and citations.
  return `${incidentID}:${index}`
}

function sourceIDForSelection(context: PivotContext): string | undefined {
  if (context.selection?.kind !== 'evidence') return undefined
  return context.selection.id
}

function entityValues(incident: Incident): string[] {
  const values = new Set<string>()
  const add = (value: string | undefined) => {
    const clean = value?.trim()
    if (clean) values.add(clean)
  }
  add(incident.target)
  add(incident.prefix)
  for (const signal of incident.signals ?? []) {
    add(signal.target)
    add(signal.prefix)
    for (const key of ['service', 'device', 'node', 'agent_id', 'host']) {
      add(signal.attributes?.[key])
    }
  }
  return Array.from(values)
}

export function IncidentRoom({
  incidentId,
  pivotContext,
  incidentSnapshot,
  sharedAnswer,
  sharedArtifactID,
  sharedExpiresAt,
}: {
  incidentId: string
  pivotContext: PivotContext
  incidentSnapshot?: Incident
  sharedAnswer?: Answer
  sharedArtifactID?: string
  sharedExpiresAt?: string
}) {
  const { t } = useI18n()
  const [params, setParams] = useSearchParams()
  const incident = useIncident(incidentSnapshot ? undefined : incidentId)
  const changes = useIncidentChanges(incidentSnapshot ? undefined : incidentId)
  const resolve = useResolveIncident(incidentId)
  const remediations = useRemediations(!sharedArtifactID)
  const createProposal = useCreateRemediationProposal()
  const createShare = useCreateIncidentShare(incidentId)
  const { push } = useToast()
  const [explanation, setExplanation] = useState<Answer | undefined>(sharedAnswer)
  const [shareLink, setShareLink] = useState<string>()

  useEffect(() => setExplanation(sharedAnswer), [sharedAnswer])

  const inc = incidentSnapshot ?? incident.data
  const signalRows = useMemo<SignalRow[]>(
    () =>
      (inc?.signals ?? []).map((signal, index) => ({
        id: signalID(incidentId, index),
        index,
        signal,
      })),
    [inc?.signals, incidentId],
  )
  const selectedSourceID = sourceIDForSelection(pivotContext)
  const selectedSignal = signalRows.find((row) => row.id === selectedSourceID)
  const selectedChange = changes.data?.find((candidate) => candidate.event.id === selectedSourceID)
  const clockItems = useMemo<ClockItem[]>(() => {
    const items = signalRows.map((row) => ({
      id: row.id,
      plane: row.signal.plane,
      title: row.signal.title || row.signal.kind,
      occurredAt: row.signal.occurred_at,
    }))
    for (const candidate of changes.data ?? []) {
      items.push({
        id: candidate.event.id,
        plane: 'change',
        title: candidate.event.title,
        occurredAt: candidate.event.occurred_at,
      })
    }
    return items.sort((a, b) => a.occurredAt.localeCompare(b.occurredAt))
  }, [changes.data, signalRows])

  if (!incidentSnapshot && incident.isLoading)
    return <LoadingState label={t('incidents.loadingOne')} />
  if ((!incidentSnapshot && incident.isError) || !inc)
    return <ErrorState description={t('incidents.errorOne')} headingLevel={2} />
  const roomIncident = inc

  const canPropose = Boolean(remediations.data)
  const entities = entityValues(inc)
  const knownPlanes = new Set(PLANE_GROUPS.flatMap((group) => Array.from(group.aliases)))
  const otherSignals = signalRows.filter(
    (row) => !knownPlanes.has(row.signal.plane.toLowerCase()) && row.signal.plane !== 'change',
  )

  function selectEvidence(id: string) {
    setParams(
      replacePivotContext(params, {
        ...pivotContext,
        incidentId: roomIncident.id,
        from: roomIncident.started_at,
        to: roomIncident.last_seen_at,
        selection: { kind: 'evidence', id },
      }),
    )
  }

  function selectExplanationEvidence(evidence: Evidence) {
    const sourceID = evidence.fields?.id
    if (typeof sourceID === 'string' && sourceID) selectEvidence(sourceID)
  }

  function proposeIncidentReview() {
    const proposal = explanation
      ? proposalFromAnswer(explanation, {
          incidentID: roomIncident.id,
          target: incidentTarget(roomIncident),
        })
      : proposalFromIncident(roomIncident)
    createProposal.mutate(proposal, {
      onSuccess: (proposal) =>
        push({
          tone: 'success',
          title: t('incidents.toast.proposalCreated'),
          message: t('incidents.toast.proposalCreatedMessage', { id: proposal.id }),
        }),
      onError: (error) =>
        push({
          tone: 'danger',
          title: t('incidents.toast.proposalFailed'),
          message:
            error instanceof Error ? error.message : t('incidents.toast.proposalFailedMessage'),
        }),
    })
  }

  function copyCitedShareLink() {
    createShare.mutate(
      {
        context: {
          from: pivotContext.from ?? roomIncident.started_at,
          to: pivotContext.to ?? roomIncident.last_seen_at,
          filters: pivotContext.filters,
          ...(pivotContext.selection ? { selection: pivotContext.selection } : {}),
        },
      },
      {
        onSuccess: (artifact) => {
          const url = new URL('/incidents', window.location.origin)
          url.searchParams.set('share', artifact.id)
          const stableLink = url.toString()
          setShareLink(stableLink)
          void navigator.clipboard?.writeText(stableLink).catch(() => undefined)
          push({
            tone: 'success',
            title: t('incidents.share.copied'),
            message: t('incidents.share.expires', { expires: artifact.expires_at }),
          })
        },
        onError: () =>
          push({
            tone: 'danger',
            title: t('incidents.share.failed'),
            message: t('incidents.share.failedDescription'),
          }),
      },
    )
  }

  return (
    <section className={styles.room} aria-label={t('incidents.room.aria')}>
      <Card>
        <CardHeader
          title={inc.title || inc.target || t('incidents.fallbackTitle')}
          actions={
            <div className={styles.actions}>
              {inc.status === 'open' ? (
                <Badge tone="warning">{t('incidents.status.open')}</Badge>
              ) : (
                <Badge tone="neutral">{t('incidents.status.resolved')}</Badge>
              )}
            </div>
          }
        />
        <CardBody>
          <dl className={styles.summaryGrid}>
            <div>
              <dt>{t('incidents.meta.severity')}</dt>
              <dd>
                <Badge tone={severityTone(inc.severity)}>{inc.severity}</Badge>
              </dd>
            </div>
            <div>
              <dt>{t('incidents.meta.target')}</dt>
              <dd>{inc.target || inc.prefix || '—'}</dd>
            </div>
            <div>
              <dt>{t('incidents.meta.signals')}</dt>
              <dd>{inc.signal_count}</dd>
            </div>
            <div>
              <dt>{t('incidents.meta.started')}</dt>
              <dd>
                <DateTime value={inc.started_at} />
              </dd>
            </div>
            <div>
              <dt>{t('incidents.meta.lastActivity')}</dt>
              <dd>
                <DateTime value={inc.last_seen_at} />
              </dd>
            </div>
          </dl>
          {inc.signals_truncated ? (
            <p className={styles.coverageWarning} role="status">
              {t('incidents.room.coverage.truncated', {
                returned: inc.signals?.length ?? 0,
                total: inc.signal_count,
              })}
            </p>
          ) : null}
        </CardBody>
      </Card>

      <ExplainView
        surface="incident"
        question={questionForIncident(roomIncident)}
        subject={{
          incident_id: roomIncident.id,
          target: incidentTarget(roomIncident),
          prefix: roomIncident.prefix,
        }}
        pivotContext={{
          ...pivotContext,
          incidentId: roomIncident.id,
          from: roomIncident.started_at,
          to: roomIncident.last_seen_at,
        }}
        onEvidenceSelect={selectExplanationEvidence}
        onAnswer={setExplanation}
        initialAnswer={sharedAnswer}
      />

      {sharedArtifactID ? (
        <Card>
          <CardHeader title={t('incidents.share.snapshot')} />
          <CardBody>
            <p className={styles.nextStep}>
              {t('incidents.share.snapshotDescription', { expires: sharedExpiresAt ?? '' })}
            </p>
            <dl className={styles.summaryGrid}>
              <div>
                <dt>{t('incidents.share.from')}</dt>
                <dd>{pivotContext.from ? <DateTime value={pivotContext.from} /> : '—'}</dd>
              </div>
              <div>
                <dt>{t('incidents.share.to')}</dt>
                <dd>{pivotContext.to ? <DateTime value={pivotContext.to} /> : '—'}</dd>
              </div>
              <div>
                <dt>{t('incidents.share.filters')}</dt>
                <dd>
                  {Object.entries(pivotContext.filters).length > 0
                    ? Object.entries(pivotContext.filters)
                        .sort(([left], [right]) => left.localeCompare(right))
                        .map(([key, value]) => <code key={key}>{`${key}=${value}`}</code>)
                    : '—'}
                </dd>
              </div>
              <div>
                <dt>{t('incidents.share.selection')}</dt>
                <dd>{pivotContext.selection ? <code>{pivotContext.selection.id}</code> : '—'}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>
      ) : explanation ? (
        <Card>
          <CardHeader title={t('incidents.share.title')} />
          <CardBody>
            <p className={styles.nextStep}>{t('incidents.share.description')}</p>
            <div className={styles.actions}>
              <Button
                variant="secondary"
                onClick={copyCitedShareLink}
                disabled={createShare.isPending}
              >
                {createShare.isPending ? t('incidents.share.creating') : t('incidents.share.copy')}
              </Button>
              {shareLink ? <a href={shareLink}>{t('incidents.share.open')}</a> : null}
            </div>
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardHeader
          title={t('incidents.room.clock.title')}
          description={t('incidents.room.clock.description')}
        />
        <CardBody>
          <ol className={styles.clock} aria-label={t('incidents.room.clock.aria')}>
            {clockItems.map((item) => (
              <li key={`${item.plane}:${item.id}`}>
                <Button
                  size="sm"
                  variant={selectedSourceID === item.id ? 'primary' : 'ghost'}
                  aria-pressed={selectedSourceID === item.id}
                  onClick={() => selectEvidence(item.id)}
                >
                  <DateTime value={item.occurredAt} />
                  <span>{item.plane}</span>
                </Button>
              </li>
            ))}
          </ol>
        </CardBody>
      </Card>

      <div className={styles.workspace}>
        <div className={styles.evidenceColumn}>
          <Card>
            <CardHeader
              title={t('incidents.room.evidence.title')}
              description={t('incidents.room.evidence.description')}
            />
            <CardBody>
              <div className={styles.planeGroups}>
                {PLANE_GROUPS.map((group) => {
                  const rows = signalRows.filter((row) =>
                    group.aliases.has(row.signal.plane.toLowerCase()),
                  )
                  return (
                    <PlaneEvidence
                      key={group.id}
                      label={t(group.labelKey)}
                      rows={rows}
                      selectedID={selectedSourceID}
                      onSelect={selectEvidence}
                      t={t}
                    />
                  )
                })}
                {otherSignals.length > 0 ? (
                  <PlaneEvidence
                    label={t('incidents.room.plane.other')}
                    rows={otherSignals}
                    selectedID={selectedSourceID}
                    onSelect={selectEvidence}
                    t={t}
                  />
                ) : null}
              </div>
            </CardBody>
          </Card>

          {!sharedArtifactID ? (
            <ChangeEvidence
              candidates={changes.data}
              isLoading={changes.isLoading}
              isError={changes.isError}
              selectedID={selectedSourceID}
              onSelect={selectEvidence}
              t={t}
            />
          ) : null}
        </div>

        <div className={styles.inspectorColumn} aria-label={t('incidents.room.inspector.aria')}>
          <Card>
            <CardHeader title={t('incidents.room.entities.title')} />
            <CardBody>
              {entities.length > 0 ? (
                <ul className={styles.entities}>
                  {entities.map((entity) => (
                    <li key={entity}>
                      <Badge tone="neutral">{entity}</Badge>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className={styles.coverageWarning}>{t('incidents.room.entities.empty')}</p>
              )}
            </CardBody>
          </Card>

          <EvidenceInspector signal={selectedSignal?.signal} change={selectedChange} t={t} />

          {!sharedArtifactID ? (
            <Card>
              <CardHeader title={t('incidents.room.next.title')} />
              <CardBody>
                <p className={styles.nextStep}>{t('incidents.room.next.description')}</p>
                <p className={styles.safety}>{t('incidents.room.next.safety')}</p>
                <div className={styles.actions}>
                  {canPropose ? (
                    <Button
                      variant="secondary"
                      onClick={proposeIncidentReview}
                      disabled={createProposal.isPending}
                    >
                      {createProposal.isPending
                        ? t('incidents.action.proposing')
                        : t('incidents.action.propose')}
                    </Button>
                  ) : null}
                  {inc.status === 'open' ? (
                    <Button
                      variant="secondary"
                      onClick={() => resolve.mutate()}
                      disabled={resolve.isPending}
                    >
                      {t('incidents.action.resolve')}
                    </Button>
                  ) : null}
                </div>
              </CardBody>
            </Card>
          ) : null}
        </div>
      </div>
    </section>
  )
}

function PlaneEvidence({
  label,
  rows,
  selectedID,
  onSelect,
  t,
}: {
  label: string
  rows: SignalRow[]
  selectedID?: string
  onSelect: (id: string) => void
  t: (key: MessageKey, vars?: Record<string, string | number>) => string
}) {
  const columns: Column<SignalRow>[] = [
    {
      key: 'time',
      header: t('incidents.room.column.time'),
      render: (row) => <DateTime value={row.signal.occurred_at} />,
    },
    {
      key: 'evidence',
      header: t('incidents.room.column.evidence'),
      render: (row) => (
        <Button
          size="sm"
          variant={selectedID === row.id ? 'primary' : 'ghost'}
          aria-pressed={selectedID === row.id}
          onClick={() => onSelect(row.id)}
        >
          {row.signal.title || row.signal.kind}
        </Button>
      ),
    },
    {
      key: 'kind',
      header: t('incidents.room.column.kind'),
      render: (row) => <code>{row.signal.kind}</code>,
    },
    {
      key: 'severity',
      header: t('incidents.column.severity'),
      render: (row) => (
        <StatusDot tone={severityTone(row.signal.severity)} label={row.signal.severity} />
      ),
    },
  ]
  return (
    <section className={styles.planeGroup} aria-label={label}>
      <h3>{label}</h3>
      {rows.length > 0 ? (
        <Table
          caption={t('incidents.room.table.caption', { plane: label })}
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          maxRows={100}
        />
      ) : (
        <p className={styles.coverageGap} role="status">
          {t('incidents.room.coverage.missing', { plane: label })}
        </p>
      )}
    </section>
  )
}

function ChangeEvidence({
  candidates,
  isLoading,
  isError,
  selectedID,
  onSelect,
  t,
}: {
  candidates?: ChangeCandidate[]
  isLoading: boolean
  isError: boolean
  selectedID?: string
  onSelect: (id: string) => void
  t: (key: MessageKey, vars?: Record<string, string | number>) => string
}) {
  return (
    <Card>
      <CardHeader
        title={t('incidents.room.changes.title')}
        description={t('incidents.room.changes.description')}
      />
      <CardBody>
        {isLoading ? (
          <LoadingState label={t('incidents.room.changes.loading')} />
        ) : isError ? (
          <p className={styles.coverageGap} role="status">
            {t('incidents.room.changes.error')}
          </p>
        ) : !candidates || candidates.length === 0 ? (
          <p className={styles.coverageGap} role="status">
            {t('incidents.room.changes.empty')}
          </p>
        ) : (
          <ol className={styles.changes}>
            {candidates.map((candidate) => (
              <li key={candidate.event.id}>
                <Button
                  variant={selectedID === candidate.event.id ? 'primary' : 'ghost'}
                  aria-pressed={selectedID === candidate.event.id}
                  onClick={() => onSelect(candidate.event.id)}
                >
                  {candidate.event.title}
                </Button>
                <span>{t('incidents.room.changes.score', { score: candidate.score })}</span>
                <span>{candidate.reason}</span>
                <DateTime value={candidate.event.occurred_at} />
              </li>
            ))}
          </ol>
        )}
      </CardBody>
    </Card>
  )
}

function EvidenceInspector({
  signal,
  change,
  t,
}: {
  signal?: Signal
  change?: ChangeCandidate
  t: (key: MessageKey, vars?: Record<string, string | number>) => string
}) {
  return (
    <Card>
      <CardHeader title={t('incidents.room.inspector.title')} />
      <CardBody>
        {signal ? (
          <dl className={styles.inspector}>
            <div>
              <dt>{t('incidents.room.inspector.plane')}</dt>
              <dd>{signal.plane}</dd>
            </div>
            <div>
              <dt>{t('incidents.room.column.kind')}</dt>
              <dd>{signal.kind}</dd>
            </div>
            <div>
              <dt>{t('incidents.room.column.time')}</dt>
              <dd>
                <DateTime value={signal.occurred_at} />
              </dd>
            </div>
            <div>
              <dt>{t('incidents.meta.target')}</dt>
              <dd>{signal.target || signal.prefix || '—'}</dd>
            </div>
            {signal.summary ? (
              <div>
                <dt>{t('incidents.room.inspector.summary')}</dt>
                <dd>{signal.summary}</dd>
              </div>
            ) : null}
          </dl>
        ) : change ? (
          <dl className={styles.inspector}>
            <div>
              <dt>{t('incidents.room.inspector.plane')}</dt>
              <dd>{t('incidents.room.changes.title')}</dd>
            </div>
            <div>
              <dt>{t('incidents.room.column.kind')}</dt>
              <dd>{change.event.kind}</dd>
            </div>
            <div>
              <dt>{t('incidents.room.column.time')}</dt>
              <dd>
                <DateTime value={change.event.occurred_at} />
              </dd>
            </div>
            <div>
              <dt>{t('incidents.room.inspector.summary')}</dt>
              <dd>{change.reason}</dd>
            </div>
          </dl>
        ) : (
          <EmptyState
            title={t('incidents.room.inspector.emptyTitle')}
            description={t('incidents.room.inspector.emptyDescription')}
          />
        )}
      </CardBody>
    </Card>
  )
}
