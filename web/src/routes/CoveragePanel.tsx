// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Field,
  HonestDataState,
  LoadingState,
  Select,
  StatusDot,
  Table,
  classifySurfaceTruth,
  type BadgeTone,
  type Column,
} from '../components'
import {
  useCoverageDebt,
  useCoverageMatrix,
  type CoverageDebtItem,
  type CoverageDebtPlane,
  type CoverageDebtState,
  type CoverageMatrixItem,
  type CoverageStatus,
  type ExecutionCadenceReason,
  type ExecutionCadenceState,
} from '../api/coverage'
import { DateTime } from '../time/DateTime'
import { formatInteger } from '../i18n/number'
import { useI18n } from '../i18n/useI18n'
import type { I18nContextValue } from '../i18n/context'
import type { MessageKey } from '../i18n/messages'
import styles from './pages.module.css'
import { FilterBar } from './listControls'

const statusLabels: Record<CoverageStatus, string> = {
  uncovered: 'Uncovered',
  stale: 'Stale',
  non_redundant: 'Non-redundant',
  covered: 'Covered',
}

const statusTones: Record<CoverageStatus, BadgeTone> = {
  uncovered: 'danger',
  stale: 'warning',
  non_redundant: 'warning',
  covered: 'success',
}

const cadenceLabelKeys: Record<ExecutionCadenceState, MessageKey> = {
  on_cadence: 'coverage.cadence.state.onCadence',
  gaps_observed: 'coverage.cadence.state.gapsObserved',
  never_observed: 'coverage.cadence.state.neverObserved',
  unknown: 'coverage.cadence.state.unknown',
}

const cadenceTones: Record<ExecutionCadenceState, BadgeTone> = {
  on_cadence: 'success',
  gaps_observed: 'danger',
  never_observed: 'warning',
  unknown: 'neutral',
}

const cadenceReasonKeys: Record<ExecutionCadenceReason, MessageKey> = {
  on_cadence: 'coverage.cadence.reason.onCadence',
  missed_rounds: 'coverage.cadence.reason.missedRounds',
  no_exact_test_evidence: 'coverage.cadence.reason.noExactTestEvidence',
  evidence_unwired: 'coverage.cadence.reason.evidenceUnwired',
  legacy_or_unattributed_evidence: 'coverage.cadence.reason.legacyOrUnattributedEvidence',
  legacy_schedule_metadata: 'coverage.cadence.reason.legacyScheduleMetadata',
  interval_mismatch: 'coverage.cadence.reason.intervalMismatch',
  history_truncated: 'coverage.cadence.reason.historyTruncated',
  insufficient_history: 'coverage.cadence.reason.insufficientHistory',
  future_evidence_timestamp: 'coverage.cadence.reason.futureEvidenceTimestamp',
  definition_mismatch: 'coverage.cadence.reason.definitionMismatch',
  invalid_configured_interval: 'coverage.cadence.reason.invalidConfiguredInterval',
}

function formatCadenceDuration(seconds: number, locale: string, t: I18nContextValue['t']): string {
  if (seconds < 60)
    return t('coverage.cadence.duration.seconds', { count: formatInteger(seconds, locale) })
  if (seconds < 3600 && seconds % 60 === 0)
    return t('coverage.cadence.duration.minutes', {
      count: formatInteger(seconds / 60, locale),
    })
  if (seconds < 86400 && seconds % 3600 === 0)
    return t('coverage.cadence.duration.hours', {
      count: formatInteger(seconds / 3600, locale),
    })
  return t('coverage.cadence.duration.seconds', { count: formatInteger(seconds, locale) })
}

function CadenceReceipt({ item }: { item: CoverageMatrixItem }) {
  const navigate = useNavigate()
  const { locale, t } = useI18n()
  const cadence = item.execution_cadence
  const observed = formatInteger(cadence.observed_rounds, locale)
  const expected = formatInteger(cadence.expected_rounds, locale)
  const missed = formatInteger(cadence.missed_rounds, locale)
  const agents = formatInteger(cadence.observed_agent_count, locale)
  const operatorAction =
    cadence.state === 'on_cadence'
      ? null
      : `/targets?test_id=${encodeURIComponent(item.test_id)}#tests`

  return (
    <span className={styles.fleetCell} data-cadence-receipt data-test-id={item.test_id}>
      <StatusDot tone={cadenceTones[cadence.state]} label={t(cadenceLabelKeys[cadence.state])} />
      <small>{t(cadenceReasonKeys[cadence.reason])}</small>
      <small>
        {t('coverage.cadence.rounds', { observed, expected })} ·{' '}
        {t(
          cadence.missed_rounds === 1
            ? 'coverage.cadence.missed.one'
            : 'coverage.cadence.missed.other',
          { count: missed },
        )}{' '}
        ·{' '}
        {t('coverage.cadence.largestGap', {
          duration: formatCadenceDuration(cadence.max_gap_seconds, locale, t),
        })}
      </small>
      <small>
        {t('coverage.cadence.window', {
          duration: formatCadenceDuration(cadence.window_seconds, locale, t),
        })}{' '}
        ·{' '}
        {t(
          cadence.history_complete
            ? 'coverage.cadence.history.complete'
            : 'coverage.cadence.history.incomplete',
        )}{' '}
        ·{' '}
        {t(
          cadence.observed_agent_count === 1
            ? 'coverage.cadence.agent.one'
            : 'coverage.cadence.agent.other',
          { count: agents },
        )}
      </small>
      {!cadence.current_assignment_verified ? (
        <small>{t('coverage.cadence.assignmentCaveat')}</small>
      ) : null}
      {operatorAction ? (
        <Button size="sm" variant="secondary" onClick={() => void navigate(operatorAction)}>
          {t('coverage.cadence.inspectTest', { name: item.test_name, id: item.test_id })}
        </Button>
      ) : null}
    </span>
  )
}

export function CoveragePanel({ canCreateTest }: { canCreateTest: boolean }) {
  const navigate = useNavigate()
  const { locale, t } = useI18n()
  const { data, isPending, isError, error, refetch } = useCoverageMatrix()
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<CoverageStatus | 'all'>('all')
  const [region, setRegion] = useState('all')

  const regions = useMemo(
    () => [...new Set((data?.items ?? []).map((item) => item.region))].sort(),
    [data?.items],
  )
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return (data?.items ?? []).filter((item) => {
      const haystack = [item.test_name, item.region, item.site, item.probe_family, item.target]
        .join(' ')
        .toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (status === 'all' || item.status === status) &&
        (region === 'all' || item.region === region)
      )
    })
  }, [data?.items, query, region, status])

  const columns: Column<CoverageMatrixItem>[] = [
    {
      key: 'status',
      header: 'Coverage',
      render: (item) => (
        <span className={styles.fleetCell}>
          <StatusDot tone={statusTones[item.status]} label={statusLabels[item.status]} />
          {item.next_action ? (
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void navigate(item.next_action!.href)}
            >
              {item.next_action.label}
            </Button>
          ) : (
            <Badge tone="success">No gap</Badge>
          )}
        </span>
      ),
    },
    {
      key: 'location',
      header: 'Owned vantage',
      render: (item) => (
        <span className={styles.fleetCell}>
          <strong>{item.site}</strong>
          <small>{item.region}</small>
          <StatusDot
            tone={
              item.agent_readiness === 'ready'
                ? 'success'
                : item.agent_readiness === 'degraded'
                  ? 'warning'
                  : 'danger'
            }
            label={`${item.agent_readiness} · ${item.ready_agent_count}/${item.agent_count} ready`}
          />
        </span>
      ),
    },
    {
      key: 'target',
      header: 'Probe / target',
      render: (item) => (
        <span className={styles.fleetCell}>
          <strong>{item.test_name}</strong>
          <Badge tone="neutral">{item.probe_family}</Badge>
          <code>{item.target || '—'}</code>
        </span>
      ),
    },
    {
      key: 'evidence',
      header: 'Evidence',
      render: (item) => (
        <span className={styles.fleetCell}>
          {item.last_evidence_at ? <DateTime value={item.last_evidence_at} /> : 'Never'}
          <small>
            {item.independent_vantage_count}{' '}
            {item.independent_vantage_count === 1 ? 'independent vantage' : 'independent vantages'}
          </small>
        </span>
      ),
    },
    {
      key: 'cadence',
      header: t('coverage.cadence.column'),
      render: (item) => <CadenceReceipt item={item} />,
    },
  ]

  const gapCount = (data?.items ?? []).filter((item) => item.status !== 'covered').length
  const cadenceGapCount = (data?.items ?? []).filter(
    (item) => item.execution_cadence.state === 'gaps_observed',
  ).length
  return (
    <>
      <Card data-targets-coverage>
        <CardHeader
          title="Owned-vantage coverage"
          description="Local agent labels × enabled tests × recent evidence. Region and site are operator-declared; no geolocation or external service is used."
          actions={
            data ? (
              <span className={styles.fleetBadges}>
                <Badge tone={gapCount > 0 ? 'warning' : 'success'}>
                  {gapCount} {gapCount === 1 ? 'gap' : 'gaps'}
                </Badge>
                <Badge tone={cadenceGapCount > 0 ? 'danger' : 'neutral'}>
                  {t(
                    cadenceGapCount === 1
                      ? 'coverage.cadence.summary.one'
                      : 'coverage.cadence.summary.other',
                    { count: formatInteger(cadenceGapCount, locale) },
                  )}
                </Badge>
                <Badge tone="neutral">{data.items.length} matrix rows</Badge>
              </span>
            ) : null
          }
        />
        <CardBody>
          {isPending ? (
            <LoadingState label="Deriving tenant coverage…" />
          ) : isError ? (
            <HonestDataState
              state={classifySurfaceTruth({ error })}
              producer="Owned-vantage coverage query"
              producerReadiness={`The server did not return an authoritative tenant-scoped matrix: ${error?.message ?? 'request failed'}`}
              lastSuccessfulIngest={null}
              coverageLimitation="Agent placement, test definitions, and evidence recency are not shown while this read is unavailable."
              action={
                <Button variant="secondary" onClick={() => void refetch()}>
                  Retry coverage query
                </Button>
              }
            />
          ) : (data?.items.length ?? 0) === 0 ? (
            <HonestDataState
              state="ready-no-data"
              producer="Owned-vantage coverage query"
              producerReadiness="Ready; no enabled test definitions produced matrix rows"
              lastSuccessfulIngest={null}
              coverageLimitation="Coverage cannot be measured until at least one synthetic test is enabled."
              action={
                <div className={styles.permissionAction}>
                  <Button
                    variant="primary"
                    onClick={() => void navigate('/targets?create=test')}
                    disabled={!canCreateTest}
                  >
                    New test
                  </Button>
                  {!canCreateTest ? <small>Requires test.write permission.</small> : null}
                </div>
              }
            />
          ) : (
            <>
              {!data?.evidence_running ? (
                <p role="status" className={styles.fleetNotice}>
                  Result evidence is not wired on this control-plane instance. Rows remain
                  uncovered; they are not presented as healthy.
                </p>
              ) : null}
              {data?.truncated ? (
                <p role="status" className={styles.fleetNotice}>
                  Candidate scan reached its {data.candidate_limit}-row safety bound. Refine the
                  tenant inventory before treating this snapshot as complete.
                </p>
              ) : null}
              <FilterBar>
                <Field
                  label="Find coverage"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="site, region, probe, target"
                />
                <Select
                  label="Coverage state"
                  value={status}
                  onChange={(event) => setStatus(event.target.value as CoverageStatus | 'all')}
                  options={[
                    { value: 'all', label: 'All coverage states' },
                    ...Object.entries(statusLabels).map(([value, label]) => ({ value, label })),
                  ]}
                />
                <Select
                  label="Region"
                  value={region}
                  onChange={(event) => setRegion(event.target.value)}
                  options={[
                    { value: 'all', label: 'All regions' },
                    ...regions.map((value) => ({ value, label: value })),
                  ]}
                />
              </FilterBar>
              <div className={styles.coverageDesktop}>
                <Table
                  caption="Owned-vantage coverage matrix"
                  columns={columns}
                  rows={filtered}
                  rowKey={(item) => `${item.test_id}:${item.region}:${item.site}`}
                  empty={
                    <EmptyState
                      title="No coverage rows match these filters"
                      description="Clear or change the local filters; no server data was deleted."
                      action={
                        <Button
                          variant="secondary"
                          onClick={() => {
                            setQuery('')
                            setStatus('all')
                            setRegion('all')
                          }}
                        >
                          Clear filters
                        </Button>
                      }
                    />
                  }
                />
              </div>
              <ul className={styles.coverageMobile} aria-label={t('coverage.cadence.mobileList')}>
                {filtered.map((item) => (
                  <li
                    key={`${item.test_id}:${item.region}:${item.site}`}
                    className={styles.coverageRecord}
                    data-coverage-mobile-record
                    data-test-id={item.test_id}
                    data-test-name={item.test_name}
                    data-probe-family={item.probe_family}
                    data-target={item.target}
                    data-coverage-status={item.status}
                  >
                    <div className={styles.coverageRecordHeader}>
                      <strong>{item.test_name}</strong>
                      <Badge tone="neutral">{item.probe_family}</Badge>
                      <code>{item.target || '—'}</code>
                    </div>
                    <div className={styles.coverageRecordGroup}>
                      <strong>{t('coverage.cadence.mobileCoverage')}</strong>
                      <StatusDot
                        tone={statusTones[item.status]}
                        label={statusLabels[item.status]}
                      />
                      {item.next_action ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => void navigate(item.next_action!.href)}
                        >
                          {item.next_action.label}
                        </Button>
                      ) : (
                        <Badge tone="success">No gap</Badge>
                      )}
                    </div>
                    <div className={styles.coverageRecordGroup}>
                      <strong>{t('coverage.cadence.mobileVantage')}</strong>
                      <span>
                        {item.site} · {item.region}
                      </span>
                      <StatusDot
                        tone={
                          item.agent_readiness === 'ready'
                            ? 'success'
                            : item.agent_readiness === 'degraded'
                              ? 'warning'
                              : 'danger'
                        }
                        label={`${item.agent_readiness} · ${item.ready_agent_count}/${item.agent_count} ready`}
                      />
                    </div>
                    <div
                      className={styles.coverageRecordGroup}
                      data-coverage-evidence={item.last_evidence_at ? 'observed' : 'never'}
                    >
                      <strong>{t('coverage.cadence.mobileEvidence')}</strong>
                      {item.last_evidence_at ? (
                        <DateTime value={item.last_evidence_at} />
                      ) : (
                        t('coverage.cadence.evidenceNever')
                      )}
                      <small>
                        {t(
                          item.independent_vantage_count === 1
                            ? 'coverage.cadence.independentVantage.one'
                            : 'coverage.cadence.independentVantage.other',
                          { count: formatInteger(item.independent_vantage_count, locale) },
                        )}
                      </small>
                    </div>
                    <div className={styles.coverageRecordGroup}>
                      <strong>{t('coverage.cadence.column')}</strong>
                      <CadenceReceipt item={item} />
                    </div>
                  </li>
                ))}
                {filtered.length === 0 ? (
                  <li>
                    <EmptyState
                      title="No coverage rows match these filters"
                      description="Clear or change the local filters; no server data was deleted."
                      action={
                        <Button
                          variant="secondary"
                          onClick={() => {
                            setQuery('')
                            setStatus('all')
                            setRegion('all')
                          }}
                        >
                          Clear filters
                        </Button>
                      }
                    />
                  </li>
                ) : null}
              </ul>
            </>
          )}
        </CardBody>
      </Card>
      <CoverageDebtPanel canCreateTest={canCreateTest} />
    </>
  )
}

const debtStateLabels: Record<CoverageDebtState, string> = {
  uncovered: 'Uncovered',
  stale: 'Stale',
  unknown: 'Unknown',
  covered: 'Covered',
}

const debtStateTones: Record<CoverageDebtState, BadgeTone> = {
  uncovered: 'danger',
  stale: 'warning',
  unknown: 'neutral',
  covered: 'success',
}

const debtPlaneLabels: Record<CoverageDebtPlane, string> = {
  synthetic: 'Synthetic',
  path: 'Path',
  flow: 'Flow / eBPF',
  routing: 'Routing / BGP',
  device: 'Device telemetry',
}

function formatEvidenceAge(seconds: number): string {
  if (seconds < 60) return `${seconds}s old`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m old`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h old`
  return `${Math.floor(seconds / 86400)}d old`
}

function CoverageDebtPanel({ canCreateTest }: { canCreateTest: boolean }) {
  const navigate = useNavigate()
  const { data, isPending, isError, error, refetch } = useCoverageDebt()
  const [query, setQuery] = useState('')
  const [plane, setPlane] = useState<CoverageDebtPlane | 'all'>('all')
  const [state, setState] = useState<CoverageDebtState | 'all'>('all')

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return (data?.items ?? []).filter((item) => {
      const haystack = [
        item.label,
        item.entity_id,
        item.entity_kind,
        item.region ?? '',
        item.site ?? '',
        item.evidence_basis,
      ]
        .join(' ')
        .toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (plane === 'all' || item.plane === plane) &&
        (state === 'all' || item.state === state)
      )
    })
  }, [data?.items, plane, query, state])

  const columns: Column<CoverageDebtItem>[] = [
    {
      key: 'state',
      header: 'Debt state',
      render: (item) => (
        <span className={styles.fleetCell}>
          <StatusDot tone={debtStateTones[item.state]} label={debtStateLabels[item.state]} />
          <small>{debtPlaneLabels[item.plane]}</small>
        </span>
      ),
    },
    {
      key: 'entity',
      header: 'Known entity / site',
      render: (item) => (
        <span className={styles.fleetCell}>
          <strong>{item.label || item.entity_id}</strong>
          <Badge tone="neutral">{item.entity_kind}</Badge>
          {item.entity_kind === 'site' ? (
            <small>
              {item.site} · {item.region}
            </small>
          ) : (
            <code>{item.entity_id}</code>
          )}
        </span>
      ),
    },
    {
      key: 'evidence',
      header: 'Exact local evidence',
      render: (item) => (
        <span className={styles.fleetCell}>
          {item.observed_at ? <DateTime value={item.observed_at} /> : 'No exact evidence'}
          <small>
            {item.evidence_age_seconds === undefined
              ? item.evidence_basis
              : `${formatEvidenceAge(item.evidence_age_seconds)} · ${item.evidence_basis}`}
          </small>
          {item.evidence_ref ? <code>{item.evidence_ref}</code> : null}
        </span>
      ),
    },
    {
      key: 'pivot',
      header: 'Read-only pivot',
      render: (item) => (
        <Button size="sm" variant="secondary" onClick={() => void navigate(item.next_action.href)}>
          {item.next_action.label}
        </Button>
      ),
    },
  ]

  const debtCount = (data?.items ?? []).filter(
    (item) => item.state === 'uncovered' || item.state === 'stale',
  ).length
  const unknownCount = (data?.items ?? []).filter((item) => item.state === 'unknown').length

  return (
    <Card data-targets-coverage-debt>
      <CardHeader
        title="Cross-plane coverage debt"
        description="Tenant-local sites and topology entities × five signal planes. Green requires fresh exact evidence; registration or topology presence alone never counts."
        actions={
          data ? (
            <span className={styles.fleetBadges}>
              <Badge tone={debtCount > 0 ? 'warning' : 'success'}>
                {debtCount} {debtCount === 1 ? 'debt row' : 'debt rows'}
              </Badge>
              <Badge tone="neutral">{unknownCount} unknown</Badge>
            </span>
          ) : null
        }
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Deriving cross-plane debt…" />
        ) : isError ? (
          <HonestDataState
            state={classifySurfaceTruth({ error })}
            producer="Cross-plane coverage-debt query"
            producerReadiness={`The server did not return an authoritative tenant-scoped debt map: ${error?.message ?? 'request failed'}`}
            lastSuccessfulIngest={null}
            coverageLimitation="Entity, plane, and evidence-age rows are unavailable while this local read fails."
            action={
              <Button variant="secondary" onClick={() => void refetch()}>
                Retry debt query
              </Button>
            }
          />
        ) : (data?.items.length ?? 0) === 0 && (data?.partial_reasons?.length ?? 0) > 0 ? (
          <HonestDataState
            state="degraded"
            producer="Cross-plane coverage-debt query"
            producerReadiness={`Incomplete: ${(data?.partial_reasons ?? []).join('; ')}`}
            lastSuccessfulIngest={null}
            coverageLimitation="No entity rows can be treated as an authoritative empty inventory while a required local producer is unavailable."
            action={
              <Button variant="secondary" onClick={() => void refetch()}>
                Retry debt query
              </Button>
            }
          />
        ) : (data?.items.length ?? 0) === 0 ? (
          <HonestDataState
            state="ready-no-data"
            producer="Cross-plane coverage-debt query"
            producerReadiness={`Ready; no tenant-local sites or topology entities are known. Producer states: ${
              (data?.producers ?? [])
                .map((producer) => `${debtPlaneLabels[producer.plane]} ${producer.status}`)
                .join(', ') || 'not reported'
            }`}
            lastSuccessfulIngest={null}
            coverageLimitation="Coverage cannot be derived until a local test/site or topology observation exists."
            action={
              <div className={styles.permissionAction}>
                <Button
                  variant="primary"
                  onClick={() => void navigate('/targets?create=test')}
                  disabled={!canCreateTest}
                >
                  New test
                </Button>
                {!canCreateTest ? <small>Requires test.write permission.</small> : null}
              </div>
            }
          />
        ) : (
          <>
            {(data?.partial_reasons?.length ?? 0) > 0 ? (
              <p role="status" className={styles.fleetNotice}>
                Partial snapshot: {(data?.partial_reasons ?? []).join('; ')}. Unknown remains
                unknown.
              </p>
            ) : null}
            <div className={styles.fleetBadges} aria-label="Signal producer readiness">
              {(data?.producers ?? []).map((producer) => (
                <Badge
                  key={producer.plane}
                  tone={
                    producer.status === 'observed'
                      ? 'success'
                      : producer.status === 'idle'
                        ? 'warning'
                        : 'neutral'
                  }
                >
                  {debtPlaneLabels[producer.plane]}: {producer.status} · {producer.registered_count}{' '}
                  registered · {producer.evidence_count} evidence
                </Badge>
              ))}
            </div>
            <FilterBar>
              <Field
                label="Find debt entity"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="entity, site, evidence basis"
              />
              <Select
                label="Signal plane"
                value={plane}
                onChange={(event) => setPlane(event.target.value as CoverageDebtPlane | 'all')}
                options={[
                  { value: 'all', label: 'All signal planes' },
                  ...Object.entries(debtPlaneLabels).map(([value, label]) => ({ value, label })),
                ]}
              />
              <Select
                label="Debt state"
                value={state}
                onChange={(event) => setState(event.target.value as CoverageDebtState | 'all')}
                options={[
                  { value: 'all', label: 'All debt states' },
                  ...Object.entries(debtStateLabels).map(([value, label]) => ({ value, label })),
                ]}
              />
            </FilterBar>
            <Table
              caption="Cross-plane coverage debt map"
              columns={columns}
              rows={filtered}
              rowKey={(item) => `${item.entity_id}:${item.plane}`}
              empty={
                <EmptyState
                  title="No debt rows match these filters"
                  description="Clear or change the local filters; no server evidence was changed."
                  action={
                    <Button
                      variant="secondary"
                      onClick={() => {
                        setQuery('')
                        setPlane('all')
                        setState('all')
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              }
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
