// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Column,
  EmptyState,
  ErrorState,
  Field,
  Icon,
  LoadingState,
  Modal,
  Select,
  StatusDot,
  Table,
} from '../../components'
import { Page } from '../RoutePage'
import {
  useAgents,
  useMintAgentEnrollToken,
  useRegisterCollector,
  fleetMetadata,
  flattenAgents,
  type Agent,
  type AgentEnrollToken,
  type CollectorPlane,
  type CollectorRegistration,
} from '../../api/agents'
import { useSecretsHealth, type SecretBackendHealth } from '../../api/secrets'
import { RemediationCard, KeysCard } from './AdminCards'
import { LifecycleCard, SupportCard, EditionsCard } from './LifecycleCards'
import { IdentityCard } from './IdentityCard'
import { agentEnrollCommand, defaultControlPlaneURL } from '../enrollment'
import styles from '../pages.module.css'
import { FilterBar, SavedViews } from '../listControls'
import { filterValue, filtersForSave, setURLFilters } from '../urlFilters'
import { useI18n } from '../../i18n/useI18n'
import type { MessageKey } from '../../i18n/messages'
import { CodeExportPanel } from '../CodeExportPanel'
import { collectorRegistrationAsCode } from '../codeExport'

type TFn = (key: MessageKey, vars?: Record<string, string | number>) => string

function agentStatusLabel(status: Agent['status'], t: TFn) {
  if (status === 'online') return t('admin.filter.online')
  if (status === 'offline') return t('admin.filter.offline')
  return t('admin.filter.registered')
}

function readinessState(agent: Agent): NonNullable<Agent['readiness_state']> | 'unavailable' {
  return agent.readiness_state ?? 'unavailable'
}

function readinessLabel(agent: Agent, t: TFn) {
  const labels: Record<ReturnType<typeof readinessState>, MessageKey> = {
    ready: 'admin.fleet.health.ready',
    stale: 'admin.fleet.health.stale',
    never_connected: 'admin.fleet.health.neverConnected',
    unsupported_capability: 'admin.fleet.health.capabilityGap',
    version_skew: 'admin.fleet.health.versionSkew',
    unavailable: 'admin.fleet.health.unavailable',
  }
  return t(labels[readinessState(agent)])
}

function readinessTone(agent: Agent): 'success' | 'warning' | 'danger' | 'neutral' {
  const state = readinessState(agent)
  if (state === 'ready') return 'success'
  if (state === 'stale' || state === 'version_skew') return 'warning'
  if (state === 'never_connected' || state === 'unsupported_capability') return 'danger'
  return 'neutral'
}

function versionLabel(agent: Agent, t: TFn) {
  const labels: Record<NonNullable<Agent['version_state']> | 'unknown', MessageKey> = {
    current: 'admin.fleet.version.current',
    supported_skew: 'admin.fleet.version.supportedSkew',
    unsupported: 'admin.fleet.version.unsupported',
    unknown: 'admin.fleet.version.unknown',
  }
  return t(labels[agent.version_state ?? 'unknown'])
}

function heartbeatAge(agent: Agent, t: TFn) {
  if (agent.heartbeat_state === 'never_seen') return t('admin.fleet.heartbeat.never')
  if (agent.heartbeat_age_seconds === undefined) return t('admin.fleet.heartbeat.unavailable')
  return t('admin.fleet.heartbeat.age', { seconds: agent.heartbeat_age_seconds })
}

function safeActionLabel(agent: Agent, t: TFn) {
  const labels: Record<NonNullable<Agent['next_safe_action']>['kind'], MessageKey> = {
    inspect_heartbeat: 'admin.fleet.action.inspectHeartbeat',
    review_capabilities: 'admin.fleet.action.reviewCapabilities',
    review_staged_rollout: 'admin.fleet.action.reviewRollout',
    verify_rollout_wave: 'admin.fleet.action.verifyWave',
    review_halted_rollout: 'admin.fleet.action.reviewHalted',
    inspect_evidence: 'admin.fleet.action.inspect',
  }
  return agent.next_safe_action
    ? t(labels[agent.next_safe_action.kind])
    : t('admin.fleet.action.inspect')
}

function FleetActionDialog({
  agent,
  rolloutsAvailable,
  onClose,
}: {
  agent: Agent | null
  rolloutsAvailable: boolean
  onClose: () => void
}) {
  const { t } = useI18n()
  if (!agent) return null
  const action = agent.next_safe_action

  return (
    <Modal
      open
      onClose={onClose}
      title={t('admin.fleet.dialog.title', { agent: agent.name || agent.id })}
      footer={
        <Button variant="primary" onClick={onClose}>
          {t('admin.fleet.dialog.done')}
        </Button>
      }
    >
      <div className={styles.form}>
        <p className={styles.fleetSafety}>{t('admin.fleet.dialog.safety')}</p>
        <dl className={styles.fleetEvidence}>
          <div>
            <dt>{t('admin.fleet.dialog.health')}</dt>
            <dd>{readinessLabel(agent, t)}</dd>
          </div>
          <div>
            <dt>{t('admin.fleet.dialog.heartbeat')}</dt>
            <dd>{agent.heartbeat_reason || t('admin.fleet.evidenceUnavailable')}</dd>
          </div>
          <div>
            <dt>{t('admin.fleet.dialog.version')}</dt>
            <dd>{agent.version_reason || t('admin.fleet.evidenceUnavailable')}</dd>
          </div>
          <div>
            <dt>{t('admin.fleet.dialog.rollout')}</dt>
            <dd>
              {!rolloutsAvailable
                ? t('admin.fleet.rollout.unavailable')
                : agent.rollout_id
                  ? t('admin.fleet.rollout.detail', {
                      id: agent.rollout_id,
                      cohort: agent.rollout_cohort ?? '—',
                      state: agent.rollout_state ?? '—',
                      target: agent.rollout_target ?? '—',
                    })
                  : t('admin.fleet.rollout.none')}
            </dd>
          </div>
          <div>
            <dt>{t('admin.fleet.dialog.lastFailure')}</dt>
            <dd>{agent.last_failure || t('admin.fleet.failure.none')}</dd>
          </div>
        </dl>
        <div>
          <strong>{safeActionLabel(agent, t)}</strong>
          <p className={styles.editionsLede}>
            {action?.reason || t('admin.fleet.action.inspectReason')}
          </p>
        </div>
        <p className={styles.editionsLede}>{t('admin.fleet.dialog.guardrails')}</p>
        <Link to={action?.href || '/docs/api#rollouts'}>{t('admin.fleet.dialog.openRunbook')}</Link>
      </div>
    </Modal>
  )
}

// --- Admin & Settings: the agent fleet (live /v1/agents) + secret-backend
// health (S41, live /v1/secrets/health) ---

function AgentEnrollDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useI18n()
  const mint = useMintAgentEnrollToken()
  const [name, setName] = useState('')
  const [agentID, setAgentID] = useState('')
  const [ttlMinutes, setTTLMinutes] = useState('60')
  const [server, setServer] = useState(defaultControlPlaneURL)
  const [created, setCreated] = useState<AgentEnrollToken | null>(null)

  function submit(e: FormEvent) {
    e.preventDefault()
    const ttl = Number(ttlMinutes)
    const input = {
      ...(agentID.trim() ? { agent_id: agentID.trim() } : {}),
      ...(name.trim() ? { name: name.trim() } : {}),
      ...(Number.isFinite(ttl) && ttl > 0 ? { ttl_seconds: Math.round(ttl * 60) } : {}),
    }
    mint.mutate(input, { onSuccess: setCreated })
  }

  const command = created
    ? agentEnrollCommand(created, server.trim() || defaultControlPlaneURL())
    : ''
  const expires = created ? new Date(created.expires_at).toISOString() : ''

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={created ? t('admin.agentDialog.createdTitle') : t('admin.agentDialog.title')}
      footer={
        created ? (
          <span className={styles.actions}>
            <Button
              variant="secondary"
              onClick={() => void navigator.clipboard?.writeText(command)}
            >
              <Icon name="check" /> {t('admin.agentDialog.copyCommand')}
            </Button>
            <Button variant="primary" onClick={onClose}>
              {t('admin.agentDialog.done')}
            </Button>
          </span>
        ) : null
      }
    >
      {created ? (
        <div className={styles.form}>
          <p className={styles.editionsLede}>
            {t('admin.agentDialog.tokenExpires', {
              id: created.id,
              expires,
            })}
          </p>
          <Field label={t('admin.agentDialog.token')} value={created.token} readOnly />
          <Field label={t('admin.agentDialog.command')} value={command} readOnly />
          <p className={styles.editionsLede}>
            {created.server_cert_pin
              ? t('admin.agentDialog.pinHint')
              : t('admin.agentDialog.caHint')}
          </p>
        </div>
      ) : (
        <form
          className={styles.form}
          onSubmit={(e) => {
            void submit(e)
          }}
        >
          <Field
            label={t('admin.agentDialog.label')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="edge-probe-1"
            hint={t('admin.agentDialog.labelHint')}
          />
          <Field
            label={t('admin.agentDialog.pinnedID')}
            value={agentID}
            onChange={(e) => setAgentID(e.target.value)}
            placeholder={t('admin.agentDialog.pinnedPlaceholder')}
            hint={t('admin.agentDialog.pinnedHint')}
          />
          <Field
            label={t('admin.agentDialog.ttl')}
            type="number"
            min={1}
            value={ttlMinutes}
            onChange={(e) => setTTLMinutes(e.target.value)}
            hint={t('admin.agentDialog.ttlHint')}
          />
          <Field
            label={t('admin.agentDialog.controlURL')}
            value={server}
            onChange={(e) => setServer(e.target.value)}
            hint={t('admin.agentDialog.controlURLHint')}
          />
          {mint.isError ? (
            <p role="alert" className={styles.editionsLede}>
              {mint.error.message}
            </p>
          ) : null}
          <span className={styles.actions}>
            <Button type="submit" variant="primary" disabled={mint.isPending}>
              <Icon name="admin" />{' '}
              {mint.isPending ? t('admin.agentDialog.minting') : t('admin.agentDialog.mint')}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>
              {t('admin.cancel')}
            </Button>
          </span>
        </form>
      )}
    </Modal>
  )
}

const collectorPlanes: { value: CollectorPlane; labelKey: MessageKey }[] = [
  { value: 'bgp', labelKey: 'onboarding.producer.bgp.title' },
  { value: 'flow', labelKey: 'onboarding.producer.flow.title' },
  { value: 'device', labelKey: 'onboarding.producer.device.title' },
  { value: 'ebpf', labelKey: 'onboarding.producer.ebpf.title' },
  { value: 'endpoint', labelKey: 'onboarding.producer.endpoint.title' },
]

const collectorPlaneGuidance: Record<
  CollectorPlane,
  { prerequisitesKey: MessageKey; firstSignalKey: MessageKey }
> = {
  bgp: {
    prerequisitesKey: 'onboarding.producer.bgp.prerequisites',
    firstSignalKey: 'onboarding.producer.bgp.firstSignal',
  },
  flow: {
    prerequisitesKey: 'onboarding.producer.flow.prerequisites',
    firstSignalKey: 'onboarding.producer.flow.firstSignal',
  },
  device: {
    prerequisitesKey: 'onboarding.producer.device.prerequisites',
    firstSignalKey: 'onboarding.producer.device.firstSignal',
  },
  ebpf: {
    prerequisitesKey: 'onboarding.producer.ebpf.prerequisites',
    firstSignalKey: 'onboarding.producer.ebpf.firstSignal',
  },
  endpoint: {
    prerequisitesKey: 'onboarding.producer.endpoint.prerequisites',
    firstSignalKey: 'onboarding.producer.endpoint.firstSignal',
  },
}

function isCollectorPlane(value: string | null): value is CollectorPlane {
  return collectorPlanes.some((plane) => plane.value === value)
}

function formatKeyValues(values: Record<string, string>): string {
  return Object.entries(values)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')
}

function CollectorRegisterDialog({
  open,
  onClose,
  initialPlane,
}: {
  open: boolean
  onClose: () => void
  initialPlane?: CollectorPlane
}) {
  const { t } = useI18n()
  const mint = useMintAgentEnrollToken()
  const register = useRegisterCollector()
  const [plane, setPlane] = useState<CollectorPlane>(initialPlane ?? 'flow')
  const [hostname, setHostname] = useState('')
  const [agentID, setAgentID] = useState('')
  const [registered, setRegistered] = useState<CollectorRegistration | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setPlane(initialPlane ?? 'flow')
    setRegistered(null)
    setError('')
  }, [initialPlane, open])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setRegistered(null)
    try {
      const token = await mint.mutateAsync({
        ...(agentID.trim() ? { agent_id: agentID.trim() } : {}),
        ...(hostname.trim() ? { name: hostname.trim() } : {}),
        ttl_seconds: 300,
      })
      const out = await register.mutateAsync({
        token: token.token,
        plane,
        ...(hostname.trim() ? { hostname: hostname.trim() } : {}),
      })
      setRegistered(out)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('admin.collectorDialog.failed'))
    }
  }

  const envText = registered ? formatKeyValues(registered.config.env) : ''
  const labelPlaceholder = plane === 'bgp' ? 'rrc00' : 'edge-flow-1'
  const guidance = collectorPlaneGuidance[plane]

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={
        registered ? t('admin.collectorDialog.registeredTitle') : t('admin.collectorDialog.title')
      }
      footer={
        registered ? (
          <span className={styles.actions}>
            <Button
              variant="secondary"
              onClick={() => void navigator.clipboard?.writeText(envText)}
            >
              <Icon name="check" /> {t('admin.collectorDialog.copyEnv')}
            </Button>
            <Button variant="primary" onClick={onClose}>
              {t('admin.agentDialog.done')}
            </Button>
          </span>
        ) : null
      }
    >
      {registered ? (
        <div className={styles.form}>
          <Field
            label={t('admin.collectorDialog.collectorID')}
            value={registered.agent_id}
            readOnly
          />
          <Field
            label={t('admin.collectorDialog.tenantID')}
            value={registered.tenant_id}
            readOnly
          />
          <Field label={t('admin.collectorDialog.plane')} value={registered.plane} readOnly />
          <p className={styles.editionsLede}>
            {t('admin.collectorDialog.capabilities', {
              capabilities: registered.capabilities.join(', '),
            })}
          </p>
          {registered.config.startup_command ? (
            <Field
              label={t('admin.collectorDialog.startupCommand')}
              value={registered.config.startup_command}
              readOnly
            />
          ) : null}
          <CodeExportPanel
            title={t('admin.collectorDialog.exportCode')}
            code={collectorRegistrationAsCode(registered)}
          />
          <p className={styles.editionsLede}>{t('admin.collectorDialog.environment')}</p>
          {Object.entries(registered.config.env).map(([key, value]) => (
            <Field key={key} label={key} value={`${key}=${value}`} readOnly />
          ))}
          <p className={styles.editionsLede}>{t('admin.collectorDialog.yaml')}</p>
          {Object.entries(registered.config.yaml).map(([key, value]) => (
            <Field
              key={key}
              label={t('admin.collectorDialog.yamlKey', { key })}
              value={`${key}: ${JSON.stringify(value)}`}
              readOnly
            />
          ))}
        </div>
      ) : (
        <form
          className={styles.form}
          onSubmit={(e) => {
            void submit(e)
          }}
        >
          <Select
            label={t('admin.collectorDialog.collectorPlane')}
            options={collectorPlanes.map((item) => ({
              value: item.value,
              label: t(item.labelKey),
            }))}
            value={plane}
            onChange={(e) => setPlane(e.target.value as CollectorPlane)}
          />
          <p className={styles.editionsLede}>
            {t('admin.collectorDialog.guidance', {
              prerequisites: t(guidance.prerequisitesKey),
              firstSignal: t(guidance.firstSignalKey),
            })}
          </p>
          <Field
            label={t('admin.collectorDialog.label')}
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder={labelPlaceholder}
            hint={t('admin.collectorDialog.labelHint')}
          />
          <Field
            label={t('admin.collectorDialog.pinnedID')}
            value={agentID}
            onChange={(e) => setAgentID(e.target.value)}
            placeholder={t('admin.collectorDialog.pinnedPlaceholder')}
            hint={t('admin.collectorDialog.pinnedHint')}
          />
          {error ? (
            <p role="alert" className={styles.editionsLede}>
              {error}
            </p>
          ) : null}
          <span className={styles.actions}>
            <Button type="submit" variant="primary" disabled={mint.isPending || register.isPending}>
              <Icon name="admin" />{' '}
              {mint.isPending || register.isPending
                ? t('admin.collectorDialog.registering')
                : t('admin.collectorDialog.register')}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>
              {t('admin.cancel')}
            </Button>
          </span>
        </form>
      )}
    </Modal>
  )
}

/** SecretBackendsCard is the S41 surface: per-backend credential-resolution
 * health. No secret material ever reaches this card — the API serves counters
 * and redacted errors only. resolver_running=false renders as the honest
 * "not wired" empty state, never as a healthy zero. */
function SecretBackendsCard() {
  const { t } = useI18n()
  const { data, isPending, isError } = useSecretsHealth()

  const columns: Column<SecretBackendHealth>[] = [
    {
      key: 'scheme',
      header: t('admin.secrets.column.backend'),
      render: (b) => <code>{b.scheme}</code>,
    },
    {
      key: 'status',
      header: t('admin.secrets.column.status'),
      render: (b) =>
        !b.configured ? (
          <StatusDot tone="neutral" label={t('admin.secrets.status.notConfigured')} />
        ) : b.failures > 0 && (!b.last_ok || (b.last_error_at && b.last_error_at > b.last_ok)) ? (
          <StatusDot tone="danger" label={t('admin.secrets.status.failing')} />
        ) : (
          <StatusDot tone="success" label={t('admin.secrets.status.ok')} />
        ),
    },
    { key: 'resolves', header: t('admin.secrets.column.resolves'), render: (b) => b.resolves },
    { key: 'failures', header: t('admin.secrets.column.failures'), render: (b) => b.failures },
    {
      key: 'leases',
      header: t('admin.secrets.column.leases'),
      render: (b) => (b.cached_leases > 0 ? <Badge tone="info">{b.cached_leases}</Badge> : '0'),
    },
    {
      key: 'last',
      header: t('admin.secrets.column.lastError'),
      render: (b) => (b.last_error ? <code>{b.last_error}</code> : '—'),
    },
  ]

  return (
    <Card>
      <CardHeader title={t('admin.secrets.title')} description={t('admin.secrets.description')} />
      <CardBody>
        {isPending ? (
          <LoadingState label={t('admin.secrets.loading')} />
        ) : isError ? (
          <ErrorState description={t('admin.secrets.error')} />
        ) : !data?.resolver_running ? (
          <EmptyState
            icon="admin"
            title={t('admin.secrets.notWired.title')}
            description={t('admin.secrets.notWired.description')}
          />
        ) : (
          <Table
            caption={t('admin.secrets.table.caption')}
            columns={columns}
            rows={data.backends}
            rowKey={(b) => b.scheme}
            empty={
              <EmptyState
                icon="admin"
                title={t('admin.secrets.empty.title')}
                description={t('admin.secrets.empty.description')}
              />
            }
          />
        )}
      </CardBody>
    </Card>
  )
}

export function AdminPage() {
  const { t } = useI18n()
  const { data, isPending, isError, fetchNextPage, hasNextPage, isFetchingNextPage } = useAgents()
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [collectorOpen, setCollectorOpen] = useState(false)
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [params, setParams] = useSearchParams()
  const collectorPlaneParam = params.get('register_collector')
  const deepLinkedCollectorPlane = isCollectorPlane(collectorPlaneParam)
    ? collectorPlaneParam
    : undefined
  const defaults = {
    agent_q: '',
    agent_status: 'all',
    agent_capability: 'all',
    agent_health: 'all',
  }
  const q = filterValue(params, 'agent_q')
  const status = filterValue(params, 'agent_status', 'all')
  const capability = filterValue(params, 'agent_capability', 'all')
  const health = filterValue(params, 'agent_health', 'all')
  const setFilter = (patch: Record<string, string>) =>
    setURLFilters(params, setParams, defaults, patch)

  useEffect(() => {
    if (deepLinkedCollectorPlane) setCollectorOpen(true)
  }, [deepLinkedCollectorPlane])

  function closeCollectorDialog() {
    setCollectorOpen(false)
    if (!params.has('register_collector')) return
    const next = new URLSearchParams(params)
    next.delete('register_collector')
    setParams(next, { replace: true })
  }
  // UX-004: flatten the cursor-paged result into the rows fetched so far.
  const agents = flattenAgents(data?.pages)
  const fleet = fleetMetadata(data?.pages)
  const capabilities = useMemo(
    () => Array.from(new Set(agents.flatMap((a) => a.capabilities))).sort(),
    [agents],
  )
  const filteredAgents = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return agents.filter((agent) => {
      const haystack = [
        agent.name,
        agent.hostname,
        agent.agent_version,
        agent.status,
        agent.heartbeat_state,
        agent.heartbeat_reason,
        agent.version_state,
        agent.version_reason,
        agent.readiness_state,
        agent.readiness_reason,
        agent.rollout_cohort,
        agent.rollout_state,
        agent.rollout_target,
        agent.last_failure,
        ...agent.capabilities,
      ]
        .join(' ')
        .toLowerCase()
      return (
        (!needle || haystack.includes(needle)) &&
        (status === 'all' || agent.status === status) &&
        (capability === 'all' || agent.capabilities.includes(capability)) &&
        (health === 'all' ||
          (health === 'needs_action'
            ? readinessState(agent) !== 'ready'
            : readinessState(agent) === health))
      )
    })
  }, [agents, capability, health, q, status])

  const columns: Column<Agent>[] = [
    {
      key: 'agent',
      header: t('admin.column.agent'),
      render: (a) => (
        <span className={styles.fleetCell}>
          <strong>{a.name}</strong>
          <code>{a.hostname || '—'}</code>
        </span>
      ),
    },
    {
      key: 'health',
      header: t('admin.fleet.column.health'),
      render: (a) => (
        <span className={styles.fleetCell}>
          <StatusDot tone={readinessTone(a)} label={readinessLabel(a, t)} />
          <span>{heartbeatAge(a, t)}</span>
          <small>{agentStatusLabel(a.status, t)}</small>
          <small>{a.readiness_reason || t('admin.fleet.evidenceUnavailable')}</small>
        </span>
      ),
    },
    {
      key: 'version',
      header: t('admin.column.version'),
      render: (a) => (
        <span className={styles.fleetCell}>
          <code>{a.agent_version || '—'}</code>
          <Badge
            tone={
              a.version_state === 'current'
                ? 'success'
                : a.version_state === 'unsupported'
                  ? 'danger'
                  : a.version_state === 'supported_skew'
                    ? 'warning'
                    : 'neutral'
            }
          >
            {versionLabel(a, t)}
          </Badge>
          {fleet.controlVersion ? (
            <small>{t('admin.fleet.controlVersion', { version: fleet.controlVersion })}</small>
          ) : null}
        </span>
      ),
    },
    {
      key: 'caps',
      header: t('admin.column.capabilities'),
      render: (a) => (
        <span className={styles.fleetBadges}>
          {a.capabilities.length ? (
            a.capabilities.map((cap) => <Badge key={cap}>{cap}</Badge>)
          ) : (
            <Badge tone="danger">{t('admin.fleet.capabilities.none')}</Badge>
          )}
        </span>
      ),
    },
    {
      key: 'rollout',
      header: t('admin.fleet.column.rollout'),
      render: (a) => (
        <span className={styles.fleetCell}>
          {!fleet.rolloutsAvailable ? (
            <StatusDot tone="neutral" label={t('admin.fleet.rollout.unavailable')} />
          ) : a.rollout_id ? (
            <>
              <Badge tone={a.rollout_halted ? 'danger' : 'info'}>
                {a.rollout_cohort} · {a.rollout_state}
              </Badge>
              <small>{t('admin.fleet.rollout.target', { target: a.rollout_target ?? '—' })}</small>
            </>
          ) : (
            <span>{t('admin.fleet.rollout.none')}</span>
          )}
        </span>
      ),
    },
    {
      key: 'failure',
      header: t('admin.fleet.column.lastFailure'),
      render: (a) => a.last_failure || t('admin.fleet.failure.none'),
    },
    {
      key: 'action',
      header: t('admin.fleet.column.safeAction'),
      render: (a) => (
        <Button size="sm" variant="secondary" onClick={() => setSelectedAgent(a)}>
          {safeActionLabel(a, t)}
        </Button>
      ),
    },
  ]

  return (
    <Page title={t('admin.page.title')} subtitle={t('admin.page.subtitle')}>
      <Card>
        <CardHeader
          title={t('admin.agents.title')}
          description={t('admin.agents.description')}
          actions={
            <span className={styles.actions}>
              <Button variant="secondary" onClick={() => setCollectorOpen(true)}>
                <Icon name="admin" /> {t('admin.action.registerCollector')}
              </Button>
              <Button variant="primary" onClick={() => setEnrollOpen(true)}>
                <Icon name="admin" /> {t('admin.action.enrollAgent')}
              </Button>
            </span>
          }
        />
        <CardBody>
          {!fleet.rolloutsAvailable && !isPending ? (
            <p role="status" className={styles.fleetNotice}>
              {t('admin.fleet.rollout.unavailableNotice')}
            </p>
          ) : null}
          <FilterBar>
            <Field
              label={t('admin.filter.find')}
              value={q}
              onChange={(e) => setFilter({ agent_q: e.target.value })}
              placeholder={t('admin.filter.placeholder')}
            />
            <Select
              label={t('admin.filter.status')}
              value={status}
              onChange={(e) => setFilter({ agent_status: e.target.value })}
              options={[
                { value: 'all', label: t('admin.filter.allStatuses') },
                { value: 'online', label: t('admin.filter.online') },
                { value: 'offline', label: t('admin.filter.offline') },
                { value: 'registered', label: t('admin.filter.registered') },
              ]}
            />
            <Select
              label={t('admin.fleet.filter.health')}
              value={health}
              onChange={(e) => setFilter({ agent_health: e.target.value })}
              options={[
                { value: 'all', label: t('admin.fleet.filter.allHealth') },
                { value: 'needs_action', label: t('admin.fleet.filter.needsAction') },
                { value: 'ready', label: t('admin.fleet.health.ready') },
                { value: 'stale', label: t('admin.fleet.health.stale') },
                { value: 'version_skew', label: t('admin.fleet.health.versionSkew') },
                { value: 'never_connected', label: t('admin.fleet.health.neverConnected') },
                {
                  value: 'unsupported_capability',
                  label: t('admin.fleet.health.capabilityGap'),
                },
              ]}
            />
            <Select
              label={t('admin.filter.capability')}
              value={capability}
              onChange={(e) => setFilter({ agent_capability: e.target.value })}
              options={[
                { value: 'all', label: t('admin.filter.allCapabilities') },
                ...capabilities.map((c) => ({ value: c, label: c })),
              ]}
            />
            <SavedViews
              surface="agents"
              filters={filtersForSave(params, defaults)}
              onApply={(filters) =>
                setURLFilters(params, setParams, defaults, {
                  agent_q: filters.agent_q ?? '',
                  agent_status: filters.agent_status ?? 'all',
                  agent_capability: filters.agent_capability ?? 'all',
                  agent_health: filters.agent_health ?? 'all',
                })
              }
              placeholder={t('admin.saved.placeholder')}
            />
          </FilterBar>
          {isPending ? (
            <LoadingState label={t('admin.loadingAgents')} />
          ) : isError ? (
            <ErrorState description={t('admin.errorAgents')} />
          ) : (
            <>
              <Table
                caption={t('admin.table.registeredAgents')}
                columns={columns}
                rows={filteredAgents}
                rowKey={(a) => a.id}
                empty={
                  <EmptyState
                    icon="admin"
                    title={t('admin.empty.agents.title')}
                    description={t('admin.empty.agents.description')}
                  />
                }
              />
              {hasNextPage && (
                <button
                  type="button"
                  onClick={() => {
                    void fetchNextPage()
                  }}
                  disabled={isFetchingNextPage}
                >
                  {isFetchingNextPage ? t('admin.loadMore.loading') : t('admin.loadMore')}
                </button>
              )}
            </>
          )}
        </CardBody>
      </Card>
      <AgentEnrollDialog open={enrollOpen} onClose={() => setEnrollOpen(false)} />
      <FleetActionDialog
        agent={selectedAgent}
        rolloutsAvailable={fleet.rolloutsAvailable}
        onClose={() => setSelectedAgent(null)}
      />
      <CollectorRegisterDialog
        open={collectorOpen}
        onClose={closeCollectorDialog}
        initialPlane={deepLinkedCollectorPlane}
      />
      <SecretBackendsCard />
      <IdentityCard />
      <KeysCard />
      <LifecycleCard />
      <RemediationCard />
      <SupportCard />
      <EditionsCard />
    </Page>
  )
}
