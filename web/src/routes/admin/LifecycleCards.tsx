// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useCallback, useState } from 'react'
import styles from '../pages.module.css'
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
  LoadingState,
  Modal,
  StatusDot,
  Table,
} from '../../components'
import { useEditions, type FeatureInfo } from '../../api/editions'
import {
  useEraseTenantLifecycle,
  useLifecycle,
  useSaveLifecycleRetention,
  type LifecycleEraseAttestation,
  type LifecycleRetentionInput,
  type LifecycleStoreResult,
} from '../../api/lifecycle'
import {
  useDiagnostics,
  type HealthStatus,
  type SelfMetricsSnapshot,
  type Version,
} from '../../api/diagnostics'
import { DateTime } from '../../time/DateTime'
import { useI18n } from '../../i18n/useI18n'
import { formatInteger, formatScaledBytes, formatDuration } from '../../i18n/number'

/** LifecycleCard (S-T5, core): self-service data export, the retention
 *  control, and residency/isolation visibility — export + verifiable
 *  deletion are a compliance right, present in every edition. */
export function LifecycleCard() {
  const { data, isPending, isError } = useLifecycle()
  const saveRetention = useSaveLifecycleRetention()
  const eraseTenant = useEraseTenantLifecycle()
  const [retentionDays, setRetentionDays] = useState<Record<string, string>>({})
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')
  const [eraseOpen, setEraseOpen] = useState(false)
  const [eraseConfirm, setEraseConfirm] = useState('')
  const [eraseError, setEraseError] = useState('')
  const [attestation, setAttestation] = useState<LifecycleEraseAttestation | null>(null)
  const closeEraseDialog = useCallback(() => setEraseOpen(false), [])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSaved(false)
    try {
      const payload = retentionFields.reduce((acc, field) => {
        const value = retentionDays[field.key] ?? ''
        acc[field.key] = value === '' ? null : Number(value)
        return acc
      }, {} as LifecycleRetentionInput)
      await saveRetention.mutateAsync(payload)
      setSaved(true)
    } catch (err) {
      setError((err as Error).message)
    }
  }

  function openEraseDialog() {
    setEraseConfirm('')
    setEraseError('')
    setAttestation(null)
    eraseTenant.reset()
    setEraseOpen(true)
  }

  async function erase(e: React.FormEvent) {
    e.preventDefault()
    setEraseError('')
    setAttestation(null)
    try {
      const out = await eraseTenant.mutateAsync({ confirm: eraseConfirm.trim() })
      setAttestation(out)
    } catch (err) {
      setEraseError(err instanceof Error ? err.message : 'Tenant erasure failed')
    }
  }

  return (
    <Card>
      <CardHeader
        title="Data lifecycle"
        description="Export your tenant's data (portability bundle), tighten per-plane retention, see where your data lives, and run slug-confirmed verifiable erasure."
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Loading lifecycle…" />
        ) : isError ? (
          <ErrorState description="Tenant lifecycle is not wired on this deployment." />
        ) : (
          <>
            <p className={styles.editionsLede}>
              Isolation:{' '}
              <Badge tone={data?.isolation_model === 'pooled' ? 'neutral' : 'accent'}>
                {data?.isolation_model ?? 'pooled'}
              </Badge>
              {data?.residency ? <> · residency {data.residency}</> : null}
              {' · '}
              <a href="/v1/lifecycle/export" download>
                Export my data (tar.gz)
              </a>
              {' · '}
              <a
                href="/v1/lifecycle/export?redact=true"
                download
                title="PII (IP addresses, emails, geo, …) masked per the data-governance policy"
              >
                Redacted export
              </a>
            </p>
            <p className={styles.editionsLede}>
              Audit retention defaults to the deployment window. A tenant value can only shorten a
              positive deployment maximum; single deployments may keep provider rows forever while
              still setting a finite tenant window. Tenant pruning always waits for its SIEM export
              cursor, and provider pruning always waits for WORM evidence.
            </p>
            <form
              className={styles.actions}
              onSubmit={(e) => {
                void save(e)
              }}
            >
              {retentionFields.map((field) => (
                <Field
                  key={field.key}
                  label={`${field.label} days`}
                  inputMode="numeric"
                  value={retentionDays[field.key] ?? ''}
                  onChange={(e) =>
                    setRetentionDays((prev) => ({ ...prev, [field.key]: e.target.value }))
                  }
                  placeholder={data?.[field.key] != null ? String(data[field.key]) : 'default'}
                />
              ))}
              <Button type="submit" variant="primary" disabled={saveRetention.isPending}>
                {saveRetention.isPending ? 'Saving retention' : 'Save retention'}
              </Button>
            </form>
            {saved ? <p className={styles.editionsLede}>Retention saved.</p> : null}
            {error ? (
              <p role="alert" className={styles.editionsLede}>
                {error}
              </p>
            ) : null}
            <div className={styles.actions}>
              <Button variant="danger" onClick={openEraseDialog}>
                Erase tenant data
              </Button>
            </div>
            <EraseTenantDialog
              open={eraseOpen}
              onClose={closeEraseDialog}
              confirm={eraseConfirm}
              onConfirmChange={setEraseConfirm}
              onSubmit={(e) => {
                void erase(e)
              }}
              pending={eraseTenant.isPending}
              error={eraseError}
              attestation={attestation}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}

const retentionFields: Array<{ key: keyof LifecycleRetentionInput; label: string }> = [
  { key: 'flow_retention_days', label: 'Flow' },
  { key: 'otel_retention_days', label: 'OTLP' },
  { key: 'ebpf_retention_days', label: 'eBPF' },
  { key: 'path_retention_days', label: 'Path' },
  { key: 'derived_identity_retention_days', label: 'Derived identity' },
  { key: 'ai_answer_retention_days', label: 'AI answers' },
  { key: 'audit_retention_days', label: 'Audit' },
  { key: 'object_retention_days', label: 'Objects' },
]

function EraseTenantDialog({
  open,
  onClose,
  confirm,
  onConfirmChange,
  onSubmit,
  pending,
  error,
  attestation,
}: {
  open: boolean
  onClose: () => void
  confirm: string
  onConfirmChange: (value: string) => void
  onSubmit: (e: React.FormEvent) => void
  pending: boolean
  error: string
  attestation: LifecycleEraseAttestation | null
}) {
  const columns: Column<LifecycleStoreResult>[] = [
    { key: 'store', header: 'Store', render: (r) => <code>{r.store}</code> },
    {
      key: 'deleted',
      header: 'Deleted',
      numeric: true,
      render: (r) => (r.deleted < 0 ? 'unknown' : r.deleted),
    },
    {
      key: 'verified',
      header: 'Verified',
      render: (r) =>
        r.verified_zero ? (
          <StatusDot tone="success" label="zero" />
        ) : (
          <StatusDot tone="danger" label="not zero" />
        ),
    },
    { key: 'notes', header: 'Notes', render: (r) => r.notes || '—' },
  ]

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={attestation ? 'Erasure receipt' : 'Erase tenant data'}
      footer={
        attestation ? (
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        ) : null
      }
    >
      {attestation ? (
        <div className={styles.form}>
          <p className={styles.editionsLede}>
            <Badge tone={attestation.complete ? 'success' : 'warning'}>
              {attestation.complete ? 'complete' : 'manual follow-up'}
            </Badge>{' '}
            Finished <DateTime value={attestation.finished_at} />. Report SHA-256:{' '}
            <code>{attestation.report_sha256}</code>
            {attestation.backup_erasure_deadline ? (
              <>
                {' '}
                · backups covered by <DateTime value={attestation.backup_erasure_deadline} />
              </>
            ) : null}
          </p>
          <Table
            caption="Erasure attestation stores"
            columns={columns}
            rows={attestation.stores}
            rowKey={(r) => r.store}
          />
        </div>
      ) : (
        <form
          className={styles.form}
          onSubmit={(e) => {
            void onSubmit(e)
          }}
        >
          <p className={styles.editionsLede}>
            This deletes tenant-owned data across wired stores and returns an attestation receipt.
            Type the tenant slug exactly; the control plane validates it against the tenant registry
            and records the audit event.
          </p>
          <Field
            label="Tenant slug confirmation"
            value={confirm}
            onChange={(e) => onConfirmChange(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            hint="The browser sends only this confirmation string; tenant scope comes from your signed-in session."
          />
          {error ? (
            <p role="alert" className={styles.editionsLede}>
              {error}
            </p>
          ) : null}
          <span className={styles.actions}>
            <Button type="submit" variant="danger" disabled={pending || confirm.trim() === ''}>
              {pending ? 'Erasing...' : 'Erase tenant data'}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
          </span>
        </form>
      )}
    </Modal>
  )
}

/** SupportCard (S-EE4, core): deep health per component + a one-click
 *  secret-stripped support bundle for triage. The bundle never contains
 *  credentials or PII. */
export function SupportCard() {
  const { locale, t } = useI18n()
  const { data, isPending, isError, refetch, isFetching } = useDiagnostics()
  const checks = data?.checks ?? []
  const findings = checks.flatMap((check) => (check.finding ? [check.finding] : []))
  const missingFindings = checks.filter((check) => check.status !== 'ok' && !check.finding).length
  const selfMetrics = data?.self_metrics
  const build = data?.build
  const selfMetricsReady = hasCompleteSelfMetrics(selfMetrics)
  const buildReady = hasCompleteBuildIdentity(build)
  const selfMetricRows = selfMetricsReady
    ? [
        {
          id: 'goroutines',
          metric: t('admin.support.metrics.goroutines'),
          value: formatInteger(selfMetrics.goroutines, locale),
        },
        {
          id: 'mem-alloc',
          metric: t('admin.support.metrics.allocatedMemory'),
          value: formatScaledBytes(selfMetrics.mem_alloc_bytes, locale),
        },
        {
          id: 'mem-sys',
          metric: t('admin.support.metrics.runtimeMemory'),
          value: formatScaledBytes(selfMetrics.mem_sys_bytes, locale),
        },
        {
          id: 'gc',
          metric: t('admin.support.metrics.garbageCollections'),
          value: formatInteger(selfMetrics.num_gc, locale),
        },
        {
          id: 'uptime',
          metric: t('admin.support.metrics.uptime'),
          // DPR-186: uptime in raw seconds is a number nobody converts.
          value: t('admin.support.metrics.uptimeValue', {
            duration: formatDuration(selfMetrics.uptime_seconds, locale),
          }),
        },
        {
          id: 'capacity',
          metric: t('admin.support.metrics.processCapacity'),
          value: formatInteger(selfMetrics.max_procs, locale),
        },
      ]
    : []
  const buildRows = buildReady
    ? [
        { id: 'version', field: t('admin.support.build.version'), value: build.version },
        { id: 'commit', field: t('admin.support.build.commit'), value: build.commit },
        { id: 'built', field: t('admin.support.build.built'), value: build.date },
        { id: 'go', field: t('admin.support.build.goRuntime'), value: build.go_version },
        {
          id: 'platform',
          field: t('admin.support.build.platform'),
          value: `${build.os}/${build.arch}`,
        },
      ]
    : []

  const tone = (s: HealthStatus) =>
    s === 'ok' ? 'success' : s === 'degraded' ? 'warning' : 'danger'

  return (
    <Card id="support-bundle">
      <CardHeader
        title="Support & diagnostics"
        description="Deep health across components, and a one-click support bundle (versions, redacted config, health, self-metrics, anonymized topology) — secret-stripped: never contains credentials or PII."
      />
      <CardBody>
        <p className={styles.editionsLede}>
          {data ? (
            <Badge tone={tone(data.status)}>{data.status}</Badge>
          ) : (
            <Badge tone="neutral">unknown</Badge>
          )}
          {' · '}
          {data ? (
            <>
              checked <DateTime value={data.checked_at} /> · {findings.length}{' '}
              {findings.length === 1 ? 'finding' : 'findings'} ·{' '}
            </>
          ) : null}
          <a href="/v1/diagnostics/bundle" download>
            Download support bundle (tar.gz)
          </a>
        </p>
        {isPending ? (
          <LoadingState label="Running health checks…" />
        ) : isError ? (
          <>
            <ErrorState description="Could not load diagnostics. No healthy state is being inferred." />
            <Button
              onClick={() => {
                void refetch()
              }}
              disabled={isFetching}
            >
              {isFetching ? 'Retrying…' : 'Retry diagnostics'}
            </Button>
          </>
        ) : (
          <div className={styles.form}>
            {missingFindings > 0 ? (
              <p role="alert" className={styles.editionsLede}>
                {missingFindings} unhealthy{' '}
                {missingFindings === 1 ? 'component is' : 'components are'} missing finding details.
                Review component health and retry after all control-plane replicas are upgraded.
              </p>
            ) : null}
            <p className={styles.editionsLede}>
              <strong>{t('admin.support.self.title')}</strong>
              {' · '}
              {t('admin.support.self.description')}
            </p>
            {selfMetricsReady ? (
              <Table
                caption={t('admin.support.metrics.caption')}
                columns={[
                  {
                    key: 'metric',
                    header: t('admin.support.metrics.column.metric'),
                    render: (row) => row.metric,
                  },
                  {
                    key: 'value',
                    header: t('admin.support.metrics.column.value'),
                    render: (row) => row.value,
                  },
                ]}
                rows={selfMetricRows}
                rowKey={(row) => row.id}
              />
            ) : (
              <p role="status" className={styles.editionsLede}>
                {t('admin.support.metrics.unavailable')}
              </p>
            )}
            {buildReady ? (
              <Table
                caption={t('admin.support.build.caption')}
                columns={[
                  {
                    key: 'field',
                    header: t('admin.support.build.column.field'),
                    render: (row) => row.field,
                  },
                  {
                    key: 'value',
                    header: t('admin.support.build.column.value'),
                    render: (row) => <code>{row.value}</code>,
                  },
                ]}
                rows={buildRows}
                rowKey={(row) => row.id}
              />
            ) : (
              <p role="status" className={styles.editionsLede}>
                {t('admin.support.build.unavailable')}
              </p>
            )}
            <Table
              caption="Actionable readiness findings"
              columns={[
                {
                  key: 'severity',
                  header: 'Severity',
                  render: (f) =>
                    f.severity === 'critical' ? (
                      <StatusDot tone="danger" label="Critical" />
                    ) : (
                      <StatusDot tone="warning" label="Warning" />
                    ),
                },
                {
                  key: 'component',
                  header: 'Component',
                  render: (f) => <code>{f.component}</code>,
                },
                {
                  key: 'finding',
                  header: 'Finding',
                  render: (f) => (
                    <>
                      <strong>{f.summary}</strong>
                      <br />
                      <span>{f.evidence}</span>
                    </>
                  ),
                },
                {
                  key: 'action',
                  header: 'Safe local action',
                  render: (f) => (
                    <a href={f.next_action.href} download={f.next_action.kind === 'download'}>
                      {f.next_action.label}
                    </a>
                  ),
                },
              ]}
              rows={findings}
              rowKey={(f) => f.id}
              empty={
                <EmptyState
                  icon="admin"
                  title={
                    data?.status === 'ok' ? 'No readiness findings' : 'Finding details unavailable'
                  }
                  description={
                    data?.status === 'ok'
                      ? 'Every reported component is healthy.'
                      : 'Review component health below; no healthy state is being inferred.'
                  }
                />
              }
            />
            <Table
              caption="Component health"
              columns={[
                {
                  key: 'name',
                  header: 'Component',
                  render: (c: { name: string }) => <code>{c.name}</code>,
                },
                {
                  key: 'status',
                  header: 'Status',
                  render: (c: { status: HealthStatus }) =>
                    c.status === 'ok' ? (
                      <StatusDot tone="success" label="OK" />
                    ) : c.status === 'degraded' ? (
                      <StatusDot tone="warning" label="Degraded" />
                    ) : (
                      <StatusDot tone="danger" label="Down" />
                    ),
                },
                {
                  key: 'detail',
                  header: 'Detail',
                  render: (c: { detail?: string }) => c.detail || '—',
                },
              ]}
              rows={checks}
              rowKey={(c) => c.name}
              empty={<EmptyState icon="admin" title="No checks" description="—" />}
            />
          </div>
        )}
      </CardBody>
    </Card>
  )
}

function hasCompleteSelfMetrics(
  metrics: SelfMetricsSnapshot | undefined,
): metrics is SelfMetricsSnapshot {
  if (!metrics) return false
  return (
    [
      metrics.goroutines,
      metrics.mem_alloc_bytes,
      metrics.mem_sys_bytes,
      metrics.num_gc,
      metrics.uptime_seconds,
    ].every((value) => Number.isFinite(value) && value >= 0) &&
    Number.isFinite(metrics.max_procs) &&
    metrics.max_procs >= 1
  )
}

function hasCompleteBuildIdentity(build: Version | undefined): build is Version {
  if (!build) return false
  return [build.version, build.commit, build.date, build.go_version, build.os, build.arch].every(
    (value) => typeof value === 'string' && value.trim() !== '',
  )
}

/** EditionsCard (S-T0) is the ONE place tiers appear when unlicensed — the
 *  hidden-unlicensed doctrine: no lockware anywhere else in the product. */
export function EditionsCard() {
  const { data, isPending, isError } = useEditions()

  const stateBadge = () => {
    switch (data?.state) {
      case 'active':
        return <Badge tone="success">active</Badge>
      case 'grace':
        return <Badge tone="warning">expired — grace period</Badge>
      case 'read_only':
        return <Badge tone="danger">expired — read-only</Badge>
      default:
        return <Badge tone="neutral">community</Badge>
    }
  }

  const featureLabel = (f: FeatureInfo) => f.display_name || f.name
  const columns: Column<FeatureInfo>[] = [
    {
      key: 'feature',
      header: 'Feature',
      render: (f) => (
        <>
          <span>{featureLabel(f)}</span>
          {f.display_name && f.display_name !== f.name ? (
            <>
              {' '}
              · <code>{f.name}</code>
            </>
          ) : null}
        </>
      ),
    },
    { key: 'tier', header: 'Tier', render: (f) => f.tier },
    {
      key: 'state',
      header: 'State',
      render: (f) =>
        !f.licensed ? (
          <StatusDot tone="neutral" label="Not licensed" />
        ) : f.mode === 'read_only' ? (
          <StatusDot tone="danger" label="Read-only" />
        ) : (
          <StatusDot tone="success" label="Enabled" />
        ),
    },
  ]

  return (
    <Card id="editions">
      <CardHeader
        title="Editions"
        description="License state and the commercial feature map. Verification is offline (no phone-home); expiry degrades read-only after a 30-day grace — running telemetry never breaks."
      />
      <CardBody>
        {isPending ? (
          <LoadingState label="Loading license state…" />
        ) : isError ? (
          <ErrorState description="Could not load the editions state." />
        ) : (
          <>
            <p className={styles.editionsLede}>
              {stateBadge()} <strong>{(data?.tier ?? 'core').toUpperCase()}</strong>
              {data?.customer ? (
                <> · licensed to {data.customer}</>
              ) : (
                <> — the full core, free forever</>
              )}
              {data?.pricing_model ? <> · {data.pricing_model} pricing</> : null}
              {data?.expires_at ? (
                <>
                  {' '}
                  · expires <DateTime value={data.expires_at} />
                </>
              ) : null}
              {data?.state === 'grace' && data.read_only_at ? (
                <>
                  {' '}
                  · read-only from <DateTime value={data.read_only_at} />
                </>
              ) : null}
              {data?.tenant_band ? <> · tenant band {data.tenant_band}</> : null}
              {typeof data?.trust_anchors === 'number' ? (
                data.trust_anchors > 0 ? (
                  <>
                    {' '}
                    · build trusts {data.trust_anchors} license signing{' '}
                    {data.trust_anchors === 1 ? 'key' : 'keys'}
                  </>
                ) : (
                  <>
                    {' '}
                    · <Badge tone="warning">keyless build</Badge> — license files cannot be verified
                  </>
                )
              ) : null}
            </p>
            {data?.meters?.length ? (
              <p className={styles.editionsLede}>
                MSP consumption meters: <code>{data.meters.join(', ')}</code> · operator-run export
                only; never phone-home
              </p>
            ) : null}
            {data?.fips && (data.fips.build_tag || data.fips.module_active) ? (
              <p className={styles.editionsLede}>
                <Badge tone={data.fips.module_active ? 'success' : 'warning'}>
                  FIPS{' '}
                  {data.fips.module_active
                    ? `mode active${data.fips.module_version ? ` · ${data.fips.module_version}` : ''}`
                    : 'build (module inactive)'}
                </Badge>
                {data.fips.self_test_passed ? (
                  <> · crypto self-test passed</>
                ) : (
                  <> · self-test not confirmed</>
                )}
                {data.fips.enforced ? <> · enforced</> : null}
              </p>
            ) : null}
            <Table
              caption="Commercial features by tier"
              columns={columns}
              rows={data?.features ?? []}
              rowKey={(f) => f.name}
              empty={<EmptyState icon="admin" title="No feature table" description="—" />}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}
