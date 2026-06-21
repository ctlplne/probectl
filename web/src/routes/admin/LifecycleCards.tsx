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
  type LifecycleStoreResult,
} from '../../api/lifecycle'
import { useDiagnostics, type HealthStatus } from '../../api/diagnostics'
import { DateTime } from '../../time/DateTime'

/** LifecycleCard (S-T5, core): self-service data export, the retention
 *  control, and residency/isolation visibility — export + verifiable
 *  deletion are a compliance right, present in every edition. */
export function LifecycleCard() {
  const { data, isPending, isError } = useLifecycle()
  const saveRetention = useSaveLifecycleRetention()
  const eraseTenant = useEraseTenantLifecycle()
  const [days, setDays] = useState('')
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
      await saveRetention.mutateAsync({
        flow_retention_days: days === '' ? null : Number(days),
      })
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
        description="Export your tenant's data (portability bundle), tighten flow retention, see where your data lives, and run slug-confirmed verifiable erasure."
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
            <form
              className={styles.actions}
              onSubmit={(e) => {
                void save(e)
              }}
            >
              <Field
                label="Flow retention days (blank = deployment default)"
                inputMode="numeric"
                value={days}
                onChange={(e) => setDays(e.target.value)}
                placeholder={
                  data?.flow_retention_days != null ? String(data.flow_retention_days) : 'default'
                }
              />
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
            Type the tenant slug exactly; the control plane validates it against the tenant
            registry and records the audit event.
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
  const { data, isPending, isError } = useDiagnostics()

  const tone = (s: HealthStatus) =>
    s === 'ok' ? 'success' : s === 'degraded' ? 'warning' : 'danger'

  return (
    <Card>
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
          <a href="/v1/diagnostics/bundle" download>
            Download support bundle (tar.gz)
          </a>
        </p>
        {isPending ? (
          <LoadingState label="Running health checks…" />
        ) : isError ? (
          <ErrorState description="Could not load diagnostics." />
        ) : (
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
            rows={data?.checks ?? []}
            rowKey={(c) => c.name}
            empty={<EmptyState icon="admin" title="No checks" description="—" />}
          />
        )}
      </CardBody>
    </Card>
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

  const columns: Column<FeatureInfo>[] = [
    { key: 'feature', header: 'Feature', render: (f) => <code>{f.name}</code> },
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
    <Card>
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
              {stateBadge()} <strong>{(data?.tier ?? 'community').toUpperCase()}</strong>
              {data?.customer ? (
                <> · licensed to {data.customer}</>
              ) : (
                <> — the full core, free forever</>
              )}
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
            </p>
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
