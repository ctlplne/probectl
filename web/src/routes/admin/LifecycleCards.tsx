import { useState } from 'react'
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
  StatusDot,
  Table,
} from '../../components'
import { useEditions, type FeatureInfo } from '../../api/editions'
import { useLifecycle, useSaveLifecycleRetention } from '../../api/lifecycle'
import { useDiagnostics, type HealthStatus } from '../../api/diagnostics'

/** LifecycleCard (S-T5, core): self-service data export, the retention
 *  control, and residency/isolation visibility — export + verifiable
 *  deletion are a compliance right, present in every edition. */
export function LifecycleCard() {
  const { data, isPending, isError } = useLifecycle()
  const saveRetention = useSaveLifecycleRetention()
  const [days, setDays] = useState('')
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

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

  return (
    <Card>
      <CardHeader
        title="Data lifecycle"
        description="Export your tenant's data (portability bundle), tighten flow retention, and see where your data lives. Verifiable erasure is available via the API/runbook — it is irreversible and slug-confirmed."
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
            <form className={styles.actions} onSubmit={save}>
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
          </>
        )}
      </CardBody>
    </Card>
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
                <> · expires {new Date(data.expires_at).toLocaleDateString()}</>
              ) : null}
              {data?.state === 'grace' && data.read_only_at ? (
                <> · read-only from {new Date(data.read_only_at).toLocaleDateString()}</>
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
