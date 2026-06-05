// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
//
// The provider/operator console (S-T1): a VISUALLY-SEPARATE surface from any
// tenant app — its own shell, a loud PROVIDER-PLANE banner, no tenant
// indicator. It is deliberately absent from the tenant nav, and the API
// behind it 404s when unlicensed (hidden-unlicensed), which this console
// renders honestly as "not enabled".

import { useCallback, useEffect, useState } from 'react'
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Select,
  StatusDot,
  Table,
  type Column,
} from '../../../web/src/components'
import styles from './ProviderConsole.module.css'

interface Operator {
  id: string
  email: string
  name: string
  role: string
  status: string
  enrolled: boolean
}

interface Tenant {
  id: string
  slug: string
  name: string
  status: string
  isolation_model?: string
  residency?: string
}

interface FleetRow {
  tenant_id: string
  tenant_slug: string
  tenant_name: string
  tenant_status: string
  agents_total: number
  agents_online: number
  agents_stale: number
  versions: Record<string, number>
}

interface GrantRow {
  id: string
  operator_email: string
  tenant_id: string
  reason: string
  expires_at: string
  use_count: number
  state: string
}

interface LicenseInfo {
  tier: string
  state: string
  customer?: string
  tenant_band?: number
}

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (res.status === 404) throw new NotEnabledError()
  if (!res.ok) {
    const payload = (await res.json().catch(() => null)) as { error?: { message?: string; code?: string } } | null
    throw new APIError(payload?.error?.code ?? 'error', payload?.error?.message ?? `HTTP ${res.status}`)
  }
  return (await res.json()) as T
}

class NotEnabledError extends Error {
  constructor() {
    super('provider plane not enabled')
  }
}

class APIError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}

/** The console root: not-enabled / login / dashboard. */
export function ProviderConsole() {
  const [phase, setPhase] = useState<'probe' | 'login' | 'dashboard' | 'disabled'>('probe')
  const [operator, setOperator] = useState<Operator | null>(null)

  useEffect(() => {
    let cancelled = false
    api<{ operator: Operator }>('GET', '/provider/v1/me')
      .then((r) => {
        if (!cancelled) {
          setOperator(r.operator)
          setPhase('dashboard')
        }
      })
      .catch((err) => {
        if (cancelled) return
        setPhase(err instanceof NotEnabledError ? 'disabled' : 'login')
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className={styles.shell}>
      <header className={styles.domainBanner}>
        <h1 className={styles.domainName}>probectl · PROVIDER PLANE</h1>
        <Badge tone="warning">operator domain — no tenant context</Badge>
        {operator ? (
          <Badge tone="info">
            {operator.email} ({operator.role})
          </Badge>
        ) : null}
      </header>
      <main className={styles.main}>
        {phase === 'probe' ? <LoadingState label="Checking the provider plane…" /> : null}
        {phase === 'disabled' ? (
          <>
            {/* keep the h1→h2→h3 ladder intact for the EmptyState's h3 */}
            <h2 className={styles.title}>Provider plane not enabled</h2>
            <EmptyState
              icon="admin"
              title="No provider license"
              description="This deployment has no provider/MSP license, so the operator console is inactive. Tenant observability is unaffected."
            />
          </>
        ) : null}
        {phase === 'login' ? (
          <LoginScreen
            onLoggedIn={(op) => {
              setOperator(op)
              setPhase('dashboard')
            }}
          />
        ) : null}
        {phase === 'dashboard' && operator ? <Dashboard operator={operator} /> : null}
      </main>
    </div>
  )
}

function LoginScreen({ onLoggedIn }: { onLoggedIn: (op: Operator) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const r = await api<{ operator: Operator }>('POST', '/provider/v1/auth/login', {
        email,
        password,
        totp,
      })
      onLoggedIn(r.operator)
    } catch {
      setError('Login failed. Check the email, password, and authenticator code.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={styles.loginWrap}>
      <Card>
        <CardHeader
          title="Operator sign-in"
          description="Provider operators authenticate with a password AND an authenticator code — MFA is mandatory in this domain."
        />
        <CardBody>
          <form className={styles.form} onSubmit={submit}>
            <Field label="Email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
            <Field label="Password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <Field label="Authenticator code" inputMode="numeric" value={totp} onChange={(e) => setTotp(e.target.value)} required />
            {error ? <p role="alert" className={styles.note}>{error}</p> : null}
            <Button type="submit" variant="primary" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </CardBody>
      </Card>
    </div>
  )
}

function Dashboard({ operator }: { operator: Operator }) {
  const [license, setLicense] = useState<LicenseInfo | null>(null)
  useEffect(() => {
    api<LicenseInfo>('GET', '/provider/v1/license').then(setLicense).catch(() => setLicense(null))
  }, [])
  const readOnly = license?.state === 'read_only'

  return (
    <>
      <h2 className={styles.title}>Provider console</h2>
      {license ? (
        <p className={styles.note}>
          License: <strong>{license.tier}</strong> · {license.state}
          {license.tenant_band ? <> · tenant band {license.tenant_band}</> : null}
          {license.state === 'grace' ? ' — renew before the grace period ends; the plane then degrades read-only.' : null}
          {readOnly ? ' — READ-ONLY: lifecycle changes are blocked; running telemetry is unaffected.' : null}
        </p>
      ) : null}
      <TenantsCard readOnly={readOnly} />
      <FleetCard />
      <UsageCard isAdmin={operator.role === 'admin'} readOnly={readOnly} />
      <BreakGlassCard />
      {operator.role === 'admin' ? <OperatorsCard readOnly={readOnly} /> : null}
    </>
  )
}

function TenantsCard({ readOnly }: { readOnly: boolean }) {
  const [tenants, setTenants] = useState<Tenant[] | null>(null)
  const [error, setError] = useState('')
  const [slug, setSlug] = useState('')
  const [name, setName] = useState('')
  const [isolation, setIsolation] = useState('pooled')
  const [residency, setResidency] = useState('')

  const load = useCallback(() => {
    api<{ items: Tenant[] }>('GET', '/provider/v1/tenants')
      .then((r) => setTenants(r.items ?? []))
      .catch((e: Error) => setError(e.message))
  }, [])
  useEffect(load, [load])

  const provision = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await api('POST', '/provider/v1/tenants', {
        slug,
        name,
        isolation_model: isolation,
        residency: isolation === 'pooled' ? '' : residency,
      })
      setSlug('')
      setName('')
      setResidency('')
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const act = async (id: string, action: 'suspend' | 'resume' | 'offboard') => {
    setError('')
    try {
      await api('POST', `/provider/v1/tenants/${id}/${action}`)
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const columns: Column<Tenant>[] = [
    { key: 'slug', header: 'Slug', render: (t) => <code>{t.slug}</code> },
    { key: 'name', header: 'Name', render: (t) => t.name },
    {
      key: 'isolation',
      header: 'Isolation',
      render: (t) => (
        <>
          <Badge tone={t.isolation_model === 'siloed' ? 'accent' : t.isolation_model === 'hybrid' ? 'info' : 'neutral'}>
            {t.isolation_model || 'pooled'}
          </Badge>
          {t.residency ? <> {t.residency}</> : null}
        </>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (t) =>
        t.status === 'active' ? (
          <StatusDot tone="success" label="Active" />
        ) : t.status === 'suspended' ? (
          <StatusDot tone="danger" label="Suspended" />
        ) : (
          <StatusDot tone="neutral" label={t.status} />
        ),
    },
    {
      key: 'actions',
      header: 'Lifecycle',
      render: (t) => (
        <span className={styles.actions}>
          {t.status === 'active' ? (
            <Button size="sm" variant="secondary" disabled={readOnly} onClick={() => act(t.id, 'suspend')}>
              Suspend
            </Button>
          ) : null}
          {t.status === 'suspended' ? (
            <Button size="sm" variant="secondary" disabled={readOnly} onClick={() => act(t.id, 'resume')}>
              Resume
            </Button>
          ) : null}
          {t.status === 'active' || t.status === 'suspended' ? (
            <Button size="sm" variant="danger" disabled={readOnly} onClick={() => act(t.id, 'offboard')}>
              Offboard
            </Button>
          ) : null}
        </span>
      ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Tenants"
        description="Lifecycle metadata only. Suspension blocks the tenant's users at the API; data and ingestion are untouched. Offboarding removes a siloed/hybrid tenant's isolated stores; pooled-data export/deletion is the S-T5 compliance flow."
      />
      <CardBody>
        {tenants === null ? (
          <LoadingState label="Loading tenants…" />
        ) : (
          <>
            <form className={styles.row} onSubmit={provision}>
              <span className={styles.grow}>
                <Field label="New tenant slug" value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="acme" required disabled={readOnly} />
              </span>
              <span className={styles.grow}>
                <Field label="Display name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Industries" required disabled={readOnly} />
              </span>
              <Select
                label="Isolation"
                value={isolation}
                onChange={(e) => setIsolation(e.target.value)}
                disabled={readOnly}
                options={[
                  { value: 'pooled', label: 'pooled (default)' },
                  { value: 'siloed', label: 'siloed' },
                  { value: 'hybrid', label: 'hybrid' },
                ]}
              />
              {isolation !== 'pooled' ? (
                <span className={styles.grow}>
                  <Field label="Residency (data plane, optional)" value={residency} onChange={(e) => setResidency(e.target.value)} placeholder="eu" disabled={readOnly} />
                </span>
              ) : null}
              <Button type="submit" variant="primary" disabled={readOnly}>
                Provision
              </Button>
            </form>
            {error ? <p role="alert" className={styles.note}>{error}</p> : null}
            <Table
              caption="Tenant inventory"
              columns={columns}
              rows={tenants}
              rowKey={(t) => t.id}
              empty={<EmptyState icon="admin" title="No tenants" description="Provision the first tenant above." />}
            />
          </>
        )}
      </CardBody>
    </Card>
  )
}

function FleetCard() {
  const [rows, setRows] = useState<FleetRow[] | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    api<{ items: FleetRow[] }>('GET', '/provider/v1/fleet')
      .then((r) => setRows(r.items ?? []))
      .catch(() => setFailed(true))
  }, [])

  const columns: Column<FleetRow>[] = [
    { key: 'tenant', header: 'Tenant', render: (f) => <code>{f.tenant_slug}</code> },
    { key: 'total', header: 'Agents', render: (f) => f.agents_total },
    {
      key: 'online',
      header: 'Online',
      render: (f) =>
        f.agents_total === 0 ? (
          '—'
        ) : f.agents_online === f.agents_total ? (
          <StatusDot tone="success" label={String(f.agents_online)} />
        ) : (
          <StatusDot tone="danger" label={`${f.agents_online}/${f.agents_total}`} />
        ),
    },
    { key: 'stale', header: 'Stale (>5m)', render: (f) => (f.agents_stale > 0 ? <Badge tone="warning">{f.agents_stale}</Badge> : '0') },
    {
      key: 'versions',
      header: 'Versions',
      render: (f) =>
        Object.entries(f.versions ?? {})
          .map(([v, n]) => `${v}×${n}`)
          .join(', ') || '—',
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Fleet across tenants"
        description="Agent health per tenant — counts and versions only. Operators hold no implicit access to tenant telemetry; the storage role physically cannot read it."
      />
      <CardBody>
        {failed ? (
          <ErrorState description="Could not load the fleet view." />
        ) : rows === null ? (
          <LoadingState label="Aggregating fleet health…" />
        ) : (
          <Table
            caption="Fleet across tenants"
            columns={columns}
            rows={rows}
            rowKey={(f) => f.tenant_id}
            empty={<EmptyState icon="admin" title="No tenants yet" description="Fleet health appears once tenants run agents." />}
          />
        )}
      </CardBody>
    </Card>
  )
}

function BreakGlassCard() {
  const [grants, setGrants] = useState<GrantRow[] | null>(null)
  const [tenantID, setTenantID] = useState('')
  const [reason, setReason] = useState('')
  const [ttl, setTtl] = useState('60')
  const [error, setError] = useState('')

  const load = useCallback(() => {
    api<{ items: GrantRow[] }>('GET', '/provider/v1/breakglass')
      .then((r) => setGrants(r.items ?? []))
      .catch((e: Error) => setError(e.message))
  }, [])
  useEffect(load, [load])

  const request = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await api('POST', '/provider/v1/breakglass', {
        tenant_id: tenantID,
        reason,
        ttl_minutes: Number(ttl),
      })
      setReason('')
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const revoke = async (id: string) => {
    setError('')
    try {
      await api('POST', `/provider/v1/breakglass/${id}/revoke`)
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const toneFor = (state: string) =>
    state === 'active' ? 'danger' : state === 'pending' ? 'warning' : 'neutral'

  const columns: Column<GrantRow>[] = [
    { key: 'tenant', header: 'Tenant', render: (g) => <code>{g.tenant_id}</code> },
    { key: 'operator', header: 'Operator', render: (g) => g.operator_email },
    { key: 'reason', header: 'Reason', render: (g) => g.reason },
    { key: 'state', header: 'State', render: (g) => <Badge tone={toneFor(g.state)}>{g.state}</Badge> },
    { key: 'uses', header: 'Audited uses', render: (g) => g.use_count },
    {
      key: 'actions',
      header: 'Actions',
      render: (g) =>
        g.state === 'active' || g.state === 'pending' ? (
          <Button size="sm" variant="secondary" onClick={() => revoke(g.id)}>
            Revoke
          </Button>
        ) : null,
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Break-glass"
        description="The ONLY path to tenant telemetry: explicit, time-bounded, and usable only after the tenant's admin consents. Every access is written to the provider audit stream."
      />
      <CardBody>
        <form className={styles.row} onSubmit={request}>
          <span className={styles.grow}>
            <Field label="Tenant ID" value={tenantID} onChange={(e) => setTenantID(e.target.value)} required />
          </span>
          <span className={styles.grow}>
            <Field label="Reason (required — it is audited)" value={reason} onChange={(e) => setReason(e.target.value)} required />
          </span>
          <Select
            label="TTL"
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            options={[
              { value: '30', label: '30 minutes' },
              { value: '60', label: '1 hour' },
              { value: '240', label: '4 hours' },
            ]}
          />
          <Button type="submit" variant="primary">Request access</Button>
        </form>
        {error ? <p role="alert" className={styles.note}>{error}</p> : null}
        {grants === null ? (
          <LoadingState label="Loading grants…" />
        ) : (
          <Table
            caption="Break-glass grants"
            columns={columns}
            rows={grants}
            rowKey={(g) => g.id}
            empty={<EmptyState icon="admin" title="No grants" description="No break-glass access has been requested." />}
          />
        )}
      </CardBody>
    </Card>
  )
}

interface UsageRow {
  tenant_id: string
  tenant_slug: string
  meter: string
  kind: string
  period_start: string
  period_end: string
  value: number
  unit: string
}

/** UsageCard (S-T3): per-tenant showback for the current month + the
 *  billing-export feed (CSV/JSONL) + per-tenant creation quotas (admin).
 *  Hidden honestly when the metering feature is not licensed (the API 404s). */
function UsageCard({ isAdmin, readOnly }: { isAdmin: boolean; readOnly: boolean }) {
  const [rows, setRows] = useState<UsageRow[] | null>(null)
  const [enabled, setEnabled] = useState(true)
  const [quotaTenant, setQuotaTenant] = useState('')
  const [maxAgents, setMaxAgents] = useState('')
  const [maxTests, setMaxTests] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api<{ items: UsageRow[] }>('GET', '/provider/v1/usage?rollup=day')
      .then((r) => setRows(r.items ?? []))
      .catch((err) => {
        if (err instanceof NotEnabledError) setEnabled(false)
        else setError((err as Error).message)
      })
  }, [])

  if (!enabled) return null // metering not licensed: no lockware, no card

  // Aggregate the month per tenant × meter (rows are daily).
  const perTenant = new Map<string, Record<string, number>>()
  for (const r of rows ?? []) {
    const m = perTenant.get(r.tenant_slug) ?? {}
    m[r.meter] = r.kind === 'gauge' ? Math.max(m[r.meter] ?? 0, r.value) : (m[r.meter] ?? 0) + r.value
    perTenant.set(r.tenant_slug, m)
  }
  const tenants = [...perTenant.entries()].map(([slug, meters]) => ({ slug, ...meters })) as Array<
    { slug: string } & Record<string, number>
  >

  const meterCols = ['agents', 'tests', 'results_ingested', 'ingest_bytes', 'flow_events', 'ai_calls']
  const columns: Column<(typeof tenants)[number]>[] = [
    { key: 'slug', header: 'Tenant', render: (t) => <code>{t.slug}</code> },
    ...meterCols.map((m) => ({
      key: m,
      header: m.replace(/_/g, ' '),
      render: (t: (typeof tenants)[number]) => ((t[m] as number | undefined) ?? 0).toLocaleString(),
    })),
  ]

  const saveQuota = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSaved(false)
    try {
      await api('PUT', `/provider/v1/tenants/${quotaTenant}/quotas`, {
        max_agents: maxAgents === '' ? null : Number(maxAgents),
        max_tests: maxTests === '' ? null : Number(maxTests),
      })
      setSaved(true)
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <Card>
      <CardHeader
        title="Usage & showback"
        description="Month-to-date per-tenant usage, metered from the streams already flowing. Export feeds your PSA/billing system (CSV/JSONL, stable columns). Quotas gate resource creation only — telemetry is never dropped."
      />
      <CardBody>
        <p className={styles.actions}>
          <a className={styles.note} href="/provider/v1/usage/export?format=csv&rollup=day" download>
            Export CSV
          </a>
          <a className={styles.note} href="/provider/v1/usage/export?format=jsonl&rollup=day" download>
            Export JSONL
          </a>
        </p>
        {rows === null ? (
          <LoadingState label="Aggregating usage…" />
        ) : (
          <Table
            caption="Usage and showback"
            columns={columns}
            rows={tenants}
            rowKey={(t) => t.slug}
            empty={<EmptyState icon="admin" title="No usage yet" description="Meters fill as tenant telemetry flows." />}
          />
        )}
        {isAdmin ? (
          <form className={styles.row} onSubmit={saveQuota}>
            <span className={styles.grow}>
              <Field label="Tenant ID (quotas)" value={quotaTenant} onChange={(e) => setQuotaTenant(e.target.value)} required disabled={readOnly} />
            </span>
            <Field label="Max agents (blank = unlimited)" inputMode="numeric" value={maxAgents} onChange={(e) => setMaxAgents(e.target.value)} disabled={readOnly} />
            <Field label="Max tests (blank = unlimited)" inputMode="numeric" value={maxTests} onChange={(e) => setMaxTests(e.target.value)} disabled={readOnly} />
            <Button type="submit" variant="primary" disabled={readOnly}>
              Save quotas
            </Button>
          </form>
        ) : null}
        {saved ? <p className={styles.note}>Quotas saved.</p> : null}
        {error ? <p role="alert" className={styles.note}>{error}</p> : null}
      </CardBody>
    </Card>
  )
}

function OperatorsCard({ readOnly }: { readOnly: boolean }) {
  const [operators, setOperators] = useState<Operator[] | null>(null)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState('operator')
  const [enrollToken, setEnrollToken] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(() => {
    api<{ items: Operator[] }>('GET', '/provider/v1/operators')
      .then((r) => setOperators(r.items ?? []))
      .catch((e: Error) => setError(e.message))
  }, [])
  useEffect(load, [load])

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      const r = await api<{ enroll_token: string }>('POST', '/provider/v1/operators', { email, name, role })
      setEnrollToken(r.enroll_token)
      setEmail('')
      setName('')
      load()
    } catch (err) {
      setError((err as Error).message)
    }
  }

  const columns: Column<Operator>[] = [
    { key: 'email', header: 'Email', render: (o) => o.email },
    { key: 'role', header: 'Role', render: (o) => <Badge tone={o.role === 'admin' ? 'warning' : 'neutral'}>{o.role}</Badge> },
    {
      key: 'status',
      header: 'Status',
      render: (o) =>
        !o.enrolled ? (
          <StatusDot tone="neutral" label="Awaiting enrollment" />
        ) : o.status === 'active' ? (
          <StatusDot tone="success" label="Active" />
        ) : (
          <StatusDot tone="danger" label={o.status} />
        ),
    },
  ]

  return (
    <Card>
      <CardHeader
        title="Operators"
        description="Separation of duties: admins manage operators; operators run tenant lifecycle and break-glass. Enrollment binds an authenticator — MFA is not optional."
      />
      <CardBody>
        <form className={styles.row} onSubmit={create}>
          <span className={styles.grow}>
            <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required disabled={readOnly} />
          </span>
          <span className={styles.grow}>
            <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required disabled={readOnly} />
          </span>
          <Select
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            disabled={readOnly}
            options={[
              { value: 'operator', label: 'operator' },
              { value: 'admin', label: 'admin' },
            ]}
          />
          <Button type="submit" variant="primary" disabled={readOnly}>
            Create
          </Button>
        </form>
        {enrollToken ? (
          <p className={styles.secret}>
            One-time enrollment token (share it over a secure channel; it is never shown again):{' '}
            <strong>{enrollToken}</strong>
          </p>
        ) : null}
        {error ? <p role="alert" className={styles.note}>{error}</p> : null}
        {operators === null ? (
          <LoadingState label="Loading operators…" />
        ) : (
          <Table
            caption="Provider operators"
            columns={columns}
            rows={operators}
            rowKey={(o) => o.id}
            empty={<EmptyState icon="admin" title="No operators" description="Bootstrap the first admin with the deployment token." />}
          />
        )}
      </CardBody>
    </Card>
  )
}
