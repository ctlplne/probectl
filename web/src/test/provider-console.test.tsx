import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'

/** S-T1 surface: the provider/operator console at /provider — a visually-
 *  separate privilege domain (no tenant shell, no tenant indicator), hidden
 *  behind a 404 when the deployment is unlicensed. */

const operator = { id: 'op_1', email: 'root@msp.example', name: 'Root', role: 'admin', status: 'active', enrolled: true }
const tenants = [
  { id: 'tn_1', slug: 'acme', name: 'Acme Industries', status: 'active', isolation_model: 'pooled', created_at: '2026-06-01T00:00:00Z' },
  { id: 'tn_2', slug: 'globex', name: 'Globex', status: 'suspended', isolation_model: 'siloed', residency: 'eu', created_at: '2026-06-02T00:00:00Z' },
]
const fleet = [
  { tenant_id: 'tn_1', tenant_slug: 'acme', tenant_name: 'Acme Industries', tenant_status: 'active', agents_total: 3, agents_online: 2, agents_stale: 1, versions: { '0.3.0': 3 } },
  { tenant_id: 'tn_2', tenant_slug: 'globex', tenant_name: 'Globex', tenant_status: 'suspended', agents_total: 1, agents_online: 1, agents_stale: 0, versions: { '0.2.9': 1 } },
]
const grants = [
  { id: 'bg_1', operator_email: 'root@msp.example', tenant_id: 'tn_1', reason: 'incident #42', scope: 'read', expires_at: '2026-06-05T12:00:00Z', use_count: 2, state: 'active' },
  { id: 'bg_2', operator_email: 'root@msp.example', tenant_id: 'tn_2', reason: 'migration check', scope: 'read', expires_at: '2026-06-05T12:00:00Z', use_count: 0, state: 'pending' },
]

function providerStub(opts?: { loggedIn?: boolean; readOnly?: boolean }) {
  const loggedIn = opts?.loggedIn ?? true
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.endsWith('/provider/v1/me'))
      return loggedIn ? jsonResponse({ operator }) : jsonResponse({ error: { code: 'unauthorized', message: 'no session' } }, 401)
    if (url.endsWith('/provider/v1/auth/login') && method === 'POST')
      return jsonResponse({ operator, token: 't' })
    if (url.endsWith('/provider/v1/license'))
      return jsonResponse({ tier: 'provider', state: opts?.readOnly ? 'read_only' : 'active', customer: 'MSP Test GmbH', tenant_band: 25 })
    if (url.endsWith('/provider/v1/tenants') && method === 'GET') return jsonResponse({ items: tenants })
    if (url.endsWith('/provider/v1/tenants') && method === 'POST')
      return jsonResponse({ id: 'tn_new', slug: 'silo-co', name: 'Silo Co', status: 'active', isolation_model: 'siloed', residency: 'eu' }, 201)
    if (url.endsWith('/provider/v1/fleet')) return jsonResponse({ items: fleet })
    if (url.endsWith('/provider/v1/breakglass') && method === 'GET') return jsonResponse({ items: grants })
    if (url.endsWith('/provider/v1/operators') && method === 'GET') return jsonResponse({ items: [operator] })
    if (url.includes('/provider/v1/usage') && method === 'GET')
      return jsonResponse({
        items: [
          { tenant_id: 'tn_1', tenant_slug: 'acme', meter: 'results_ingested', kind: 'counter', period_start: '2026-06-05T00:00:00Z', period_end: '2026-06-06T00:00:00Z', value: 1042, unit: 'count' },
          { tenant_id: 'tn_1', tenant_slug: 'acme', meter: 'agents', kind: 'gauge', period_start: '2026-06-05T00:00:00Z', period_end: '2026-06-06T00:00:00Z', value: 3, unit: 'count' },
          { tenant_id: 'tn_2', tenant_slug: 'globex', meter: 'ai_calls', kind: 'counter', period_start: '2026-06-05T00:00:00Z', period_end: '2026-06-06T00:00:00Z', value: 7, unit: 'count' },
        ],
        meters: ['agents', 'tests', 'results_ingested', 'ingest_bytes', 'flow_events', 'ai_calls'],
      })
    if (url.includes('/provider/v1/tenants/tn_1/quotas') && method === 'PUT')
      return jsonResponse({ tenant_id: 'tn_1', max_agents: 5, max_tests: null })
    if (url.endsWith('/provider/v1/fairness') && method === 'GET')
      return jsonResponse({
        items: [
          {
            tenant_id: 'tn_1',
            policy: { results_per_sec: 100, queries_per_min: 60, burst_seconds: 10 },
            ingest: { results_ingested: { admitted_calls: 900, admitted_units: 900, shed_calls: 40, shed_units: 40 } },
            queries: { allowed: 50, rejected_concurrency: 0, rejected_budget: 13, in_flight: 1 },
          },
          {
            tenant_id: 'tn_2',
            policy: {},
            ingest: {},
            queries: { allowed: 4, rejected_concurrency: 0, rejected_budget: 0, in_flight: 0 },
          },
        ],
        overrides: {},
      })
    if (url.includes('/provider/v1/tenants/tn_1/fairness') && method === 'PUT')
      return jsonResponse({ results_per_sec: 250, flow_events_per_sec: 0, queries_per_min: 0, query_concurrency: 4 })
    if (url.includes('/provider/v1/tenants/tn_1/governance') && method === 'GET')
      return jsonResponse({
        classifications: { ip_address: 'pii', hostname: 'internal', credential: 'restricted', email: 'pii', asn: 'public' },
        redact_from: 'pii', redact_export: false, residency: 'eu', isolation_model: 'siloed', retention_days: 30, byok: 'byok',
      })
    if (url.includes('/provider/v1/tenants/tn_1/governance') && method === 'PUT')
      return jsonResponse({ ok: true })
    if (url.endsWith('/provider/v1/branding') && method === 'GET') return jsonResponse({ product_name: '' })
    if (url.includes('/provider/v1/tenants/tn_1/branding') && method === 'PUT')
      return jsonResponse({ tenant_id: 'tn_1', product_name: 'AcmeWatch' })
    if (url.includes('/provider/v1/tenants/tn_1/suspend') && method === 'POST')
      return jsonResponse({ ...tenants[0], status: 'suspended' })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('provider console (S-T1)', () => {
  test('hidden-unlicensed honesty: a 404 API renders "not enabled", never a broken console', async () => {
    vi.stubGlobal('fetch', defaultFetch()) // no provider endpoints stubbed = 404s
    renderApp('/provider')
    expect(await screen.findByText(/provider plane not enabled/i)).toBeInTheDocument()
    expect(screen.getByText(/tenant observability is unaffected/i)).toBeInTheDocument()
    // The tenant shell is NOT around this surface: no tenant nav landmarks.
    expect(screen.queryByRole('navigation')).toBeNull()
  })

  test('no session: the MFA login screen (password AND authenticator code)', async () => {
    vi.stubGlobal('fetch', providerStub({ loggedIn: false }))
    renderApp('/provider')
    expect(await screen.findByText(/operator sign-in/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/authenticator code/i)).toBeInTheDocument()
    // The domain banner brands the separate privilege domain.
    expect(screen.getByText(/PROVIDER PLANE/)).toBeInTheDocument()
    expect(screen.getByText(/operator domain — no tenant context/i)).toBeInTheDocument()
  })

  test('dashboard truth: tenants + lifecycle states, fleet counts, break-glass states, operators (admin)', async () => {
    vi.stubGlobal('fetch', providerStub())
    renderApp('/provider')

    // Tenant inventory with lifecycle states.
    const tenantsTable = (await screen.findByRole('table', { name: /tenant inventory/i })) as HTMLTableElement
    const acmeRow = within(tenantsTable).getByText('acme').closest('tr')!
    expect(within(acmeRow).getByText('Active')).toBeInTheDocument()
    expect(within(acmeRow).getByRole('button', { name: /suspend/i })).toBeInTheDocument()
    const globexRow = within(tenantsTable).getByText('globex').closest('tr')!
    expect(within(globexRow).getByText('Suspended')).toBeInTheDocument()
    expect(within(globexRow).getByRole('button', { name: /resume/i })).toBeInTheDocument()

    // Fleet: per-tenant counts + versions, metadata only.
    const fleetTable = (await screen.findByRole('table', { name: /fleet across tenants/i })) as HTMLTableElement
    const fleetAcme = within(fleetTable).getByText('acme').closest('tr')!
    expect(within(fleetAcme).getByText('2/3')).toBeInTheDocument()
    expect(within(fleetAcme).getByText('0.3.0×3')).toBeInTheDocument()

    // Break-glass: states + audited use count.
    const bgTable = (await screen.findByRole('table', { name: /break-glass grants/i })) as HTMLTableElement
    const active = within(bgTable).getByText('incident #42').closest('tr')!
    expect(within(active).getByText('active')).toBeInTheDocument()
    expect(within(active).getByText('2')).toBeInTheDocument() // audited uses
    const pending = within(bgTable).getByText('migration check').closest('tr')!
    expect(within(pending).getByText('pending')).toBeInTheDocument()

    // Admin sees the operators card (SoD surface).
    expect(await screen.findByRole('table', { name: /provider operators/i })).toBeInTheDocument()
    // License chip renders the band.
    expect(screen.getByText(/tenant band 25/)).toBeInTheDocument()
    // S-T2: isolation model + residency render per tenant.
    expect(within(acmeRow).getByText('pooled')).toBeInTheDocument()
    expect(within(globexRow).getByText('siloed')).toBeInTheDocument()
    expect(within(globexRow).getByText(/eu/)).toBeInTheDocument()
  })

  test('S-EE3 governance: the composed view loads (IPs-as-PII, residency, BYOK) and the policy PUT sends redaction settings', async () => {
    const stub = providerStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')
    expect(await screen.findByText('Data governance')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(/tenant id \(governance\)/i), 'tn_1')
    await userEvent.click(screen.getByRole('button', { name: /^load$/i }))
    // The composed view renders the redaction floor + BYOK + PII categories.
    expect(await screen.findByText(/redact from pii/i)).toBeInTheDocument()
    expect(screen.getByText('byok')).toBeInTheDocument()
    expect(screen.getAllByText('ip_address').length).toBeGreaterThan(0)
    // Force a redacted export + save → PUT carries the redaction settings.
    await userEvent.click(screen.getByLabelText(/force redacted export/i))
    await userEvent.click(screen.getByRole('button', { name: /save governance/i }))
    expect(await screen.findByText(/governance policy saved/i)).toBeInTheDocument()
    const put = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => String(c[0]).includes('/tenants/tn_1/governance') && (c[1] as RequestInit)?.method === 'PUT',
    )
    expect(put).toBeTruthy()
    expect(JSON.parse(String((put![1] as RequestInit).body))).toEqual({ redact_from: 'pii', redact_export: true })
  })

  test('S-T7 fairness: accounting renders (shed + rejections flagged) and the policy PUT sends the right payload', async () => {
    const stub = providerStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')
    expect(await screen.findByText('Fairness')).toBeInTheDocument()
    // tn_1 shows shed units + query rejections; tn_2 is unbounded.
    expect(await screen.findByText('40')).toBeInTheDocument()
    expect(screen.getByText('13')).toBeInTheDocument()
    expect(screen.getByText(/100\/s results · 60\/min queries/)).toBeInTheDocument()
    expect(screen.getByText('unbounded')).toBeInTheDocument()
    // The admin policy editor PUTs the numeric payload.
    await userEvent.type(screen.getByLabelText(/tenant id \(fairness\)/i), 'tn_1')
    await userEvent.type(screen.getByLabelText(/results\/sec/i), '250')
    await userEvent.type(screen.getByLabelText(/query concurrency/i), '4')
    await userEvent.click(screen.getByRole('button', { name: /save policy/i }))
    expect(await screen.findByText(/fairness policy saved/i)).toBeInTheDocument()
    const put = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => String(c[0]).includes('/tenants/tn_1/fairness') && (c[1] as RequestInit)?.method === 'PUT',
    )
    expect(put).toBeTruthy()
    expect(JSON.parse(String((put![1] as RequestInit).body))).toEqual({
      results_per_sec: 250,
      flow_events_per_sec: 0,
      queries_per_min: 0,
      query_concurrency: 4,
    })
  })

  test('S-T2 provisioning: the isolation select + conditional residency field send the right payload', async () => {
    const stub = providerStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')
    await screen.findByRole('table', { name: /tenant inventory/i })

    // Residency is hidden for pooled, shown for siloed/hybrid.
    expect(screen.queryByLabelText(/residency/i)).toBeNull()
    await userEvent.selectOptions(screen.getByLabelText(/isolation/i), 'siloed')
    await userEvent.type(await screen.findByLabelText(/residency/i), 'eu')
    await userEvent.type(screen.getByLabelText(/new tenant slug/i), 'silo-co')
    await userEvent.type(screen.getByLabelText(/display name/i), 'Silo Co')
    await userEvent.click(screen.getByRole('button', { name: /provision/i }))

    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls
    const post = calls.find((c) => String(c[0]).endsWith('/provider/v1/tenants') && (c[1] as RequestInit | undefined)?.method === 'POST')
    expect(post).toBeTruthy()
    const body = JSON.parse(String((post![1] as RequestInit).body))
    expect(body).toEqual({ slug: 'silo-co', name: 'Silo Co', isolation_model: 'siloed', residency: 'eu' })
  })

  test('lifecycle action fires the right call', async () => {
    const stub = providerStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')
    const tenantsTable = (await screen.findByRole('table', { name: /tenant inventory/i })) as HTMLTableElement
    const acmeRow = within(tenantsTable).getByText('acme').closest('tr')!
    await userEvent.click(within(acmeRow).getByRole('button', { name: /suspend/i }))
    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls.map((c) => `${(c[1] as RequestInit | undefined)?.method ?? 'GET'} ${String(c[0])}`)
    expect(calls.some((c) => c === 'POST /provider/v1/tenants/tn_1/suspend')).toBe(true)
  })

  test('read-only license degrade is loud and disables mutations', async () => {
    vi.stubGlobal('fetch', providerStub({ readOnly: true }))
    renderApp('/provider')
    expect(await screen.findByText(/READ-ONLY: lifecycle changes are blocked/i)).toBeInTheDocument()
    const provision = await screen.findByRole('button', { name: /provision/i })
    expect(provision).toBeDisabled()
  })

  test('S-T3 showback: month-to-date usage per tenant + the export feed links', async () => {
    vi.stubGlobal('fetch', providerStub())
    renderApp('/provider')
    const usageTable = (await screen.findByRole('table', { name: /usage and showback/i })) as HTMLTableElement
    const acme = within(usageTable).getByText('acme').closest('tr')!
    expect(within(acme).getByText('1,042')).toBeInTheDocument()
    expect(within(acme).getByText('3')).toBeInTheDocument()
    const globex = within(usageTable).getByText('globex').closest('tr')!
    expect(within(globex).getByText('7')).toBeInTheDocument()
    // The export feed (the generic CSV/JSONL contract) is one click away.
    expect(screen.getByRole('link', { name: /export csv/i })).toHaveAttribute('href', '/provider/v1/usage/export?format=csv&rollup=day')
    expect(screen.getByRole('link', { name: /export jsonl/i })).toHaveAttribute('href', '/provider/v1/usage/export?format=jsonl&rollup=day')
  })

  test('S-T3 quotas: the admin editor PUTs the right payload (blank = unlimited)', async () => {
    const stub = providerStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')
    await screen.findByRole('table', { name: /usage and showback/i })
    await userEvent.type(screen.getByLabelText(/tenant id \(quotas\)/i), 'tn_1')
    await userEvent.type(screen.getByLabelText(/max agents/i), '5')
    await userEvent.click(screen.getByRole('button', { name: /save quotas/i }))
    expect(await screen.findByText(/quotas saved/i)).toBeInTheDocument()
    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls
    const put = calls.find((c) => String(c[0]).endsWith('/provider/v1/tenants/tn_1/quotas') && (c[1] as RequestInit | undefined)?.method === 'PUT')
    expect(put).toBeTruthy()
    expect(JSON.parse(String((put![1] as RequestInit).body))).toEqual({ max_agents: 5, max_tests: null })
  })

  test('S-T3 hidden-unlicensed: a 404 usage API renders no usage card at all', async () => {
    const stub = providerStub()
    const wrapped = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes('/provider/v1/usage'))
        return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
      return (stub as unknown as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>)(input, init)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', wrapped)
    renderApp('/provider')
    await screen.findByRole('table', { name: /tenant inventory/i })
    expect(screen.queryByText(/usage & showback/i)).toBeNull()
  })

  test('S-T4 branding: the admin card PUTs the tenant brand with validated token overrides', async () => {
    const stub = providerStub()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')
    await screen.findByText(/white-label branding/i)
    await userEvent.type(screen.getByLabelText(/tenant id \(branding\)/i), 'tn_1')
    await userEvent.type(screen.getByLabelText(/product name/i), 'AcmeWatch')
    await userEvent.type(screen.getByLabelText(/accent color/i), '#ff3300')
    await userEvent.type(screen.getByLabelText(/custom domain/i), 'status.acme.example')
    await userEvent.click(screen.getByRole('button', { name: /save brand/i }))
    expect(await screen.findByText(/brand saved/i)).toBeInTheDocument()
    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls
    const put = calls.find((c) => String(c[0]).endsWith('/provider/v1/tenants/tn_1/branding') && (c[1] as RequestInit | undefined)?.method === 'PUT')
    expect(put).toBeTruthy()
    const body = JSON.parse(String((put![1] as RequestInit).body))
    expect(body.product_name).toBe('AcmeWatch')
    expect(body.custom_domain).toBe('status.acme.example')
    expect(body.token_overrides).toEqual({ '--color-accent': '#ff3300' })
  })

  test('a11y: the provider console passes the axe bar (logged-in dashboard)', async () => {
    vi.stubGlobal('fetch', providerStub())
    const { container } = renderApp('/provider')
    await screen.findByRole('table', { name: /tenant inventory/i })
    expect(await axe(container)).toHaveNoViolations()
  })
})
