import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { TLSPosture } from '../api/tls'

/** Fixtures per the sprint spec: expired / weak / self-signed / CT-anomaly,
 *  plus a clean cert (inventories that hide healthy certs hide the fleet). */
function postureFixtures(): TLSPosture[] {
  const now = Date.now()
  const days = (n: number) => new Date(now + n * 86_400_000).toISOString()
  const leaf = (subject: string, notAfter: string, extra?: Partial<TLSPosture['leaf']>) => ({
    subject,
    issuer: 'CN=ACME Issuing CA',
    serial_number: '0a',
    not_before: days(-300),
    not_after: notAfter,
    key_type: 'RSA',
    key_bits: 2048,
    signature_algorithm: 'SHA256-RSA',
    self_signed: false,
    is_ca: false,
    ...extra,
  })
  return [
    {
      target: 'expired.acme.example:443',
      source: 'http',
      tls_version: '1.2',
      cipher: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      leaf: leaf('CN=expired.acme.example', days(-2)),
      findings: [
        { kind: 'cert_expired', severity: 'critical', message: 'certificate expired 2 days ago' },
      ],
      severity: 'critical',
      handoff: {
        target: 'expired.acme.example:443',
        subject: 'CN=expired.acme.example',
        issuer: 'CN=ACME Issuing CA',
        serial: '0a',
        not_after: days(-2),
        reason: 'cert_expired',
        url: 'https://trustctl.acme.example/renew?serial=0a',
      },
      observed_at: new Date(now).toISOString(),
    },
    {
      target: 'weak.acme.example:443',
      source: 'http',
      tls_version: '1.0',
      cipher: 'TLS_RSA_WITH_RC4_128_SHA',
      leaf: leaf('CN=weak.acme.example', days(200), { key_type: 'RSA', key_bits: 1024 }),
      findings: [
        { kind: 'weak_key', severity: 'warning', message: 'RSA 1024 below minimum' },
        { kind: 'deprecated_protocol', severity: 'warning', message: 'TLS 1.0 is deprecated' },
        { kind: 'weak_cipher', severity: 'warning', message: 'RC4 cipher' },
      ],
      severity: 'warning',
      observed_at: new Date(now).toISOString(),
    },
    {
      target: 'self.acme.example:8443',
      source: 'http',
      tls_version: '1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      leaf: leaf('CN=self.acme.example', days(20), { self_signed: true }),
      findings: [
        { kind: 'cert_self_signed', severity: 'warning', message: 'self-signed leaf' },
        { kind: 'cert_expiring_soon', severity: 'warning', message: 'expires in 20 days' },
      ],
      severity: 'warning',
      observed_at: new Date(now).toISOString(),
    },
    {
      target: 'ct.acme.example:443',
      source: 'http',
      tls_version: '1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      leaf: leaf('CN=ct.acme.example', days(80)),
      findings: [
        { kind: 'ct_not_logged', severity: 'warning', message: 'leaf not found in CT logs' },
      ],
      severity: 'warning',
      observed_at: new Date(now).toISOString(),
    },
    {
      target: 'clean.acme.example:443',
      source: 'http',
      tls_version: '1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      leaf: leaf('CN=clean.acme.example', days(120)),
      findings: [],
      severity: 'info',
      observed_at: new Date(now).toISOString(),
    },
  ]
}

function intelStatusFixture() {
  return {
    open_data_enabled: true,
    threat_intel_enabled: true,
    ioc_count: 2048,
    open_data_sources: [
      {
        name: 'test_cymru',
        kind: 'asn',
        cadence_seconds: 86_400,
        aup: {
          license: 'public lookup',
          url: 'https://terms.example/opendata',
          attribution: 'Example Data',
          commercial_use: 'allowed-with-attribution',
          redistribution: 'cached lookup only',
        },
        enabled: true,
        status: 'ok',
        last_success: '2026-06-04T12:00:00Z',
        last_error: '',
      },
    ],
    threat_intel_feeds: [
      {
        name: 'feodo_tracker',
        kind: 'threat_intel',
        cadence_seconds: 3600,
        aup: {
          license: 'abuse.ch CC0',
          url: 'https://abuse.ch/',
          attribution: '',
          commercial_use: 'allowed',
          redistribution: '',
        },
        enabled: true,
        status: 'ok',
        last_success: '2026-06-04T12:00:00Z',
        last_error: '',
        ioc_count: 2048,
      },
      {
        name: 'firehol_level1',
        kind: 'threat_intel',
        cadence_seconds: 14_400,
        aup: {
          license: 'mixed terms',
          url: 'https://iplists.firehol.org/',
          attribution: '',
          commercial_use: 'restricted',
          redistribution: 'verify before resale',
        },
        enabled: true,
        status: 'degraded',
        last_success: '2026-06-04T10:00:00Z',
        last_error: 'rate limited',
        ioc_count: 0,
      },
    ],
  }
}

function tlsBackend(items: TLSPosture[]) {
  const state = { requests: [] as string[] }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    state.requests.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.endsWith('/v1/tls/posture')) {
      return jsonResponse({ items, collector_running: true })
    }
    if (url.endsWith('/v1/threat/intel/status')) return jsonResponse(intelStatusFixture())
    if (url.endsWith('/v1/alerts/active'))
      return jsonResponse({ items: [], evaluator_running: true })
    if (url.endsWith('/v1/alerts')) return jsonResponse({ items: [] })
    return jsonResponse({ error: { code: 'not_found', message: `unstubbed ${url}` } }, 404)
  }) as unknown as typeof fetch
  return { state, fetcher }
}

describe('TLS/cert posture surface (S-FE2)', () => {
  beforeEach(() => vi.restoreAllMocks())

  test('renders the fixture inventory with expiry, key, and flag badges', async () => {
    const { fetcher } = tlsBackend(postureFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const inv = within(await screen.findByRole('table', { name: 'Certificate inventory' }))
    expect(inv.getByText('expired.acme.example:443')).toBeDefined()
    expect(inv.getAllByText(/expired \dd ago/).length).toBeGreaterThan(0)
    expect(inv.getByText('weak key')).toBeDefined()
    expect(inv.getByText('deprecated TLS')).toBeDefined()
    expect(inv.getByText('self-signed')).toBeDefined()
    expect(inv.getByText('CT anomaly')).toBeDefined()
    expect(inv.getByText('clean')).toBeDefined()
    expect(inv.getByText('RSA 1024')).toBeDefined()

    // The worklist holds only the expired + expiring certs, soonest first.
    const wl = within(screen.getByRole('table', { name: 'Expiring soon worklist' }))
    const rows = wl.getAllByRole('row')
    expect(rows.length).toBe(1 + 2) // header + expired + self/expiring
    expect(within(rows[1]).getByText('expired.acme.example:443')).toBeDefined()
    expect(within(rows[2]).getByText('self.acme.example:8443')).toBeDefined()
  })

  test('renders the open-data and threat-intel AUP health matrix', async () => {
    const { fetcher } = tlsBackend(postureFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    expect(await screen.findByText('2,048 IOCs')).toBeDefined()
    const feeds = within(await screen.findByRole('table', { name: 'Threat-intel feed status' }))
    expect(feeds.getByText('feodo_tracker')).toBeDefined()
    expect(feeds.getByText(/allowed · abuse\.ch CC0/)).toBeDefined()
    expect(feeds.getByText('firehol_level1')).toBeDefined()
    expect(feeds.getByText(/restricted · mixed terms/)).toBeDefined()
    expect(feeds.getByText('rate limited')).toBeDefined()

    const sources = within(screen.getByRole('table', { name: 'Open-data source status' }))
    expect(sources.getByText('test_cymru')).toBeDefined()
    expect(sources.getByText(/allowed-with-attribution · public lookup/)).toBeDefined()
  })

  test('filters by flag and free text', async () => {
    const { fetcher } = tlsBackend(postureFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')
    await screen.findByRole('table', { name: 'Certificate inventory' })

    await userEvent.selectOptions(screen.getByLabelText('Flag', { selector: 'select' }), 'weak')
    await waitFor(() => {
      const inv = within(screen.getByRole('table', { name: 'Certificate inventory' }))
      expect(inv.getAllByRole('row').length).toBe(2) // header + weak
      expect(inv.getByText('weak.acme.example:443')).toBeDefined()
    })

    await userEvent.selectOptions(screen.getByLabelText('Flag', { selector: 'select' }), 'all')
    await userEvent.type(screen.getByLabelText('Search'), 'ct.acme')
    await waitFor(() => {
      const inv = within(screen.getByRole('table', { name: 'Certificate inventory' }))
      expect(inv.getAllByRole('row').length).toBe(2) // header + ct
    })
  })

  test('detail shows findings and the VERBATIM trustctl handoff payload', async () => {
    const fixtures = postureFixtures()
    const { fetcher } = tlsBackend(fixtures)
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const inv = within(await screen.findByRole('table', { name: 'Certificate inventory' }))
    // Open the expired cert's detail (first Details in the inventory table).
    await userEvent.click(inv.getAllByRole('button', { name: 'Details' })[0])
    const dialog = await screen.findByRole('dialog')

    expect(within(dialog).getByText('CN=expired.acme.example')).toBeDefined()
    expect(within(dialog).getByText(/certificate expired 2 days ago/)).toBeDefined()

    // Handoff fidelity: the rendered payload IS the S27 payload, key for key.
    const pre = within(dialog).getByLabelText('trustctl handoff payload')
    const rendered = JSON.parse(pre.textContent ?? '{}') as Record<string, unknown>
    expect(rendered).toEqual(fixtures[0].handoff as unknown as Record<string, unknown>)

    // The trustctl deep link uses the payload URL untouched.
    const link = within(dialog).getByRole('link', { name: 'Open in trustctl' })
    expect(link.getAttribute('href')).toBe(fixtures[0].handoff?.url)
  })

  test('tenant scoping: renders exactly the tenant-scoped API items, no tenant params sent', async () => {
    const fixtures = postureFixtures()
    const { state, fetcher } = tlsBackend(fixtures)
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const inv = within(await screen.findByRole('table', { name: 'Certificate inventory' }))
    await waitFor(() => {
      expect(inv.getAllByRole('row').length).toBe(1 + fixtures.length)
    })
    expect(state.requests.every((r) => !r.includes('tenant'))).toBe(true)
  })

  test('collector-off is stated, not guessed', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/v1/tls/posture'))
        return jsonResponse({ items: [], collector_running: false })
      if (url.endsWith('/v1/threat/intel/status')) return jsonResponse(intelStatusFixture())
      return jsonResponse({ items: [] })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')
    expect(await screen.findByText(/posture collector is not wired/)).toBeDefined()
  })
})
