import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, pathOf } from './fetchStub'
import type { EndpointView } from '../api/endpoints'

/** The sprint's named fixture: local-WiFi degradation attributed to WiFi —
 *  plus a privacy-minimized endpoint (no SSID / gateway IP collected) and a
 *  healthy one. */
function endpointFixtures(): EndpointView[] {
  const at = '2026-06-04T12:00:00Z'
  return [
    {
      agent_id: 'laptop-anna',
      last_seen_at: at,
      cause: 'wifi',
      slow: true,
      confidence: 0.8,
      summary: 'weak RSSI (-82 dBm) on the local wireless link',
      attribution: {
        type: 'endpoint.attribution',
        target: 'app.acme.example',
        success: false,
        observed_at: at,
        metrics: {
          confidence: 0.8,
          slow: 1,
          wifi_score: 0.9,
          local_score: 0,
          isp_score: 0.1,
          network_score: 0,
        },
        attributes: {
          'endpoint.cause': 'wifi',
          'endpoint.summary': 'weak RSSI (-82 dBm) on the local wireless link',
        },
      },
      wifi: {
        type: 'endpoint.wifi',
        target: 'HomeNet',
        success: true,
        observed_at: at,
        metrics: { rssi_dbm: -82, signal_pct: 31, link_rate_mbps: 43, channel: 11, associated: 1 },
        attributes: { 'wifi.ssid': 'HomeNet', 'wifi.band': '2.4GHz' },
      },
      gateway: {
        type: 'endpoint.gateway',
        target: '192.168.1.1',
        success: true,
        observed_at: at,
        metrics: { rtt_ms: 3.4, loss_pct: 0, reachable: 1 },
        attributes: { 'gateway.ip': '192.168.1.1' },
      },
      last_mile: {
        type: 'endpoint.lastmile',
        target: 'app.acme.example',
        success: true,
        observed_at: at,
        metrics: { local_rtt_ms: 4, isp_rtt_ms: 18, isp_loss_pct: 0, beyond_rtt_ms: 35, hops: 9 },
      },
      sessions: [
        {
          type: 'endpoint.session',
          target: 'app.acme.example',
          success: true,
          observed_at: at,
          metrics: {
            dns_ms: 20,
            connect_ms: 30,
            tls_ms: 40,
            ttfb_ms: 350,
            total_ms: 900,
            status: 200,
          },
        },
      ],
    },
    {
      // Privacy-minimized: the agent withheld SSID + gateway IP entirely.
      agent_id: 'kiosk-7',
      last_seen_at: at,
      cause: 'isp',
      slow: true,
      confidence: 0.6,
      summary: 'ISP edge loss 8%',
      attribution: {
        type: 'endpoint.attribution',
        target: 'app.acme.example',
        success: false,
        observed_at: at,
        metrics: { confidence: 0.6, slow: 1, isp_score: 0.7 },
        attributes: { 'endpoint.cause': 'isp', 'endpoint.summary': 'ISP edge loss 8%' },
      },
      wifi: {
        type: 'endpoint.wifi',
        target: '',
        success: true,
        observed_at: at,
        metrics: { rssi_dbm: -55, associated: 1 },
        attributes: { 'wifi.band': '5GHz' }, // no wifi.ssid — withheld
      },
      gateway: {
        type: 'endpoint.gateway',
        target: '',
        success: true,
        observed_at: at,
        metrics: { rtt_ms: 2.1, loss_pct: 0, reachable: 1 }, // no gateway.ip — withheld
      },
    },
    {
      agent_id: 'desk-42',
      last_seen_at: at,
      cause: 'none',
      slow: false,
      confidence: 0.9,
      attribution: {
        type: 'endpoint.attribution',
        target: 'app.acme.example',
        success: true,
        observed_at: at,
        metrics: { confidence: 0.9, slow: 0 },
        attributes: { 'endpoint.cause': 'none' },
      },
    },
  ]
}

function endpointsBackend(items: EndpointView[]) {
  type SavedView = {
    id: string
    tenant_id: string
    surface: 'endpoints'
    name: string
    filters: Record<string, string>
    created_at: string
    updated_at: string
  }
  const state = { requests: [] as string[], saved: new Map<string, SavedView[]>() }
  let tenant = 'tenant-a'
  let seq = 0
  const savedForTenant = () => {
    if (!state.saved.has(tenant)) state.saved.set(tenant, [])
    return state.saved.get(tenant)!
  }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    state.requests.push(`${init?.method ?? 'GET'} ${url}`)
    const path = pathOf(input)
    if (path === '/v1/endpoints') {
      const parsed = new URL(url, 'http://t.invalid')
      const cause = parsed.searchParams.get('cause') ?? 'all'
      const q = (parsed.searchParams.get('q') ?? '').toLowerCase()
      const filtered = items.filter((v) => {
        if (cause === 'impaired' && !v.slow) return false
        if (cause !== 'all' && cause !== 'impaired' && (v.cause ?? 'none') !== cause) return false
        return !q || `${v.agent_id} ${v.summary ?? ''}`.toLowerCase().includes(q)
      })
      return jsonResponse({ items: filtered, collector_running: true })
    }
    if (path === '/v1/inventory/views' && (init?.method ?? 'GET') === 'GET') {
      return jsonResponse({ items: savedForTenant() })
    }
    if (path === '/v1/inventory/views' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as {
        surface: 'endpoints'
        name: string
        filters: Record<string, string>
      }
      const now = '2026-06-30T12:00:00Z'
      const view: SavedView = {
        id: `view-${++seq}`,
        tenant_id: tenant,
        surface: body.surface,
        name: body.name,
        filters: body.filters,
        created_at: now,
        updated_at: now,
      }
      savedForTenant().unshift(view)
      return jsonResponse(view, 201)
    }
    if (path.startsWith('/v1/inventory/views/') && (init?.method ?? 'GET') === 'GET') {
      const id = path.split('/').pop()
      const view = savedForTenant().find((v) => v.id === id)
      return view ? jsonResponse(view) : jsonResponse({ error: { message: 'saved view not found' } }, 404)
    }
    return jsonResponse({ items: [] })
  }) as unknown as typeof fetch
  return { state, fetcher, setTenant: (next: string) => (tenant = next) }
}

describe('endpoint / WiFi DEM surface (S-FE4)', () => {
  beforeEach(() => vi.restoreAllMocks())

  test('renders the WiFi-degradation fixture: verdict, WiFi health, segments', async () => {
    const { fetcher } = endpointsBackend(endpointFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/endpoints')

    const fleet = within(await screen.findByRole('table', { name: 'Endpoint fleet' }))
    const rows = fleet.getAllByRole('row')
    expect(rows.length).toBe(1 + 3)
    // Impaired endpoints sort first; the WiFi-attributed one shows its verdict.
    expect(within(rows[1]).getByText('slow: WiFi')).toBeDefined()
    expect(within(rows[1]).getByText('laptop-anna')).toBeDefined()
    expect(within(rows[1]).getByText(/-82 dBm · 2\.4GHz/)).toBeDefined()
    expect(within(rows[3]).getByText('healthy')).toBeDefined()

    // Detail: attribution summary, layer scores, gateway + last-mile numbers.
    await userEvent.click(within(rows[1]).getByRole('button', { name: 'Details' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/weak RSSI \(-82 dBm\)/)).toBeDefined()
    expect(within(dialog).getByText(/confidence 0\.8/)).toBeDefined()
    expect(within(dialog).getByText('severity 0.9')).toBeDefined() // WiFi layer
    expect(within(dialog).getByText(/SSID HomeNet/)).toBeDefined()
    expect(within(dialog).getByText(/192\.168\.1\.1/)).toBeDefined()
    expect(within(dialog).getByText(/ISP edge\s+18 ms/)).toBeDefined()
    // Session row renders the browser-session timings.
    expect(within(dialog).getByText('900 ms')).toBeDefined()
  })

  test('privacy display: withheld fields say so — never a fabricated value', async () => {
    const { fetcher } = endpointsBackend(endpointFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/endpoints')

    const fleet = within(await screen.findByRole('table', { name: 'Endpoint fleet' }))
    const kioskRow = fleet.getAllByRole('row').find((r) => within(r).queryByText('kiosk-7'))
    expect(kioskRow).toBeDefined()
    await userEvent.click(within(kioskRow!).getByRole('button', { name: 'Details' }))
    const dialog = await screen.findByRole('dialog')

    // SSID + gateway IP were withheld by the agent: the UI states it.
    expect(within(dialog).getByText(/SSID withheld \(privacy\)/)).toBeDefined()
    expect(within(dialog).getByText(/withheld \(privacy\) · reachable/)).toBeDefined()
    // And no fabricated identifier appears anywhere in the dialog.
    expect(within(dialog).queryByText(/HomeNet/)).toBeNull()
    expect(within(dialog).queryByText(/192\.168/)).toBeNull()
  })

  test('filters by attribution cause and text', async () => {
    const { fetcher } = endpointsBackend(endpointFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/endpoints')
    await screen.findByRole('table', { name: 'Endpoint fleet' })

    await userEvent.selectOptions(
      screen.getByLabelText('Attribution', { selector: 'select' }),
      'impaired',
    )
    await waitFor(() => {
      expect(
        within(screen.getByRole('table', { name: 'Endpoint fleet' })).getAllByRole('row').length,
      ).toBe(1 + 2)
    })
    await userEvent.selectOptions(
      screen.getByLabelText('Attribution', { selector: 'select' }),
      'isp',
    )
    await waitFor(() => {
      const rows = within(screen.getByRole('table', { name: 'Endpoint fleet' })).getAllByRole('row')
      expect(rows.length).toBe(2)
      expect(within(rows[1]).getByText('kiosk-7')).toBeDefined()
    })
    await userEvent.selectOptions(
      screen.getByLabelText('Attribution', { selector: 'select' }),
      'all',
    )
    await userEvent.type(screen.getByLabelText('Find'), 'desk')
    await waitFor(() => {
      expect(
        within(screen.getByRole('table', { name: 'Endpoint fleet' })).getAllByRole('row').length,
      ).toBe(2)
    })
  })

  test('saved views persist per tenant and drive server-side filters', async () => {
    const backend = endpointsBackend(endpointFixtures())
    backend.setTenant('tenant-a')
    vi.stubGlobal('fetch', backend.fetcher)
    const first = renderApp('/endpoints', { me: { tenant_id: 'tenant-a' } })
    await screen.findByRole('table', { name: 'Endpoint fleet' })

    await userEvent.selectOptions(
      screen.getByLabelText('Attribution', { selector: 'select' }),
      'wifi',
    )
    await userEvent.type(screen.getByLabelText('Find'), 'laptop')
    await userEvent.type(screen.getByLabelText('View name'), 'WiFi saved')
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() => expect(screen.getByRole('option', { name: 'WiFi saved' })).toBeDefined())
    const saved = backend.state.saved.get('tenant-a')?.[0]
    expect(saved?.filters).toEqual({ cause: 'wifi', q: 'laptop' })
    expect(backend.state.requests.some((r) => r.includes('/v1/endpoints?') && r.includes('cause=wifi'))).toBe(
      true,
    )
    first.unmount()

    backend.setTenant('tenant-b')
    vi.stubGlobal('fetch', backend.fetcher)
    renderApp('/endpoints', { me: { tenant_id: 'tenant-b' } })
    await screen.findByRole('table', { name: 'Endpoint fleet' })
    expect(screen.queryByRole('option', { name: 'WiFi saved' })).toBeNull()
    const openedAsB = await backend.fetcher(`/v1/inventory/views/${saved!.id}`)
    expect(openedAsB.status).toBe(404)
  })

  test('tenant scoping: renders exactly the tenant-scoped API items, no tenant params sent', async () => {
    const fixtures = endpointFixtures()
    const { state, fetcher } = endpointsBackend(fixtures)
    vi.stubGlobal('fetch', fetcher)
    renderApp('/endpoints')

    const fleet = within(await screen.findByRole('table', { name: 'Endpoint fleet' }))
    await waitFor(() => expect(fleet.getAllByRole('row').length).toBe(1 + fixtures.length))
    expect(state.requests.every((r) => !r.includes('tenant'))).toBe(true)
  })

  test('collector-off is stated, not guessed', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/v1/endpoints'))
        return jsonResponse({ items: [], collector_running: false })
      return jsonResponse({ items: [] })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)
    renderApp('/endpoints')
    expect(await screen.findByText(/endpoint-view consumer is not wired/)).toBeDefined()
  })
})
