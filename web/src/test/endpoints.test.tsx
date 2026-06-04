import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { EndpointView } from '../api/endpoints'

/** The sprint's named fixture: local-WiFi degradation attributed to WiFi —
 *  plus a privacy-minimized endpoint (no SSID / gateway IP collected) and a
 *  healthy one. */
function endpointFixtures(): EndpointView[] {
  const at = '2026-06-04T12:00:00Z'
  return [
    {
      agent_id: 'laptop-anna', last_seen_at: at, cause: 'wifi', slow: true, confidence: 0.8,
      summary: 'weak RSSI (-82 dBm) on the local wireless link',
      attribution: {
        type: 'endpoint.attribution', target: 'app.acme.example', success: false, observed_at: at,
        metrics: { confidence: 0.8, slow: 1, wifi_score: 0.9, local_score: 0, isp_score: 0.1, network_score: 0 },
        attributes: { 'endpoint.cause': 'wifi', 'endpoint.summary': 'weak RSSI (-82 dBm) on the local wireless link' },
      },
      wifi: {
        type: 'endpoint.wifi', target: 'HomeNet', success: true, observed_at: at,
        metrics: { rssi_dbm: -82, signal_pct: 31, link_rate_mbps: 43, channel: 11, associated: 1 },
        attributes: { 'wifi.ssid': 'HomeNet', 'wifi.band': '2.4GHz' },
      },
      gateway: {
        type: 'endpoint.gateway', target: '192.168.1.1', success: true, observed_at: at,
        metrics: { rtt_ms: 3.4, loss_pct: 0, reachable: 1 },
        attributes: { 'gateway.ip': '192.168.1.1' },
      },
      last_mile: {
        type: 'endpoint.lastmile', target: 'app.acme.example', success: true, observed_at: at,
        metrics: { local_rtt_ms: 4, isp_rtt_ms: 18, isp_loss_pct: 0, beyond_rtt_ms: 35, hops: 9 },
      },
      sessions: [
        {
          type: 'endpoint.session', target: 'app.acme.example', success: true, observed_at: at,
          metrics: { dns_ms: 20, connect_ms: 30, tls_ms: 40, ttfb_ms: 350, total_ms: 900, status: 200 },
        },
      ],
    },
    {
      // Privacy-minimized: the agent withheld SSID + gateway IP entirely.
      agent_id: 'kiosk-7', last_seen_at: at, cause: 'isp', slow: true, confidence: 0.6,
      summary: 'ISP edge loss 8%',
      attribution: {
        type: 'endpoint.attribution', target: 'app.acme.example', success: false, observed_at: at,
        metrics: { confidence: 0.6, slow: 1, isp_score: 0.7 },
        attributes: { 'endpoint.cause': 'isp', 'endpoint.summary': 'ISP edge loss 8%' },
      },
      wifi: {
        type: 'endpoint.wifi', target: '', success: true, observed_at: at,
        metrics: { rssi_dbm: -55, associated: 1 },
        attributes: { 'wifi.band': '5GHz' }, // no wifi.ssid — withheld
      },
      gateway: {
        type: 'endpoint.gateway', target: '', success: true, observed_at: at,
        metrics: { rtt_ms: 2.1, loss_pct: 0, reachable: 1 }, // no gateway.ip — withheld
      },
    },
    {
      agent_id: 'desk-42', last_seen_at: at, cause: 'none', slow: false, confidence: 0.9,
      attribution: {
        type: 'endpoint.attribution', target: 'app.acme.example', success: true, observed_at: at,
        metrics: { confidence: 0.9, slow: 0 },
        attributes: { 'endpoint.cause': 'none' },
      },
    },
  ]
}

function endpointsBackend(items: EndpointView[]) {
  const state = { requests: [] as string[] }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    state.requests.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.endsWith('/v1/endpoints')) return jsonResponse({ items, collector_running: true })
    return jsonResponse({ items: [] })
  }) as unknown as typeof fetch
  return { state, fetcher }
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

    await userEvent.selectOptions(screen.getByLabelText('Attribution', { selector: 'select' }), 'impaired')
    await waitFor(() => {
      expect(within(screen.getByRole('table', { name: 'Endpoint fleet' })).getAllByRole('row').length).toBe(1 + 2)
    })
    await userEvent.selectOptions(screen.getByLabelText('Attribution', { selector: 'select' }), 'isp')
    await waitFor(() => {
      const rows = within(screen.getByRole('table', { name: 'Endpoint fleet' })).getAllByRole('row')
      expect(rows.length).toBe(2)
      expect(within(rows[1]).getByText('kiosk-7')).toBeDefined()
    })
    await userEvent.selectOptions(screen.getByLabelText('Attribution', { selector: 'select' }), 'all')
    await userEvent.type(screen.getByLabelText('Find'), 'desk')
    await waitFor(() => {
      expect(within(screen.getByRole('table', { name: 'Endpoint fleet' })).getAllByRole('row').length).toBe(2)
    })
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
      if (url.endsWith('/v1/endpoints')) return jsonResponse({ items: [], collector_running: false })
      return jsonResponse({ items: [] })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)
    renderApp('/endpoints')
    expect(await screen.findByText(/endpoint-view consumer is not wired/)).toBeDefined()
  })
})
