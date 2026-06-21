import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, jsonResponse, pathOf } from './fetchStub'
import type { LatestResult } from '../api/results'

/** Per-type fixtures (the sprint contract: every shipped type renders its
 *  result shape first-class — DNS breakdown, HTTP waterfall, latency/loss). */
function resultFixtures(): LatestResult[] {
  const at = '2026-06-04T12:00:00Z'
  return [
    {
      agent_id: 'a1',
      type: 'http',
      target: 'https://app.acme.example',
      success: true,
      observed_at: at,
      metrics: {
        'http.dns.ms': 20,
        'http.connect.ms': 30,
        'http.tls.ms': 50,
        'http.ttfb.ms': 200,
        'http.total.ms': 450,
        'http.status': 200,
        'http.throughput.kbps': 1800,
        'http.content.bytes': 102400,
        'http.tls.cert_expiry_days': 42,
      },
    },
    {
      agent_id: 'a1',
      type: 'browser',
      target: 'https://shop.acme.example/login',
      success: true,
      observed_at: at,
      metrics: {
        'transaction.total_ms': 735,
        'transaction.steps': 3,
        'transaction.resources': 4,
        'transaction.failed_steps': 0,
        'transaction.step.0.duration_ms': 120,
        'transaction.step.1.duration_ms': 42,
        'transaction.step.2.duration_ms': 5,
      },
      attributes: {
        'browser.script': 'checkout',
        'browser.step_count': '3',
        'browser.step.0.name': 'open login',
        'browser.step.0.action': 'goto',
        'browser.step.0.success': 'true',
        'browser.step.1.name': 'welcome',
        'browser.step.1.action': 'assert_text',
        'browser.step.1.success': 'true',
        'browser.step.2.name': 'status',
        'browser.step.2.action': 'assert_status',
        'browser.step.2.success': 'true',
      },
    },
    {
      agent_id: 'a1',
      type: 'dns',
      target: 'acme.example',
      success: true,
      observed_at: at,
      metrics: { 'dns.query.ms': 12.5, 'dns.answers': 2, 'dns.dnssec.secure': 1 },
      attributes: {
        'dns.rcode': 'NOERROR',
        'dns.answer': '203.0.113.10, 203.0.113.11',
        'dns.server': '192.0.2.53:53',
        'dns.transport': 'udp',
        'dns.qtype': 'A',
      },
    },
    {
      agent_id: 'a1',
      type: 'icmp',
      target: '10.0.0.7',
      success: true,
      observed_at: at,
      metrics: {
        'loss.ratio': 0.1,
        'packets.sent': 10,
        'packets.received': 9,
        'rtt.min.ms': 8.1,
        'rtt.avg.ms': 12.4,
        'rtt.max.ms': 30.2,
        'rtt.stddev.ms': 4.4,
        'jitter.ms': 3.1,
      },
    },
    {
      agent_id: 'a1',
      type: 'tcp',
      target: 'db.acme.example:5432',
      success: true,
      observed_at: at,
      metrics: {
        'loss.ratio': 0,
        'packets.sent': 5,
        'packets.received': 5,
        'connect.min.ms': 1.2,
        'connect.avg.ms': 1.9,
        'connect.max.ms': 3.4,
        'connect.stddev.ms': 0.7,
        'jitter.ms': 0.4,
      },
    },
    {
      agent_id: 'a1',
      type: 'udp',
      target: 'echo.acme.example:9999',
      success: false,
      error: 'timeout waiting for echo',
      observed_at: at,
      metrics: { 'loss.ratio': 1, 'packets.sent': 5, 'packets.received': 0 },
    },
    {
      agent_id: 'a1',
      type: 'voice',
      target: 'pbx.acme.example:5004',
      success: true,
      observed_at: at,
      metrics: {
        'voice.mos': 3.1,
        'voice.r_factor': 61.4,
        'voice.jitter.ms': 12.42,
        'voice.one_way.ms': 96.5,
        'voice.loss.pct': 8.5,
        'loss.ratio': 0.085,
        'packets.sent': 150,
        'packets.received': 137,
        'rtt.avg.ms': 64.2,
        'rtt.min.ms': 50.1,
        'rtt.max.ms': 110.4,
        'rtt.stddev.ms': 9.9,
        'jitter.ms': 8.8,
      },
      attributes: {
        'voice.codec': 'g711',
        'voice.model': 'itu-t-g107-e-model-simplified',
        'voice.one_way_estimate': 'rtt/2 + codec + jitter buffer',
      },
    },
  ]
}

const testsList = [
  {
    id: 't1',
    name: 'app http',
    type: 'http',
    target: 'https://app.acme.example',
    interval_seconds: 30,
    timeout_seconds: 5,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't2',
    name: 'checkout browser',
    type: 'browser',
    target: 'https://shop.acme.example/login',
    interval_seconds: 30,
    timeout_seconds: 5,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't3',
    name: 'apex dns',
    type: 'dns',
    target: 'acme.example',
    interval_seconds: 30,
    timeout_seconds: 5,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't4',
    name: 'core ping',
    type: 'icmp',
    target: '10.0.0.7',
    interval_seconds: 30,
    timeout_seconds: 5,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't5',
    name: 'db tcp',
    type: 'tcp',
    target: 'db.acme.example:5432',
    interval_seconds: 30,
    timeout_seconds: 5,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't6',
    name: 'udp echo',
    type: 'udp',
    target: 'echo.acme.example:9999',
    interval_seconds: 30,
    timeout_seconds: 5,
    params: {},
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 't7',
    name: 'voip probe',
    type: 'voice',
    target: 'pbx.acme.example:5004',
    interval_seconds: 60,
    timeout_seconds: 5,
    params: { codec: 'g711' },
    enabled: true,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
]

function resultsBackend(items: LatestResult[]) {
  const state = { requests: [] as string[] }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    state.requests.push(`${init?.method ?? 'GET'} ${url}`)
    if (path === '/v1/results/latest') return jsonResponse({ items, collector_running: true })
    if (path === '/v1/tests') return jsonResponse({ items: testsList })
    if (path === '/v1/agents') return jsonResponse({ items: [] })
    if (path === '/v1/ai/discover') return jsonResponse({ proposals: [] })
    return jsonResponse({ items: [] })
  }) as unknown as typeof fetch
  return { state, fetcher }
}

async function openResults(name: string) {
  await screen.findByText(name)
  const row = screen.getAllByRole('row').find((r) => within(r).queryByText(name))
  await userEvent.click(within(row!).getByRole('button', { name: `Results for ${name}` }))
  return screen.findByRole('dialog')
}

describe('synthetic result views (S-FE5)', () => {
  beforeEach(() => vi.restoreAllMocks())

  test('HTTP renders the dns/connect/tls/ttfb waterfall + status/throughput', async () => {
    const { fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    const dialog = await openResults('app http')

    const wf = within(dialog).getByLabelText('HTTP timing waterfall')
    for (const phase of ['DNS', 'Connect', 'TLS', 'TTFB']) {
      expect(within(wf).getByText(phase)).toBeDefined()
    }
    expect(within(wf).getByText('20 ms')).toBeDefined()
    expect(within(wf).getByText('200 ms')).toBeDefined()
    expect(within(dialog).getByText(/450 ms · HTTP 200/)).toBeDefined()
    expect(within(dialog).getByText(/1,800 kbps/)).toBeDefined()
    expect(within(dialog).getByText(/42 days/)).toBeDefined()
    // a11y: the open result dialog passes axe.
    expect(await axe(dialog)).toHaveNoViolations()
  })

  test('DNS renders the resolution breakdown (rcode, answers, resolver, DNSSEC)', async () => {
    const { fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    const dialog = await openResults('apex dns')

    expect(within(dialog).getByText(/12\.5 ms · 2 answers · NOERROR/)).toBeDefined()
    expect(within(dialog).getByText('203.0.113.10, 203.0.113.11')).toBeDefined()
    expect(within(dialog).getByText(/192\.0\.2\.53:53 via udp · A/)).toBeDefined()
    expect(within(dialog).getByText('validated')).toBeDefined()
  })

  test('browser renders transaction steps with timings (F15)', async () => {
    const { fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    const dialog = await openResults('checkout browser')

    expect(within(dialog).getByText(/checkout · 735 ms/)).toBeDefined()
    expect(within(dialog).getByText(/4 resources · 0 failed steps/)).toBeDefined()
    const table = within(dialog).getByRole('table', { name: /browser transaction steps/i })
    expect(within(table).getByText('open login')).toBeDefined()
    expect(within(table).getByText('welcome')).toBeDefined()
    expect(within(table).getByText('assert_text')).toBeDefined()
    expect(within(table).getByText('42 ms')).toBeDefined()
    expect(await axe(dialog)).toHaveNoViolations()
  })

  test('ICMP/TCP/UDP render latency families + loss consistently', async () => {
    const { fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')

    let dialog = await openResults('core ping')
    expect(within(dialog).getByText('10%')).toBeDefined() // loss badge
    expect(within(dialog).getByText(/9\/10 received/)).toBeDefined()
    expect(within(dialog).getByText(/min 8\.1 ms · avg 12\.4 ms · max 30\.2 ms/)).toBeDefined()
    expect(within(dialog).getByText(/3\.1 ms/)).toBeDefined() // jitter
    await userEvent.click(within(dialog).getByRole('button', { name: /close/i }))

    dialog = await openResults('db tcp')
    expect(within(dialog).getByText('Connect')).toBeDefined() // the tcp family label
    expect(within(dialog).getByText(/min 1\.2 ms · avg 1\.9 ms/)).toBeDefined()
    await userEvent.click(within(dialog).getByRole('button', { name: /close/i }))

    dialog = await openResults('udp echo')
    expect(within(dialog).getByText('failed')).toBeDefined()
    expect(within(dialog).getByText('timeout waiting for echo')).toBeDefined()
    expect(within(dialog).getByText('100%')).toBeDefined()
  })

  test('voice renders MOS (E-model) + jitter/loss with the model named (S47c)', async () => {
    const { fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    const dialog = await openResults('voip probe')

    // The contract fields: MOS prominent with the satisfaction tone…
    expect(within(dialog).getByText('3.1')).toBeDefined()
    expect(within(dialog).getByText(/R-factor\s*61\.4/)).toBeDefined()
    // …jitter/loss…
    expect(within(dialog).getByText(/12\.4 ms \(RFC 3550\) · loss 8\.5%/)).toBeDefined()
    expect(within(dialog).getByText(/137\/150 packets/)).toBeDefined()
    // …the delay estimate stated AS an estimate…
    expect(within(dialog).getByText(/one-way est\. 96\.5 ms/)).toBeDefined()
    // …and the model honesty: a computed score, never a measured one.
    expect(within(dialog).getByText(/g711 · itu-t-g107-e-model-simplified/)).toBeDefined()
    expect(await axe(dialog)).toHaveNoViolations()
  })

  test('consistency: no view ever renders raw JSON', async () => {
    const { fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    for (const name of ['app http', 'checkout browser', 'apex dns', 'core ping', 'voip probe']) {
      const dialog = await openResults(name)
      expect(dialog.textContent).not.toMatch(/[{}"]/) // no JSON braces/quotes leak
      await userEvent.click(within(dialog).getByRole('button', { name: /close/i }))
    }
  })

  test('tenant scoping: renders exactly the tenant-scoped API items, no tenant params sent', async () => {
    const { state, fetcher } = resultsBackend(resultFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    const dialog = await openResults('app http')
    expect(within(dialog).getByText(/a1 ·/)).toBeDefined()
    expect(state.requests.every((r) => !r.includes('tenant'))).toBe(true)
  })

  test('no results yet / collector-off are stated, not guessed', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      assertNoDoublePrefix(input)
      const path = pathOf(input)
      if (path === '/v1/results/latest')
        return jsonResponse({ items: [], collector_running: false })
      if (path === '/v1/tests') return jsonResponse({ items: testsList })
      if (path === '/v1/ai/discover') return jsonResponse({ proposals: [] })
      return jsonResponse({ items: [] })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets')
    const dialog = await openResults('app http')
    expect(within(dialog).getByText(/result-view consumer is not wired/)).toBeDefined()
  })
})
