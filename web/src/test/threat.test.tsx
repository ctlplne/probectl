import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, jsonResponse, pathOf } from './fetchStub'
import type { Detection } from '../api/threat'

/** The sprint's named fixture: a flow/connection to a known-bad IP with full
 *  source attribution + confidence — plus a low-confidence Tor-exit match
 *  (the honest "benign-but-listed" case). */
function detectionFixtures(): Detection[] {
  return [
    {
      id: 'det-2',
      kind: 'ioc.botnet',
      plane: 'threat',
      severity: 'critical',
      confidence: 90,
      source: 'feodo',
      category: 'botnet',
      license: 'non-commercial',
      indicator: '203.0.113.66',
      entity: '203.0.113.66',
      title: '203.0.113.66 matches threat-intel indicator (botnet, source feodo)',
      summary:
        '203.0.113.66 matched threat-intel indicator 203.0.113.66 from feodo (confidence 90)',
      incident_id: 'inc-42',
      observed_at: '2026-06-04T12:05:00Z',
    },
    {
      id: 'det-1',
      kind: 'ioc.tor',
      plane: 'threat',
      severity: 'info',
      confidence: 40,
      source: 'tor-exits',
      category: 'tor',
      indicator: '198.51.100.9',
      entity: '198.51.100.9',
      title: '198.51.100.9 matches threat-intel indicator (tor, source tor-exits)',
      observed_at: '2026-06-04T12:00:00Z',
    },
  ]
}

function intelStatusFixture() {
  return {
    open_data_enabled: true,
    threat_intel_enabled: true,
    ioc_count: 1200,
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
        ioc_count: 1200,
      },
    ],
  }
}

function threatBackend(items: Detection[]) {
  const state = {
    requests: [] as string[],
    proposalBody: undefined as Record<string, unknown> | undefined,
  }
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    state.requests.push(`${method} ${url}`)
    if (path === '/v1/threat/detections') return jsonResponse({ items, detections_running: true })
    if (path === '/v1/threat/intel/status') return jsonResponse(intelStatusFixture())
    if (path === '/v1/tls/posture') return jsonResponse({ items: [], collector_running: true })
    if (path === '/v1/remediation/proposals' && method === 'GET')
      return jsonResponse({ items: [], approvals_enabled: false })
    if (path === '/v1/remediation/proposals' && method === 'POST') {
      state.proposalBody = JSON.parse(String(init!.body)) as Record<string, unknown>
      return jsonResponse(
        {
          id: 'rem-42',
          tenant_id: 't',
          kind: state.proposalBody.kind,
          title: state.proposalBody.title,
          rationale: state.proposalBody.rationale,
          target: state.proposalBody.target,
          incident_id: state.proposalBody.incident_id,
          dry_run: { blast_radius: 0, note: 'no target to simulate' },
          state: 'proposed',
          proposed_by: 'user:operator@probectl.test',
          created_at: '2026-06-04T12:06:00Z',
        },
        201,
      )
    }
    const inc42 = {
      id: 'inc-42',
      tenant_id: 't',
      status: 'open',
      severity: 'critical',
      title: 'Threat-intel match on 203.0.113.66',
      target: '203.0.113.66',
      started_at: '2026-06-04T12:05:00Z',
      last_seen_at: '2026-06-04T12:05:00Z',
      signal_count: 1,
      signals: [],
    }
    if (url.endsWith('/v1/incidents')) return jsonResponse({ items: [inc42] })
    if (url.match(/\/v1\/incidents\/inc-42$/)) return jsonResponse(inc42)
    return jsonResponse({ items: [] })
  }) as unknown as typeof fetch
  return { state, fetcher }
}

describe('threat/IOC triage surface (S-FE3)', () => {
  beforeEach(() => vi.restoreAllMocks())

  test('renders the known-bad-IP fixture with attribution + confidence', async () => {
    const { fetcher } = threatBackend(detectionFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const tbl = within(await screen.findByRole('table', { name: 'Threat detections' }))
    const rows = tbl.getAllByRole('row')
    expect(rows.length).toBe(1 + 2)
    // Attribution + confidence visible in the list (the S28 contract).
    expect(within(rows[1]).getAllByText('203.0.113.66').length).toBeGreaterThan(0)
    expect(within(rows[1]).getByText('feodo')).toBeDefined()
    expect(within(rows[1]).getByText('90')).toBeDefined()
    expect(within(rows[1]).getByText('critical')).toBeDefined()
    // The incident pivot link targets the correlated incident.
    const pivot = within(rows[1]).getByRole('link', { name: 'timeline' })
    expect(pivot.getAttribute('href')).toBe('/incidents?incident=inc-42')
    // The uncorrelated detection shows no pivot.
    expect(within(rows[2]).queryByRole('link')).toBeNull()
  })

  test('detail shows provenance honestly (license, benign-may-be-listed note)', async () => {
    const { fetcher } = threatBackend(detectionFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const tbl = within(await screen.findByRole('table', { name: 'Threat detections' }))
    await userEvent.click(
      within(tbl.getAllByRole('row')[1]).getByRole('button', { name: 'Details' }),
    )
    const dialog = await screen.findByRole('dialog')

    expect(within(dialog).getByText('confidence 90')).toBeDefined()
    expect(within(dialog).getByText(/feodo · botnet · license: non-commercial/)).toBeDefined()
    expect(within(dialog).getByText(/feeds can list benign infrastructure/)).toBeDefined()
    expect(within(dialog).getByText(/never blocks/)).toBeDefined()
    expect(
      within(dialog).getByRole('link', { name: 'Open incident timeline' }).getAttribute('href'),
    ).toBe('/incidents?incident=inc-42')
  })

  test('pivoting to the incident opens its timeline (deep link honored)', async () => {
    const { fetcher } = threatBackend(detectionFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const tbl = within(await screen.findByRole('table', { name: 'Threat detections' }))
    await userEvent.click(
      within(tbl.getAllByRole('row')[1]).getByRole('link', { name: 'timeline' }),
    )
    // The incidents page mounts...
    await screen.findByRole('heading', { name: /^incidents$/i })
    // ...and selects inc-42 from the query param, loading its timeline.
    expect(
      (await screen.findAllByText('Threat-intel match on 203.0.113.66')).length,
    ).toBeGreaterThan(0)
  })

  test('proposes a human-gated remediation from detection evidence', async () => {
    const { state, fetcher } = threatBackend(detectionFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const buttons = await screen.findAllByRole('button', { name: /propose response/i })
    await userEvent.click(buttons[0])

    expect(await screen.findByText('Proposal created')).toBeInTheDocument()
    expect(state.proposalBody).toMatchObject({
      kind: 'open_ticket',
      title: 'Investigate 203.0.113.66 ioc.botnet detection',
      target: '203.0.113.66',
      incident_id: 'inc-42',
    })
    expect(String(state.proposalBody?.rationale)).toContain('Detection det-2')
    expect(String(state.proposalBody?.rationale)).toContain('confidence 90')
    expect(String(state.proposalBody?.rationale)).toContain('Source feodo / botnet')
    expect(String(state.proposalBody?.rationale)).toContain('human review only')
    expect(String(state.proposalBody?.rationale)).toContain('must not block traffic or execute')
    expect(state.requests.some((r) => /approve|reject/.test(r))).toBe(false)
  })

  test('hides proposal action when guarded remediation is unlicensed', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      assertNoDoublePrefix(input)
      const path = pathOf(input)
      if (path === '/v1/threat/detections')
        return jsonResponse({ items: detectionFixtures(), detections_running: true })
      if (path === '/v1/threat/intel/status') return jsonResponse(intelStatusFixture())
      if (path === '/v1/tls/posture') return jsonResponse({ items: [], collector_running: true })
      if (path === '/v1/remediation/proposals')
        return jsonResponse({ error: { message: 'not found' } }, 404)
      return jsonResponse({ items: [] })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    await screen.findByRole('table', { name: 'Threat detections' })
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /propose response/i })).toBeNull(),
    )
  })

  test('filters by severity and source', async () => {
    const { fetcher } = threatBackend(detectionFixtures())
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')
    await screen.findByRole('table', { name: 'Threat detections' })

    await userEvent.selectOptions(
      screen.getByLabelText('Min severity', { selector: 'select' }),
      'critical',
    )
    await waitFor(() => {
      expect(
        within(screen.getByRole('table', { name: 'Threat detections' })).getAllByRole('row').length,
      ).toBe(2)
    })
    await userEvent.selectOptions(
      screen.getByLabelText('Min severity', { selector: 'select' }),
      'all',
    )
    await userEvent.selectOptions(
      screen.getByLabelText('Source', { selector: 'select' }),
      'tor-exits',
    )
    await waitFor(() => {
      const rows = within(screen.getByRole('table', { name: 'Threat detections' })).getAllByRole(
        'row',
      )
      expect(rows.length).toBe(2)
      expect(within(rows[1]).getAllByText('198.51.100.9').length).toBeGreaterThan(0)
    })
  })

  test('tenant scoping: renders exactly the tenant-scoped API items, no tenant params sent', async () => {
    const fixtures = detectionFixtures()
    const { state, fetcher } = threatBackend(fixtures)
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')

    const tbl = within(await screen.findByRole('table', { name: 'Threat detections' }))
    await waitFor(() => expect(tbl.getAllByRole('row').length).toBe(1 + fixtures.length))
    expect(state.requests.every((r) => !r.includes('tenant'))).toBe(true)
  })

  test('detections-off is stated, not guessed', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      assertNoDoublePrefix(input)
      const path = pathOf(input)
      if (path === '/v1/threat/detections')
        return jsonResponse({ items: [], detections_running: false })
      if (path === '/v1/threat/intel/status') return jsonResponse(intelStatusFixture())
      if (path === '/v1/tls/posture') return jsonResponse({ items: [], collector_running: true })
      return jsonResponse({ items: [] })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)
    renderApp('/security')
    expect(await screen.findByText(/threat detection reader is not wired/)).toBeDefined()
  })
})
