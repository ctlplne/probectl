// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom'
import { describe, expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AppRoutes } from '../routes/AppRoutes'
import { parsePivotContext, pivotHref, type PivotContext } from '../routes/pivotContext'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const incident = {
  id: 'inc-context',
  tenant_id: 'server-only-tenant',
  status: 'open',
  severity: 'critical',
  title: 'cross-plane packet loss',
  target: '192.0.2.10',
  prefix: '192.0.2.0/24',
  started_at: '2026-07-14T10:00:00Z',
  last_seen_at: '2026-07-14T10:05:00Z',
  signal_count: 1,
  signals: [
    {
      plane: 'bgp',
      kind: 'bgp.route_change',
      severity: 'critical',
      title: 'route changed',
      occurred_at: '2026-07-14T10:03:00Z',
    },
  ],
}

const answer = {
  id: 'ans-context',
  tenant: 'server-only-tenant',
  question: 'what changed?',
  root_cause: 'The BGP route changed.',
  root_cause_citations: [{ evidence_id: 'E-BGP-1' }],
  root_cause_grounded: true,
  degraded: false,
  confidence: 'high',
  model: 'builtin',
  reasoning: {
    adapter: 'builtin',
    execution: 'builtin_local',
    egress_consent: 'not_required',
  },
  insufficient_evidence: false,
  findings: [
    {
      statement: 'The route change overlaps the packet loss.',
      citations: [{ evidence_id: 'E-BGP-1' }],
    },
  ],
  evidence: [
    {
      id: 'E-BGP-1',
      domain: 'routing',
      plane: 'bgp',
      title: 'route changed',
      occurred_at: '2026-07-14T10:03:00Z',
      fields: { id: 'inc-context:0' },
    },
  ],
}

function NavigationProbe() {
  const location = useLocation()
  const navigate = useNavigate()
  return (
    <div>
      <output data-testid="route-location">{`${location.pathname}${location.search}`}</output>
      <button type="button" onClick={() => navigate(-1)}>
        Test back
      </button>
      <button type="button" onClick={() => navigate(1)}>
        Test forward
      </button>
    </div>
  )
}

function renderWithNavigation(path: string) {
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
        <NavigationProbe />
      </MemoryRouter>
    </Providers>,
  )
}

function currentURL(): URL {
  return new URL(
    screen.getByTestId('route-location').textContent ?? '/',
    'https://probectl.invalid',
  )
}

describe('native cross-plane pivots', () => {
  test('incident room preserves inline RCA context and browser history replays selection', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
        if (path === '/v1/incidents/inc-context') return jsonResponse(incident)
        if (path === '/v1/ai/ask' && init?.method === 'POST') return jsonResponse(answer)
        return fallback(input, init)
      }),
    )

    renderWithNavigation('/incidents?incident_status=open')
    await userEvent.click(await screen.findByRole('button', { name: /cross-plane packet loss/i }))

    let url = currentURL()
    expect(parsePivotContext(url.searchParams).context.incidentId).toBe('inc-context')
    expect(parsePivotContext(url.searchParams).context.filters).toMatchObject({
      incident_status: 'open',
    })

    await userEvent.click(screen.getByRole('button', { name: /explain this view/i }))
    url = currentURL()
    const roomContext = parsePivotContext(url.searchParams).context
    expect(url.pathname).toBe('/incidents')
    expect(roomContext).toMatchObject({
      incidentId: 'inc-context',
      from: '2026-07-14T10:00:00.000Z',
      to: '2026-07-14T10:05:00.000Z',
      filters: { incident_status: 'open' },
      returnTo: '/incidents?incident_status=open&incident=inc-context',
    })
    expect(url.search.toLowerCase()).not.toContain('tenant')

    await screen.findByText('The BGP route changed.')
    await userEvent.click(screen.getAllByRole('link', { name: 'E-BGP-1' })[0])
    expect(parsePivotContext(currentURL().searchParams).context.selection).toEqual({
      kind: 'evidence',
      id: 'inc-context:0',
    })

    await userEvent.click(screen.getByRole('button', { name: 'Test back' }))
    await waitFor(() =>
      expect(parsePivotContext(currentURL().searchParams).context.selection).toBeUndefined(),
    )
    expect(currentURL().pathname).toBe('/incidents')

    await userEvent.click(screen.getByRole('button', { name: 'Test forward' }))
    await waitFor(() =>
      expect(parsePivotContext(currentURL().searchParams).context.selection?.id).toBe(
        'inc-context:0',
      ),
    )
  })

  test('plane tabs preserve the shared contract across every registered workspace', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    const context: PivotContext = {
      incidentId: 'inc-context',
      from: '2026-07-14T10:00:00Z',
      to: '2026-07-14T10:05:00Z',
      filters: { severity: 'critical' },
      selection: { kind: 'entity', id: 'prefix:203.0.113.0/24' },
      returnTo: '/incidents',
    }
    renderWithNavigation(pivotHref('/planes/bgp', context))

    await screen.findByRole('tab', { name: 'BGP' })
    for (const label of ['Flow', 'Device', 'eBPF', 'BGP']) {
      await userEvent.click(screen.getByRole('tab', { name: label }))
      const parsed = parsePivotContext(currentURL().searchParams).context
      expect(parsed).toMatchObject({
        incidentId: 'inc-context',
        filters: { severity: 'critical' },
        selection: { kind: 'entity', id: 'prefix:203.0.113.0/24' },
      })
      expect(currentURL().search.toLowerCase()).not.toContain('tenant')
    }
  })

  test('a tenant-scoped destination clears an unavailable entity but keeps safe context', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    const href = pivotHref('/topology', {
      from: '2026-07-14T10:00:00Z',
      to: '2026-07-14T10:05:00Z',
      filters: { topo_kind: 'hop' },
      selection: { kind: 'entity', id: 'host:belongs-to-old-tenant' },
    })
    renderWithNavigation(href)

    await screen.findByRole('group', { name: /topology graph/i })
    await waitFor(() => {
      const context = parsePivotContext(currentURL().searchParams).context
      expect(context.selection).toBeUndefined()
      expect(context.from).toBe('2026-07-14T10:00:00.000Z')
      expect(context.to).toBe('2026-07-14T10:05:00.000Z')
      expect(context.filters).toEqual({ topo_kind: 'hop' })
    })
  })

  test('Ask re-authorizes a URL-carried incident before it can enter an AI request', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    const href = pivotHref(
      '/ask',
      {
        incidentId: 'inc-from-previous-tenant',
        from: '2026-07-14T10:00:00Z',
        to: '2026-07-14T10:05:00Z',
        filters: { severity: 'critical' },
      },
      { question: 'What happened?' },
    )
    renderWithNavigation(href)

    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    await waitFor(() => {
      const context = parsePivotContext(currentURL().searchParams).context
      expect(context.incidentId).toBeUndefined()
      expect(context.filters).toEqual({ severity: 'critical' })
      expect(context.from).toBe('2026-07-14T10:00:00.000Z')
      expect(context.to).toBe('2026-07-14T10:05:00.000Z')
    })
    expect(screen.getByRole('button', { name: /^ask$/i })).toBeEnabled()
  })
})
