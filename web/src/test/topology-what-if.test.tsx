// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { describe, expect, test, vi } from 'vitest'
import { Providers } from '../App'
import type { TopologyResponse, WhatIfImpact } from '../api/topology'
import { AppRoutes } from '../routes/AppRoutes'
import { parsePivotContext, pivotHref } from '../routes/pivotContext'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const FROM = '2026-07-14T10:00:00.000Z'
const TO = '2026-07-14T10:05:00.000Z'

const earlier: TopologyResponse = {
  topology_running: true,
  at: FROM,
  nodes: [
    { id: 'service:api', kind: 'service', label: 'api-v1', tags: ['blue'] },
    { id: 'host:common', kind: 'host', label: 'common' },
    { id: 'host:old', kind: 'host', label: 'old' },
  ],
  edges: [
    { from: 'service:api', to: 'host:common', kind: 'flow', label: 'old-route' },
    { from: 'service:api', to: 'host:old', kind: 'flow' },
  ],
  coverage: { path_edges: 0, flow_edges: 2, routing_edges: 0, device_edges: 0 },
}

const current: TopologyResponse = {
  topology_running: true,
  at: TO,
  nodes: [
    { id: 'service:api', kind: 'service', label: 'api-v2', tags: ['green'] },
    { id: 'host:common', kind: 'host', label: 'common' },
    { id: 'host:new', kind: 'host', label: 'new' },
  ],
  edges: [
    { from: 'service:api', to: 'host:common', kind: 'flow', label: 'new-route' },
    { from: 'service:api', to: 'host:new', kind: 'flow' },
  ],
  coverage: { path_edges: 0, flow_edges: 2, routing_edges: 0, device_edges: 0 },
}

const impact: WhatIfImpact = {
  target: 'service:api',
  target_kind: 'service',
  at: TO,
  broken_paths: [
    {
      from: 'agent:edge',
      to: 'service:api',
      status: 'broken',
      route: ['agent:edge', 'service:api'],
    },
  ],
  rerouted_paths: [],
  impacted_tests: [{ agent_id: 'agent:edge', target: 'service:api', status: 'broken' }],
  impacted_services: ['service:api'],
  impacted_prefixes: [],
  disconnected: ['host:new'],
  impacted_slos: ['slo:api-availability'],
  coverage: {
    path_edges: 1,
    flow_edges: 2,
    routing_edges: 0,
    device_edges: 0,
    notes: ['routing evidence is absent; prefix impact may be incomplete'],
  },
  confidence: {
    level: 'medium',
    score: 60,
    basis: '3 of 5 impact evidence sources wired (path, flow, routing, device, SLO)',
  },
}

const incident = {
  id: 'inc-blast',
  tenant_id: 'server-derived-only',
  status: 'open',
  severity: 'critical',
  title: 'API saturation',
  target: 'api',
  started_at: FROM,
  last_seen_at: TO,
  signal_count: 1,
  signals: [
    {
      plane: 'flow',
      kind: 'flow.capacity',
      severity: 'critical',
      title: 'API flow saturation',
      target: 'service:api',
      occurred_at: '2026-07-14T10:03:00.000Z',
    },
  ],
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="route-location">{`${location.pathname}${location.search}`}</output>
}

function renderWithLocation(path: string) {
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
        <LocationProbe />
      </MemoryRouter>
    </Providers>,
  )
}

function locationURL(): URL {
  return new URL(
    screen.getByTestId('route-location').textContent ?? '/',
    'https://probectl.invalid',
  )
}

function topologyFor(input: RequestInfo | URL): TopologyResponse {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  const at = new URL(raw, 'https://probectl.invalid').searchParams.get('at')
  return at === FROM ? earlier : current
}

function topologyStub() {
  const fallback = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/topology') return jsonResponse(topologyFor(input))
    if (path === '/v1/topology/whatif' && init?.method === 'POST') return jsonResponse(impact)
    if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
    if (path === '/v1/incidents/inc-blast') return jsonResponse(incident)
    if (path === '/v1/incidents/inc-blast/changes') return jsonResponse({ items: [] })
    return fallback(input, init)
  }) as unknown as typeof fetch
}

describe('topology blast-radius workspace (X10)', () => {
  test('one clock explains graph versions and preserves the selected entity while scrubbing', async () => {
    vi.stubGlobal('fetch', topologyStub())
    renderWithLocation(
      pivotHref('/topology', {
        from: FROM,
        to: TO,
        filters: {},
        selection: { kind: 'entity', id: 'service:api' },
      }),
    )

    expect(
      await screen.findByRole('group', { name: /topology version clock/i }),
    ).toBeInTheDocument()
    const differences = await screen.findByLabelText(/topology version differences/i)
    expect(within(differences).getByRole('region', { name: 'Added nodes' })).toHaveTextContent(
      'host new',
    )
    expect(within(differences).getByRole('region', { name: 'Removed nodes' })).toHaveTextContent(
      'host old',
    )
    expect(within(differences).getByRole('region', { name: 'Changed nodes' })).toHaveTextContent(
      'service api-v2',
    )
    expect(within(differences).getByRole('region', { name: 'Added edges' })).toHaveTextContent(
      'host:new',
    )
    expect(within(differences).getByRole('region', { name: 'Removed edges' })).toHaveTextContent(
      'host:old',
    )
    expect(within(differences).getByRole('region', { name: 'Changed edges' })).toHaveTextContent(
      'new-route',
    )
    expect(screen.getByText(/selection preserved: service:api/i)).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('As of'), { target: { value: '2026-07-14T10:04' } })
    await screen.findByRole('button', { name: 'service api-v2' })
    await waitFor(() =>
      expect(parsePivotContext(locationURL().searchParams).context.selection).toEqual({
        kind: 'entity',
        id: 'service:api',
      }),
    )
    const inspector = screen.getByRole('heading', { name: 'Inspector' }).closest('section')
    expect(inspector).not.toBeNull()
    expect(within(inspector as HTMLElement).getByText('service:api')).toBeInTheDocument()
  })

  test('incident evidence pivots into an automatic observe-only preview in two interactions', async () => {
    const fetcher = topologyStub()
    vi.stubGlobal('fetch', fetcher)
    renderWithLocation('/incidents?incident_status=open')

    let interactions = 0
    const signalButtons = await screen.findAllByRole('button', { name: 'API flow saturation' })
    await userEvent.click(signalButtons.at(-1) as HTMLElement)
    interactions += 1
    await userEvent.click(
      await screen.findByRole('link', { name: 'Preview blast radius for service:api' }),
    )
    interactions += 1

    expect(await screen.findByText(/predicted impact · observe-only dry-run/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/simulation safety/i)).toHaveTextContent('DRY-RUN')
    expect(screen.getByLabelText(/simulation confidence/i)).toHaveTextContent(
      'medium confidence · 60% coverage',
    )
    expect(screen.getByRole('list', { name: /affected tests/i })).toHaveTextContent(
      'agent:edge → service:api',
    )
    expect(screen.getByText('slo:api-availability')).toBeInTheDocument()
    expect(screen.getByText('inc-blast')).toBeInTheDocument()
    expect(interactions).toBeLessThanOrEqual(3)

    const url = locationURL()
    const context = parsePivotContext(url.searchParams).context
    expect(url.pathname).toBe('/topology')
    expect(url.searchParams.get('preview')).toBe('blast')
    expect(context).toMatchObject({
      incidentId: 'inc-blast',
      from: FROM,
      to: TO,
      filters: {
        incident_status: 'open',
        topology_source_evidence: 'inc-blast:0',
      },
      selection: { kind: 'entity', id: 'service:api' },
      returnTo: '/incidents?incident_status=open&incident=inc-blast',
    })
    expect(url.search.toLowerCase()).not.toContain('tenant')
    expect(
      (
        fetcher as unknown as { mock: { calls: [RequestInfo | URL, RequestInit?][] } }
      ).mock.calls.filter(
        ([input, init]) => pathOf(input) === '/v1/topology/whatif' && init?.method === 'POST',
      ),
    ).toHaveLength(1)

    const exportLink = screen.getByRole('link', { name: /export audited json/i })
    expect(exportLink).toHaveAttribute(
      'href',
      expect.stringContaining('/v1/topology/whatif/export?'),
    )
    expect(exportLink.getAttribute('href')).not.toContain('/v1/v1/')
  })
})
