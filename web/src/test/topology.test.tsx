// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse } from './fetchStub'
import type { TopologyResponse, WhatIfImpact } from '../api/topology'

/** S43 surface (PR1): the topology graph + what-if simulation. */

function diamond(): TopologyResponse {
  return {
    topology_running: true,
    at: '2026-06-04T12:00:00Z',
    nodes: [
      { id: 'agent:probe-1', kind: 'agent', label: 'probe-1', site: 'edge', tags: ['synthetic'] },
      { id: 'hop:10.0.0.1', kind: 'hop', label: '10.0.0.1', site: 'edge', tags: ['path'] },
      { id: 'hop:10.0.0.2', kind: 'hop', label: '10.0.0.2', site: 'edge', tags: ['path'] },
      { id: 'hop:10.0.0.3', kind: 'hop', label: '10.0.0.3', site: 'edge', tags: ['path'] },
      { id: 'host:203.0.113.10', kind: 'host', label: 'web', site: 'core', tags: ['frontend'] },
      { id: 'service:api', kind: 'service', label: 'api', site: 'core', tags: ['api', 'prod'] },
      { id: 'service:db', kind: 'service', label: 'db', site: 'core', tags: ['db', 'prod'] },
    ],
    edges: [
      { from: 'agent:probe-1', to: 'hop:10.0.0.1', kind: 'path' },
      { from: 'hop:10.0.0.1', to: 'hop:10.0.0.2', kind: 'path' },
      { from: 'hop:10.0.0.1', to: 'hop:10.0.0.3', kind: 'path' },
      { from: 'hop:10.0.0.2', to: 'host:203.0.113.10', kind: 'path' },
      { from: 'hop:10.0.0.3', to: 'host:203.0.113.10', kind: 'path' },
      { from: 'service:api', to: 'service:db', kind: 'flow' },
    ],
    coverage: {
      path_edges: 5,
      flow_edges: 1,
      routing_edges: 0,
      device_edges: 0,
      notes: ['no routing-plane (BGP) edges — prefix impact may be incomplete'],
    },
  }
}

function impactFixture(): WhatIfImpact {
  return {
    target: 'hop:10.0.0.2',
    target_kind: 'hop',
    at: '2026-06-04T12:00:00Z',
    broken_paths: [],
    rerouted_paths: [
      {
        from: 'agent:probe-1',
        to: 'host:203.0.113.10',
        status: 'rerouted',
        route: ['agent:probe-1', 'hop:10.0.0.1', 'hop:10.0.0.2', 'host:203.0.113.10'],
        alt_route: ['agent:probe-1', 'hop:10.0.0.1', 'hop:10.0.0.3', 'host:203.0.113.10'],
      },
    ],
    impacted_tests: [
      {
        agent_id: 'agent:probe-1',
        target: 'host:203.0.113.10',
        status: 'rerouted',
      },
    ],
    impacted_services: ['service:api'],
    impacted_prefixes: [],
    disconnected: [],
    impacted_slos: [],
    coverage: {
      path_edges: 5,
      flow_edges: 1,
      routing_edges: 0,
      device_edges: 0,
      notes: ['slo impact not wired (S45) — paths/services only'],
    },
    confidence: {
      level: 'medium',
      score: 40,
      basis: '2 of 5 impact evidence sources wired (path, flow, routing, device, SLO)',
    },
  }
}

function stub() {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.includes('/v1/topology/whatif') && init?.method === 'POST') {
      return jsonResponse(impactFixture())
    }
    if (url.includes('/v1/topology')) return jsonResponse(diamond())
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('topology + what-if (S43)', () => {
  test('populated topology renders the same physical adjacency as device evidence', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/topology')

    const graph = await screen.findByRole('group', { name: /topology graph/i })
    expect(within(graph).getByRole('button', { name: 'device edge-r1' })).toBeInTheDocument()
    expect(within(graph).getByRole('button', { name: 'device leaf-1' })).toBeInTheDocument()
    expect(screen.getByText(/^physical$/i)).toBeInTheDocument()
  })

  test('renders the graph, inspects a node, simulates a failure', async () => {
    vi.stubGlobal('fetch', stub())
    renderApp('/topology')

    const graph = await screen.findByRole('group', { name: /topology graph/i })
    // All node kinds render.
    expect(within(graph).getByRole('button', { name: 'agent probe-1' })).toBeInTheDocument()
    expect(within(graph).getByRole('button', { name: 'service api' })).toBeInTheDocument()

    // Narrow screens get an explicit, position-aware alternative to hidden
    // horizontal overflow; wide screens use the same control as an overview receipt.
    const navigator = screen.getByRole('group', { name: /graph exploration controls/i })
    expect(within(navigator).getByText(/column 1 of 4 · agent/i)).toBeInTheDocument()
    expect(within(navigator).getByRole('button', { name: /previous/i })).toBeDisabled()
    expect(within(navigator).getByRole('button', { name: /next/i })).toBeEnabled()

    // Coverage honesty surfaces on the graph card.
    expect(screen.getByText(/no routing-plane/)).toBeInTheDocument()

    // Drill down: click the hop, inspector shows it.
    await userEvent.click(within(graph).getByRole('button', { name: 'hop 10.0.0.2' }))
    const inspector = screen.getByRole('heading', { name: /inspector/i }).closest('section')
    if (!inspector) throw new Error('missing inspector card')
    expect(within(inspector).getByText('hop:10.0.0.2')).toBeInTheDocument()

    // Simulate: the impact panel reports the reroute with the alternate route.
    await userEvent.click(screen.getByRole('button', { name: /simulate failure/i }))
    expect(await screen.findByText(/predicted impact/i)).toBeInTheDocument()
    const rerouted = screen.getByRole('list', { name: /rerouted paths/i })
    expect(within(rerouted).getByText(/agent:probe-1 → host:203.0.113.10/)).toBeInTheDocument()
    expect(within(rerouted).getByText(/alternate .*hop:10.0.0.3/)).toBeInTheDocument()
    expect(screen.getByRole('list', { name: /affected tests/i })).toHaveTextContent(
      'agent:probe-1 → host:203.0.113.10',
    )
    expect(screen.getByLabelText(/simulation confidence/i)).toHaveTextContent(
      'medium confidence · 40% coverage',
    )
    expect(screen.getByText(/executes and prevents nothing/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /export audited json/i })).toHaveAttribute(
      'href',
      expect.stringContaining('/v1/topology/whatif/export?'),
    )
    // The SLO honesty note rides along.
    expect(screen.getByText(/slo impact not wired/i)).toBeInTheDocument()
  })

  test('keyboard: nodes are focusable and Enter selects', async () => {
    vi.stubGlobal('fetch', stub())
    renderApp('/topology')

    const node = await screen.findByRole('button', { name: 'agent probe-1' })
    node.focus()
    await userEvent.keyboard('{Enter}')
    const inspector = screen.getByRole('heading', { name: /inspector/i }).closest('section')
    if (!inspector) throw new Error('missing inspector card')
    expect(within(inspector).getByText('agent:probe-1')).toBeInTheDocument()
  })

  test('search, kind, site, and tag filters update graph and complete list together', async () => {
    vi.stubGlobal('fetch', stub())
    renderApp('/topology')

    await screen.findByRole('group', { name: /topology graph/i })
    await userEvent.selectOptions(screen.getByLabelText('Kind'), 'service')
    await userEvent.selectOptions(screen.getByLabelText('Site'), 'core')
    await userEvent.selectOptions(screen.getByLabelText('Tag'), 'api')

    const graph = screen.getByRole('group', { name: /topology graph/i })
    const table = screen.getByRole('table', { name: /topology nodes/i })
    expect(within(graph).getByRole('button', { name: 'service api' })).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: 'api' })).toBeInTheDocument()
    expect(within(table).queryByRole('button', { name: 'db' })).toBeNull()

    const search = screen.getByLabelText(/search topology/i)
    fireEvent.change(search, { target: { value: 'probe-1' } })
    expect(search).toHaveValue('probe-1')
    expect(within(table).getByRole('button', { name: 'api' })).toBeInTheDocument()
    await waitFor(() => {
      const updatedTable = screen.getByRole('table', { name: /topology nodes/i })
      expect(within(updatedTable).queryByRole('button', { name: 'api' })).toBeNull()
    })
  })

  test('honesty: unwired topology renders as not wired', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ topology_running: false, nodes: [], edges: [] })),
    )
    renderApp('/topology')
    expect(await screen.findByText(/topology not wired/i)).toBeInTheDocument()
  })

  test('a11y: the topology page passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stub())
    const { container } = renderApp('/topology')
    await screen.findByRole('group', { name: /topology graph/i })
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }, // jsdom cannot compute
    })
    expect(results.violations).toEqual([])
  })

  test('dense graphs are capped but hidden nodes stay reachable through list and search', async () => {
    const big = diamond()
    big.nodes = Array.from({ length: 500 }, (_, i) => ({
      id: i === 499 ? 'service:hidden-target' : `hop:10.1.${Math.floor(i / 250)}.${i % 250}`,
      kind: i === 499 ? 'service' : 'hop',
      label: i === 499 ? 'zz-hidden-target' : `node-${String(i).padStart(3, '0')}`,
      site: i === 499 ? 'core' : 'edge',
      tags: i === 499 ? ['critical', 'prod'] : ['bulk'],
    }))
    big.edges = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(big)),
    )
    renderApp('/topology')
    expect(await screen.findByText(/showing 120 of 500 nodes/i)).toBeInTheDocument()

    const graph = screen.getByRole('group', { name: /topology graph/i })
    expect(within(graph).getAllByRole('button')).toHaveLength(120)
    expect(within(graph).queryByRole('button', { name: 'service zz-hidden-target' })).toBeNull()

    const table = screen.getByRole('table', { name: /topology nodes/i })
    expect(within(table).getByText(/showing 200 of 500/i)).toBeInTheDocument()
    expect(within(table).queryByRole('button', { name: 'zz-hidden-target' })).toBeNull()

    await userEvent.click(screen.getByText(/history & filters/i))
    fireEvent.change(screen.getByLabelText(/search topology/i), {
      target: { value: 'zz-hidden-target' },
    })
    expect(
      await within(graph).findByRole('button', { name: 'service zz-hidden-target' }),
    ).toBeInTheDocument()
    expect(
      await within(table).findByRole('button', { name: 'zz-hidden-target' }),
    ).toBeInTheDocument()
  }, 20_000)

  test('time travel: picking a time refetches with ?at=', async () => {
    const fetcher = stub()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/topology')
    await screen.findByRole('group', { name: /topology graph/i })

    await userEvent.click(screen.getByText(/history & filters/i))
    const input = screen.getByLabelText(/as of/i)
    const selectedTime = '2026-06-04T11:00'
    const expectedAt = new Date(selectedTime).toISOString()
    fireEvent.change(input, { target: { value: selectedTime } })
    await waitFor(() => {
      const urls = (
        fetcher as unknown as { mock: { calls: [RequestInfo | URL][] } }
      ).mock.calls.map((c) => String(c[0]))
      expect(
        urls.some((u) => {
          const request = new URL(u, 'https://probectl.test')
          return request.pathname === '/v1/topology' && request.searchParams.get('at') === expectedAt
        }),
      ).toBe(true)
    })
  })
})
