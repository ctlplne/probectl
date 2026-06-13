import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { TopologyResponse, WhatIfImpact } from '../api/topology'

/** S43 surface (PR1): the topology graph + what-if simulation. */

function diamond(): TopologyResponse {
  return {
    topology_running: true,
    at: '2026-06-04T12:00:00Z',
    nodes: [
      { id: 'agent:probe-1', kind: 'agent', label: 'probe-1' },
      { id: 'hop:10.0.0.1', kind: 'hop', label: '10.0.0.1' },
      { id: 'hop:10.0.0.2', kind: 'hop', label: '10.0.0.2' },
      { id: 'hop:10.0.0.3', kind: 'hop', label: '10.0.0.3' },
      { id: 'host:203.0.113.10', kind: 'host', label: 'web' },
      { id: 'service:api', kind: 'service', label: 'api' },
      { id: 'service:db', kind: 'service', label: 'db' },
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
    impacted_services: [],
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
  test('renders the graph, inspects a node, simulates a failure', async () => {
    vi.stubGlobal('fetch', stub())
    renderApp('/topology')

    const graph = await screen.findByRole('group', { name: /topology graph/i })
    // All node kinds render.
    expect(within(graph).getByRole('button', { name: 'agent probe-1' })).toBeInTheDocument()
    expect(within(graph).getByRole('button', { name: 'service api' })).toBeInTheDocument()

    // Coverage honesty surfaces on the graph card.
    expect(screen.getByText(/no routing-plane/)).toBeInTheDocument()

    // Drill down: click the hop, inspector shows it.
    await userEvent.click(within(graph).getByRole('button', { name: 'hop 10.0.0.2' }))
    expect(await screen.findByText('hop:10.0.0.2')).toBeInTheDocument()

    // Simulate: the impact panel reports the reroute with the alternate route.
    await userEvent.click(screen.getByRole('button', { name: /simulate failure/i }))
    expect(await screen.findByText(/predicted impact/i)).toBeInTheDocument()
    const rerouted = screen.getByRole('list', { name: /rerouted paths/i })
    expect(within(rerouted).getByText(/agent:probe-1 → host:203.0.113.10/)).toBeInTheDocument()
    expect(within(rerouted).getByText(/via .*hop:10.0.0.3/)).toBeInTheDocument()
    // The SLO honesty note rides along.
    expect(screen.getByText(/slo impact not wired/i)).toBeInTheDocument()
  })

  test('keyboard: nodes are focusable and Enter selects', async () => {
    vi.stubGlobal('fetch', stub())
    renderApp('/topology')

    const node = await screen.findByRole('button', { name: 'agent probe-1' })
    node.focus()
    await userEvent.keyboard('{Enter}')
    expect(await screen.findByText('agent:probe-1')).toBeInTheDocument()
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

  test('dense graphs are capped with an honest count', async () => {
    const big = diamond()
    big.nodes = Array.from({ length: 450 }, (_, i) => ({
      id: `hop:10.1.${Math.floor(i / 250)}.${i % 250}`,
      kind: 'hop',
      label: `10.1.${Math.floor(i / 250)}.${i % 250}`,
    }))
    big.edges = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(big)),
    )
    renderApp('/topology')
    expect(await screen.findByText(/showing 400 of 450 nodes/i)).toBeInTheDocument()
  })

  test('time travel: picking a time refetches with ?at=', async () => {
    const fetcher = stub()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/topology')
    await screen.findByRole('group', { name: /topology graph/i })

    const input = screen.getByLabelText(/as of/i)
    await userEvent.type(input, '2026-06-04T11:00')
    await waitFor(() => {
      const urls = (
        fetcher as unknown as { mock: { calls: [RequestInfo | URL][] } }
      ).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/v1/topology?at='))).toBe(true)
    })
  })
})
