import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

describe('plane workspaces', () => {
  test('renders native BGP, flow, device, and eBPF tabs', async () => {
    renderApp('/planes')

    expect(await screen.findByRole('heading', { name: /planes/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'BGP' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByRole('table', { name: /bgp routing edges/i })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Flow' }))
    const topTalkers = await screen.findByRole('table', { name: /flow top talkers/i })
    expect(within(topTalkers).getByText('10.0.0.10')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Device' }))
    expect(await screen.findByRole('table', { name: /topology device nodes/i })).toBeInTheDocument()
    expect(screen.getByText('edge-r1')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'eBPF' }))
    const ebpf = await screen.findByRole('table', { name: /ebpf service edges/i })
    expect(within(ebpf).getByText('checkout')).toBeInTheDocument()
  })

  test('renders BGP AS-path arcs with a table fallback', async () => {
    renderApp('/planes/bgp')

    expect(
      await screen.findByRole('img', { name: /bgp as-path arc view with 1 of 1/i }),
    ).toBeInTheDocument()
    expect(screen.getByText(/showing 1 of 1 routing relationships/i)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: /bgp routing edges/i })
    expect(within(table).getByText('AS64500')).toBeInTheDocument()
    expect(within(table).getByText('203.0.113.0/24')).toBeInTheDocument()
  })

  test('renders flow Sankey lanes with a table fallback', async () => {
    renderApp('/planes/flow')

    expect(
      await screen.findByRole('img', { name: /flow sankey view with 2 of 2/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('region', { name: /scrollable flow sankey visualization/i }),
    ).toHaveAttribute('tabindex', '0')
    expect(screen.getByText(/showing 2 of 2 contributors/i)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: /flow top talkers/i })
    expect(within(table).getByText('10.0.0.10')).toBeInTheDocument()
    expect(within(table).getByText('checkout')).toBeInTheDocument()
  })

  test('discloses visualization cardinality guardrails', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      if (path === '/v1/topology') {
        const ases = Array.from({ length: 20 }, (_, i) => ({
          id: `as:${64500 + i}`,
          kind: 'as',
          label: `AS${64500 + i}`,
        }))
        const prefixes = Array.from({ length: 20 }, (_, i) => ({
          id: `prefix:203.0.${i}.0/24`,
          kind: 'prefix',
          label: `203.0.${i}.0/24`,
        }))
        return Promise.resolve(
          jsonResponse({
            topology_running: true,
            nodes: [...ases, ...prefixes],
            edges: ases.map((asNode, i) => ({
              from: asNode.id,
              to: prefixes[i].id,
              kind: 'routing',
            })),
            coverage: { path_edges: 0, flow_edges: 0, routing_edges: 20, device_edges: 0 },
          }),
        )
      }
      if (path === '/v1/flows/top') {
        return Promise.resolve(
          jsonResponse({
            items: Array.from({ length: 12 }, (_, i) => ({
              key: `10.0.0.${i + 1}`,
              detail: `service-${i + 1}`,
              bytes: 100_000 * (12 - i),
              packets: 10_000 - i,
              flows: 20 - i,
            })),
            effective_limit: 12,
            window: '1h',
          }),
        )
      }
      return fallback(input, init)
    })

    renderApp('/planes/bgp')

    expect(await screen.findByText(/showing 16 of 20 routing relationships/i)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /bgp routing edges/i })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Flow' }))
    expect(await screen.findByText(/showing 8 of 12 contributors/i)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /flow top talkers/i })).toBeInTheDocument()
  })
})
