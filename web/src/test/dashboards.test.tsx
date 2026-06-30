import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch, pathOf } from './fetchStub'

describe('curated dashboards', () => {
  test('renders dense native dashboards from tenant-scoped API data', async () => {
    const requests: string[] = []
    const inner = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(String(input))
        return inner(input, init)
      }),
    )
    renderApp('/dashboards')

    expect(await screen.findByRole('heading', { name: /dashboards/i })).toBeInTheDocument()
    expect(screen.queryByText(/lands in a later sprint/i)).not.toBeInTheDocument()

    expect((await screen.findAllByText('Active tests')).length).toBeGreaterThan(0)
    expect(screen.getByText('BGP routes')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /cost trend/i })).toBeInTheDocument()
    expect(screen.getByRole('img', { name: /flow capacity trend/i })).toBeInTheDocument()

    const panels = [
      { caption: /active tests dashboard/i, text: 'edge-dns' },
      { caption: /bgp routing dashboard/i, text: /AS64500/ },
      { caption: /top flow contributors dashboard/i, text: '10.0.0.10' },
      { caption: /device inventory dashboard/i, text: 'edge-r1' },
      { caption: /ebpf evidence dashboard/i, text: /service:checkout/ },
      { caption: /cost budget dashboard/i, text: /payments/ },
      { caption: /threat signal dashboard/i, text: 'Known scanner contact' },
      { caption: /tenant health dashboard/i, text: 'Tenant scope' },
    ]

    for (const panel of panels) {
      const table = await screen.findByRole('table', { name: panel.caption })
      expect(within(table).queryAllByText(panel.text).length).toBeGreaterThan(0)
      expect(within(table).queryByText(/^No /i)).not.toBeInTheDocument()
      expect(within(table).queryByText(/No data/i)).not.toBeInTheDocument()
    }

    const incidents = screen.getByRole('table', { name: /open incident dashboard/i })
    expect(within(incidents).getByText(/checkout latency/i)).toBeInTheDocument()

    expect(requests.some((u) => new URL(u, 'http://t.invalid').searchParams.has('tenant_id'))).toBe(
      false,
    )
    for (const path of [
      '/v1/tests',
      '/v1/agents',
      '/v1/results/latest',
      '/v1/topology',
      '/v1/flows/top',
      '/v1/flows/capacity',
      '/v1/flows/anomalies',
      '/v1/cost/summary',
      '/v1/threat/detections',
    ]) {
      expect(requests.some((u) => pathOf(u) === path)).toBe(true)
    }
  })
})
