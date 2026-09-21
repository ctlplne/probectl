// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation, useNavigate } from 'react-router-dom'
import { Providers } from '../App'
import { AppRoutes } from '../routes/AppRoutes'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

function HistoryControls() {
  const navigate = useNavigate()
  const location = useLocation()
  return (
    <div>
      <button type="button" onClick={() => void navigate(-1)}>
        Test back
      </button>
      <button type="button" onClick={() => void navigate(1)}>
        Test forward
      </button>
      <output aria-label="Test location">{location.search}</output>
    </div>
  )
}

function renderDashboardWithHistory(path: string) {
  const inner = globalThis.fetch
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/v1/me')) {
      return Promise.resolve(
        jsonResponse({
          tenant_id: '00000000-0000-0000-0000-000000000001',
          tenant_name: 'Acme Industries',
          user_id: 'u_test',
          email: 'operator@probectl.test',
          display_name: 'Test Operator',
          mfa_satisfied: true,
          permissions: [],
        }),
      )
    }
    return inner(input, init)
  })
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <HistoryControls />
        <AppRoutes />
      </MemoryRouter>
    </Providers>,
  )
}

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
    // Cost trend (>=2 timestamped samples) upgraded to the S11 TimeSeries; in
    // jsdom (no canvas) its accessible representation is the data-table twin.
    expect(screen.getByRole('table', { name: /cost trend/i })).toBeInTheDocument()
    // Capacity has a single fixture sample, so it stays on the SVG Sparkline.
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

    const threatSignals = screen.getByRole('table', { name: /threat signal dashboard/i })
    expect(within(threatSignals).getByText('82%')).toBeInTheDocument()
    expect(within(threatSignals).queryByText('8,200%')).not.toBeInTheDocument()

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

  test('replays one bounded scope into every time-aware request and changes preset detail', async () => {
    const requests: string[] = []
    const inner = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        requests.push(String(input))
        return inner(input, init)
      }),
    )
    const user = userEvent.setup()
    renderApp('/dashboards?range=15m')

    const scope = await screen.findByRole('region', { name: /dashboard scope and preset/i })
    const timeSelect = within(scope).getByRole('combobox', { name: /relative time scope/i })
    expect(timeSelect).toHaveValue('15m')
    expect(within(scope).getByText(/last 15 minutes coordinated/i)).toBeInTheDocument()

    await waitFor(() => {
      for (const path of [
        '/v1/flows/top',
        '/v1/flows/capacity',
        '/v1/flows/anomalies',
        '/v1/results/history',
      ]) {
        expect(
          requests.some((request) => {
            const url = new URL(request, 'http://t.invalid')
            return url.pathname === path && url.searchParams.get('window') === '15m'
          }),
        ).toBe(true)
      }
    })

    requests.length = 0
    await user.selectOptions(timeSelect, '6h')
    expect(timeSelect).toHaveValue('6h')
    expect(within(scope).getByText(/last 6 hours coordinated/i)).toBeInTheDocument()
    await waitFor(() => {
      for (const path of [
        '/v1/flows/top',
        '/v1/flows/capacity',
        '/v1/flows/anomalies',
        '/v1/results/history',
      ]) {
        expect(
          requests.some((request) => {
            const url = new URL(request, 'http://t.invalid')
            return url.pathname === path && url.searchParams.get('window') === '6h'
          }),
        ).toBe(true)
      }
    })

    expect(screen.getAllByText('Latest state').length).toBeGreaterThan(0)
    expect(screen.getByRole('table', { name: /active tests dashboard/i })).toBeInTheDocument()
    await user.click(within(scope).getByRole('button', { name: 'Executive' }))
    expect(within(scope).getByText(/summary and risk panels are visible/i)).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: /active tests dashboard/i })).toBeNull()
    expect(screen.getByRole('table', { name: /open incident dashboard/i })).toBeInTheDocument()
  })

  test.each([
    '/dashboards?range=2h&tenant_id=other',
    '/dashboards?range=1h&range=24h',
    `/dashboards?range=${'x'.repeat(128)}`,
  ])('canonicalizes unsafe scope state to the tenant-free 1h default: %s', async (path) => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp(path)

    const scope = await screen.findByRole('region', { name: /dashboard scope and preset/i })
    expect(within(scope).getByRole('combobox', { name: /relative time scope/i })).toHaveValue('1h')
    expect(within(scope).getByText(/last 1 hour coordinated/i)).toBeInTheDocument()
  })

  test('renders the scope controller in Spanish and Arabic without changing wire values', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    const spanish = renderApp('/dashboards?range=24h', { locale: 'es' })
    const spanishScope = await screen.findByRole('region', {
      name: /dashboard scope and preset/i,
    })
    expect(within(spanishScope).getByRole('combobox', { name: /intervalo relativo/i })).toHaveValue(
      '24h',
    )
    expect(within(spanishScope).getByText(/últimas 24 horas coordinado/i)).toBeInTheDocument()
    spanish.unmount()

    renderApp('/dashboards?range=15m', { locale: 'ar' })
    const arabicScope = await screen.findByRole('region', {
      name: /dashboard scope and preset/i,
    })
    expect(
      within(arabicScope).getByRole('combobox', { name: /النطاق الزمني النسبي/i }),
    ).toHaveValue('15m')
    expect(within(arabicScope).getByText(/آخر 15 دقيقة منسّق/i)).toBeInTheDocument()
  })

  test('Back and Forward replay the selected relative scope', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    const user = userEvent.setup()
    renderDashboardWithHistory('/dashboards?range=1h')
    const timeSelect = await screen.findByRole('combobox', { name: /relative time scope/i })

    await user.selectOptions(timeSelect, '6h')
    await waitFor(() =>
      expect(screen.getByLabelText('Test location')).toHaveTextContent('range=6h'),
    )

    await user.click(screen.getByRole('button', { name: 'Test back' }))
    await waitFor(() => expect(timeSelect).toHaveValue('1h'))

    await user.click(screen.getByRole('button', { name: 'Test forward' }))
    await waitFor(() => expect(timeSelect).toHaveValue('6h'))
  })
})
