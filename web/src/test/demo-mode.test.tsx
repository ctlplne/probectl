// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { apiFetch, setDemoTransportIsolation } from '../api/client'
import { DEMO_PAGES, DEMO_PAGE_PATHS } from '../demo/demoPages'
import { NAV } from '../nav/ia'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

afterEach(() => setDemoTransportIsolation(false))

function requestedPaths(fetcher: ReturnType<typeof vi.fn>): string[] {
  return fetcher.mock.calls.map(([input]) => {
    const raw =
      typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url
    return new URL(raw, 'https://probectl.test').pathname
  })
}

describe('transport-isolated demo mode', () => {
  test('every tenant menu has a populated demo definition', () => {
    expect([...DEMO_PAGE_PATHS].sort()).toEqual(NAV.map((item) => item.to).sort())
    for (const item of NAV) {
      const page = DEMO_PAGES[item.to]
      expect(page.metrics, `${item.to} metrics`).toHaveLength(4)
      expect(page.primary.rows.length, `${item.to} primary rows`).toBeGreaterThanOrEqual(3)
      expect(page.secondary.rows.length, `${item.to} secondary rows`).toBeGreaterThanOrEqual(3)
      for (const panel of [page.primary, page.secondary]) {
        for (const sample of panel.rows) {
          expect(sample.cells, `${item.to}/${panel.title}/${sample.id}`).toHaveLength(
            panel.columns.length,
          )
        }
      }
    }
  })

  test('is persistent, route-aware, unmistakable, and never mounts live tenant routes', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets?demo=1')

    expect(
      await screen.findByRole('heading', { name: /targets & active tests/i }),
    ).toBeInTheDocument()
    expect(screen.getByLabelText(/demo mode is active/i)).toBeInTheDocument()
    expect(screen.getAllByText('Demo data')).toHaveLength(7)
    expect(screen.getByRole('table', { name: /active tests demo data/i })).toHaveTextContent(
      'checkout-http',
    )
    expect(screen.queryByRole('heading', { name: /targets & tests/i })).toBeNull()
    expect(requestedPaths(fetcher)).not.toContain('/v1/tests')
    expect(requestedPaths(fetcher)).not.toContain('/v1/alerts')

    await userEvent.click(screen.getByRole('link', { name: /incidents/i }))
    expect(screen.getByLabelText(/demo mode is active/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /^incidents$/i })).toBeInTheDocument()
    expect(screen.getByText('Checkout latency regression')).toBeInTheDocument()
    expect(requestedPaths(fetcher)).not.toContain('/v1/incidents')
  })

  test('mounts the real incident clock on sample props, still without live queries', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    renderApp('/incidents?demo=1')

    const clock = await screen.findByRole('list', { name: /sample checkout incident timeline/i })
    expect(within(clock).getByRole('button', { name: /as path changed/i })).toBeInTheDocument()

    await userEvent.click(within(clock).getByRole('button', { name: /as path changed/i }))
    expect(
      screen.getByText(/selected evidence: as path changed for the checkout prefix/i),
    ).toBeInTheDocument()

    // The viz panel carries its own Demo data badge: header + 4 metrics + viz + 2 tables.
    expect(screen.getAllByText('Demo data')).toHaveLength(8)
    expect(requestedPaths(fetcher)).not.toContain('/v1/incidents')
  })

  test('mounts the real path graph on sample props, still without live queries', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    renderApp('/path?demo=1')

    expect(await screen.findByRole('heading', { name: /path analysis/i })).toBeInTheDocument()
    const graph = await screen.findByRole('group', { name: /network path to checkout\.example/i })

    await userEvent.click(within(graph).getByRole('button', { name: /192\.0\.2\.9/i }))
    expect(screen.getByText(/selected hop: ttl 6 · 192\.0\.2\.9/i)).toBeInTheDocument()

    // The tour mirrors the live page's secondary views on the same sample hops.
    await userEvent.click(screen.getByRole('button', { name: /latency profile/i }))
    expect(
      await screen.findByRole('group', { name: /latency by hop to checkout\.example/i }),
    ).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^geography$/i }))
    const geo = await screen.findByRole('group', { name: /geographic path to checkout\.example/i })
    expect(within(geo).getByRole('button', { name: /ashburn/i })).toBeInTheDocument()
    expect(screen.getByText(/responders without location/i)).toBeInTheDocument()

    expect(requestedPaths(fetcher)).not.toContain('/v1/tests')
    expect(requestedPaths(fetcher)).not.toContain(
      '/v1/tests/10000000-0000-4000-8000-000000000001/path',
    )
    expect(requestedPaths(fetcher)).not.toContain(
      '/v1/tests/10000000-0000-4000-8000-000000000001/path/history',
    )
  })

  test('renders a populated and accessible dashboard without live dashboard queries', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    const { container } = renderApp('/dashboards?demo=1')

    expect(await screen.findByRole('heading', { name: /^dashboards$/i })).toBeInTheDocument()
    expect(screen.getByText('99.94%')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /service health demo data/i })).toHaveTextContent(
      'checkout',
    )
    expect(
      screen.getByRole('table', { name: /current operator queue demo data/i }),
    ).toHaveTextContent('Network SRE')

    // The sample latency chart mounts (or honestly falls back to its table
    // twin) before the accessibility assertion runs.
    expect(
      await screen.findByRole('table', { name: /checkout vs payments p95 latency/i }),
    ).toBeInTheDocument()

    expect(requestedPaths(fetcher)).not.toContain('/v1/dashboards')
    expect(requestedPaths(fetcher)).not.toContain('/v1/incidents')
    expect(requestedPaths(fetcher)).not.toContain('/v1/results/history')
    expect(await axe(container)).toHaveNoViolations()
  })

  test('Shift+D exits in one keyboard command and only then permits the live route query', async () => {
    const fetcher = defaultFetch() as ReturnType<typeof vi.fn>
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets?demo=1')
    await screen.findByLabelText(/demo mode is active/i)

    fireEvent.keyDown(document, { key: 'D', shiftKey: true })

    await waitFor(() => expect(screen.queryByLabelText(/demo mode is active/i)).toBeNull())
    expect(await screen.findByRole('heading', { name: /targets & tests/i })).toBeInTheDocument()
    await waitFor(() => expect(requestedPaths(fetcher)).toContain('/v1/tests'))
    expect(screen.queryByLabelText(/sample preview/i)).toBeNull()
  })

  test('the API client fails closed if a future demo component attempts a live request', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    setDemoTransportIsolation(true)

    await expect(apiFetch('/alerts')).rejects.toThrow(/live tenant APIs are disabled/i)
    expect(fetcher).not.toHaveBeenCalled()
  })
})
