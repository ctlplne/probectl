// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { ApiError } from '../api/client'
import { HonestDataState, classifySurfaceTruth, type HonestDataStateKind } from '../components'
import { DemoModeProvider } from '../demo/DemoMode'
import { I18nProvider } from '../i18n/I18nProvider'
import { defaultFetch, jsonResponse } from './fetchStub'
import { renderApp } from './renderApp'

afterEach(() => cleanup())

const STATES: HonestDataStateKind[] = [
  'ready-no-data',
  'blocked',
  'permission-denied',
  'degraded',
  'quiet',
  'demo',
]

function pathOf(input: RequestInfo | URL): string {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  return new URL(raw, 'https://probectl.test').pathname
}

describe('truthful tenant-data states', () => {
  test('classifies explicit server truth without turning failures into healthy empties', () => {
    expect(classifySurfaceTruth({})).toBe('ready-no-data')
    expect(classifySurfaceTruth({ producerRunning: false })).toBe('blocked')
    expect(classifySurfaceTruth({ error: new ApiError(403, 'forbidden') })).toBe(
      'permission-denied',
    )
    expect(classifySurfaceTruth({ error: new Error('store unavailable') })).toBe('degraded')
    expect(classifySurfaceTruth({ degraded: true })).toBe('degraded')
    expect(classifySurfaceTruth({ producerRunning: true, quiet: true })).toBe('quiet')
    expect(
      classifySurfaceTruth({ demo: true, error: new Error('must not leak live status') }),
    ).toBe('demo')
  })

  test.each(STATES)('%s shows readiness, ingest, coverage, and one next action', (state) => {
    // The cold states additionally render the sample-tour bridge, which
    // composes router + demo + i18n context — same providers App.tsx supplies.
    const { container } = render(
      <MemoryRouter>
        <I18nProvider initialLocale="en">
          <DemoModeProvider>
            <HonestDataState
              state={state}
              producer="Synthetic collector"
              producerReadiness="Server-reported readiness"
              lastSuccessfulIngest="2026-07-14T20:30:00Z"
              coverageLimitation="Only configured tenant vantage points are covered."
              action={<button type="button">Authorized next action</button>}
            />
          </DemoModeProvider>
        </I18nProvider>
      </MemoryRouter>,
    )

    const surfaceState = container.querySelector(`[data-data-state="${state}"]`)
    expect(surfaceState).not.toBeNull()
    expect(within(surfaceState as HTMLElement).getByText(/producer readiness/i)).toBeInTheDocument()
    expect(
      within(surfaceState as HTMLElement).getByText(/last successful ingest/i),
    ).toBeInTheDocument()
    expect(
      within(surfaceState as HTMLElement).getByText(/coverage limitation/i),
    ).toBeInTheDocument()
    const action = (surfaceState as HTMLElement).querySelector('[data-authorized-next-action]')
    expect(within(action as HTMLElement).getAllByRole('button')).toHaveLength(1)

    // The sample-tour bridge appears on exactly the cold states — never on
    // denied/degraded (no fiction as a next step) or inside the demo itself.
    const bridge = within(surfaceState as HTMLElement).queryByRole('link', {
      name: /see a sample/i,
    })
    if (state === 'ready-no-data' || state === 'blocked' || state === 'quiet') {
      expect(bridge).toBeInTheDocument()
    } else {
      expect(bridge).toBeNull()
    }
  })

  test('a successful empty targets response is ready-no-data and paints no sample telemetry', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/tests'
          ? Promise.resolve(jsonResponse({ items: [] }))
          : fallback(input, init),
      ),
    )

    const { container } = renderApp('/targets')
    await waitFor(() =>
      expect(container.querySelector('[data-data-state="ready-no-data"]')).not.toBeNull(),
    )
    expect(container).toHaveTextContent('Ready; the tenant has no test definitions')
    expect(screen.queryByLabelText(/sample preview/i)).toBeNull()
    expect(screen.queryByText(/Avg RTT \(24h\)/i)).toBeNull()
    expect(screen.queryByText(/Packet loss \(24h\)/i)).toBeNull()
  })

  test('running:false renders blocked facts, never a healthy table or sample pixel', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/compliance'
          ? Promise.resolve(jsonResponse({ compliance_running: false, items: [] }))
          : fallback(input, init),
      ),
    )

    const { container } = renderApp('/compliance')
    expect(await screen.findByText(/server reports compliance_running=false/i)).toBeInTheDocument()
    expect(container.querySelector('[data-data-state="blocked"]')).not.toBeNull()
    expect(screen.queryByRole('table', { name: /segmentation verdicts/i })).toBeNull()
    expect(screen.queryByLabelText(/sample preview/i)).toBeNull()
  })

  test('failed and forbidden fetches remain degraded and permission-denied', async () => {
    const fallback = defaultFetch()
    let status = 503
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/tests'
          ? Promise.resolve(
              jsonResponse(
                { error: { message: status === 403 ? 'forbidden' : 'store unavailable' } },
                status,
              ),
            )
          : fallback(input, init),
      ),
    )

    const first = renderApp('/targets')
    await waitFor(
      () => expect(first.container.querySelector('[data-data-state="degraded"]')).not.toBeNull(),
      { timeout: 3_000 },
    )
    expect(screen.queryByRole('table', { name: /synthetic tests/i })).toBeNull()
    first.unmount()

    status = 403
    const second = renderApp('/targets')
    await waitFor(() =>
      expect(
        second.container.querySelector('[data-data-state="permission-denied"]'),
      ).not.toBeNull(),
    )
    expect(screen.queryByRole('table', { name: /synthetic tests/i })).toBeNull()
  })

  test('server-reported feed failure is degraded, while a healthy empty window is quiet', async () => {
    const fallback = defaultFetch()
    let failed = true
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/outages'
          ? Promise.resolve(
              jsonResponse({
                outage_running: true,
                feeds_enabled: true,
                events: [],
                vantage_events: [],
                feeds: [
                  {
                    name: 'cached-open-feed',
                    status: failed ? 'failed' : 'ok',
                    last_success: '2026-07-14T20:30:00Z',
                    events: 0,
                    license: 'open',
                    commercial_use: 'reviewed',
                    url: 'https://example.test/feed',
                  },
                ],
                coverage_notes: ['Tenant vantage points only.'],
              }),
            )
          : fallback(input, init),
      ),
    )

    const degraded = renderApp('/outages')
    await waitFor(() =>
      expect(degraded.container.querySelector('[data-data-state="degraded"]')).not.toBeNull(),
    )
    expect(screen.getByText('2026-07-14T20:30:00Z')).toBeInTheDocument()
    degraded.unmount()

    failed = false
    const quiet = renderApp('/outages')
    await waitFor(() =>
      expect(quiet.container.querySelector('[data-data-state="quiet"]')).not.toBeNull(),
    )
  })

  test('dashboard running:false fixtures never synthesize zero-valued trend pixels', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        switch (pathOf(input)) {
          case '/v1/cost/summary':
            return Promise.resolve(jsonResponse({ cost_running: false }))
          case '/v1/flows/capacity':
            return Promise.resolve(jsonResponse({ items: [] }))
          case '/v1/results/latest':
            return Promise.resolve(jsonResponse({ items: [], collector_running: false }))
          default:
            return fallback(input, init)
        }
      }),
    )

    renderApp('/dashboards')
    expect(await screen.findByText(/server reports cost_running=false/i)).toBeInTheDocument()
    expect(screen.getByText(/server reports collector_running=false/i)).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /cost trend/i })).toBeNull()
    expect(screen.queryByRole('img', { name: /flow capacity trend/i })).toBeNull()
    expect(screen.queryByRole('img', { name: /synthetic latency trend/i })).toBeNull()
  })
})
