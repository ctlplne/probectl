// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const ERROR_WAIT = { timeout: 7_000 }

function serverFailure(message: string) {
  return jsonResponse({ error: { code: 'unavailable', message } }, 500)
}

function failReads(
  shouldFail: (input: RequestInfo | URL, init?: RequestInit) => boolean,
  message = 'tenant store unavailable',
) {
  const fallback = defaultFetch()
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
      shouldFail(input, init) ? Promise.resolve(serverFailure(message)) : fallback(input, init),
    ),
  )
}

describe('API failures stay distinct from empty or unavailable states', () => {
  test('path test-registry failure is not rendered as “No tests yet”', async () => {
    failReads((input) => pathOf(input) === '/v1/tests')

    renderApp('/path')

    expect(
      await screen.findByText(
        /could not load tenant tests for path discovery/i,
        undefined,
        ERROR_WAIT,
      ),
    ).toBeInTheDocument()
    expect(screen.queryByText(/^no tests yet$/i)).not.toBeInTheDocument()
  })

  test('path incident/change overlay failure is visible beside the loaded path', async () => {
    failReads((input) => ['/v1/incidents', '/v1/changes'].includes(pathOf(input)))

    renderApp('/path')

    expect(
      await screen.findByText(
        /could not load incident and change overlays for this path/i,
        undefined,
        ERROR_WAIT,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText(/selected path/i)).toBeInTheDocument()
  })

  test('populated path fixture serves normal incident and change overlay evidence', async () => {
    renderApp('/path')

    expect(
      await screen.findByRole(
        'link',
        { name: /open change evidence: dns edge route update/i },
        ERROR_WAIT,
      ),
    ).toBeInTheDocument()
    expect(
      screen.queryByText(/could not load incident and change overlays for this path/i),
    ).not.toBeInTheDocument()
  })

  test('onboarding progress failure leaves setup actions available', async () => {
    failReads((input) => pathOf(input) === '/v1/onboarding/progress')

    renderApp('/onboarding', { me: { permissions: ['agent.write'] } })

    expect(
      await screen.findByText(/onboarding progress unavailable/i, undefined, ERROR_WAIT),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /mint enrollment token/i })).toBeEnabled()
  })

  test('saved-view failure does not hide the live endpoint fleet', async () => {
    failReads((input) => pathOf(input) === '/v1/inventory/views')

    renderApp('/endpoints')

    expect(
      await screen.findByText(/saved views unavailable/i, undefined, ERROR_WAIT),
    ).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /endpoint fleet/i })).toBeInTheDocument()
  })

  test('flow capacity failure is visible while top talkers remain usable', async () => {
    failReads((input) => pathOf(input) === '/v1/flows/capacity')

    renderApp('/planes/flow')

    expect(
      await screen.findByText(/could not load flow capacity samples/i, undefined, ERROR_WAIT),
    ).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /flow top talkers/i })).toBeInTheDocument()
  })

  test('dashboard history failure fails the dashboard honestly', async () => {
    failReads((input) => pathOf(input) === '/v1/results/history')

    renderApp('/dashboards')

    expect(
      await screen.findByText(/could not load every dashboard panel/i, undefined, ERROR_WAIT),
    ).toBeInTheDocument()
    expect(screen.queryByRole('img', { name: /synthetic latency trend/i })).not.toBeInTheDocument()
  })

  test('dashboard history 404 keeps the documented latest-snapshot fallback', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/results/history'
          ? Promise.resolve(
              jsonResponse(
                { error: { code: 'not_found', message: 'history endpoint unavailable' } },
                404,
              ),
            )
          : fallback(input, init),
      ),
    )

    renderApp('/dashboards')

    expect((await screen.findAllByText(/active tests/i)).length).toBeGreaterThan(0)
    expect(screen.queryByText(/could not load every dashboard panel/i)).not.toBeInTheDocument()
  })

  test('time-travel comparison failure does not erase the selected topology', async () => {
    const comparisonTime = '2026-06-04T11:00:00.000Z'
    failReads((input) => {
      const url = new URL(String(input), 'http://t.invalid')
      return url.pathname === '/v1/topology' && url.searchParams.get('at') === comparisonTime
    })

    renderApp(
      `/topology?at=2026-06-04T12%3A00%3A00.000Z&ctx_v=1&ctx_expires=2099-01-01T00%3A00%3A00.000Z&ctx_from=${encodeURIComponent(comparisonTime)}&ctx_to=2026-06-04T12%3A00%3A00.000Z`,
    )

    expect(
      await screen.findByText(/topology comparison unavailable/i, undefined, ERROR_WAIT),
    ).toBeInTheDocument()
    expect(screen.getByRole('group', { name: /topology graph/i })).toBeInTheDocument()
  })

  test('remediation 5xx is visible while unlicensed 404 remains hidden', async () => {
    failReads((input) => pathOf(input) === '/v1/remediation/proposals')
    const failed = renderApp('/security')

    expect(
      await screen.findByText(/remediation availability unknown/i, undefined, ERROR_WAIT),
    ).toBeInTheDocument()

    failed.unmount()
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/remediation/proposals'
          ? Promise.resolve(
              jsonResponse({ error: { code: 'not_found', message: 'feature not licensed' } }, 404),
            )
          : fallback(input, init),
      ),
    )
    renderApp('/security')

    expect(await screen.findByRole('heading', { name: /security/i })).toBeInTheDocument()
    expect(screen.queryByText(/remediation availability unknown/i)).not.toBeInTheDocument()
  })
})
