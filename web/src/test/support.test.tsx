// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

/** S-EE4 surface: the Support & diagnostics card — deep health per component
 *  + the secret-stripped support-bundle download. */

describe('support & diagnostics (S-EE4)', () => {
  test('renders actionable local findings, component checks, and the bundle link', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')

    expect(await screen.findByText('Support & diagnostics')).toBeInTheDocument()
    // The secret-stripped bundle download.
    expect(screen.getByRole('link', { name: /download support bundle/i })).toHaveAttribute(
      'href',
      '/v1/diagnostics/bundle',
    )
    const findings = await screen.findByRole('table', {
      name: /actionable readiness findings/i,
    })
    expect(within(findings).getByText('Control-plane writes are temporarily fenced')).toBeInTheDocument()
    expect(within(findings).getByText('Warning')).toBeInTheDocument()
    expect(within(findings).getByRole('link', { name: /download redacted support bundle/i })).toHaveAttribute(
      'href',
      '/v1/diagnostics/bundle',
    )
    expect(
      screen.getByRole('link', { name: /download support bundle/i }).closest('p'),
    ).toHaveTextContent(/1 finding/)
    expect(document.querySelector('time[datetime="2026-06-06T00:00:00.000Z"]')).toBeInTheDocument()
    // Per-component deep health.
    const table = await screen.findByRole('table', {
      name: /component health/i,
    })
    const clusterRow = within(table).getByText('cluster').closest('tr')!
    expect(within(clusterRow).getByText('Degraded')).toBeInTheDocument()
    const dbRow = within(table).getByText('database').closest('tr')!
    expect(within(dbRow).getByText('OK')).toBeInTheDocument()
  })

  test('does not infer health when an older replica omits finding details', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/diagnostics'
          ? Promise.resolve(
              jsonResponse({
                status: 'degraded',
                checked_at: '2026-06-06T00:00:00Z',
                checks: [{ name: 'cluster', status: 'degraded', detail: 'writes are fenced' }],
              }),
            )
          : fallback(input, init),
      ),
    )

    renderApp('/admin')

    expect(await screen.findByRole('alert')).toHaveTextContent(/missing finding details/i)
    expect(screen.getByText('Finding details unavailable')).toBeInTheDocument()
    expect(screen.queryByText('No readiness findings')).not.toBeInTheDocument()
  })

  test('keeps a retry action when diagnostics cannot be loaded', async () => {
    const user = userEvent.setup()
    const fallback = defaultFetch()
    let diagnosticsCalls = 0
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) !== '/v1/diagnostics') return fallback(input, init)
        diagnosticsCalls += 1
        if (diagnosticsCalls <= 2) {
          return Promise.resolve(
            jsonResponse({ error: { code: 'unavailable', message: 'local check failed' } }, 503),
          )
        }
        return fallback(input, init)
      }),
    )

    renderApp('/admin')

    expect(
      await screen.findByText(/could not load diagnostics.*no healthy state is being inferred/i, {
        selector: 'p',
      }),
    ).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /retry diagnostics/i }))
    expect(await screen.findByText('Control-plane writes are temporarily fenced')).toBeInTheDocument()
    expect(diagnosticsCalls).toBe(3)
  })
})
