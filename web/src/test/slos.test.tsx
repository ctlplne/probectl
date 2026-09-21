// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { SLOsResponse } from '../api/slos'

/** S45 surface: the SLO dashboard — attainment, error budgets, burn rates. */

function fixture(): SLOsResponse {
  return {
    slo_running: true,
    data_since: '2026-06-04T12:00:00Z',
    items: [
      {
        name: 'checkout-availability',
        display_name: 'Checkout availability',
        service: 'checkout',
        team: 'payments',
        objective: 0.99,
        window: '30d',
        attainment: 0.96,
        error_budget_remaining: 0,
        total_events: 130,
        cold_start: false,
        burn_rates: [
          { window: 'fast', long: '1h0m0s', short: '5m0s', burn: 96.8, limit: 14.4, firing: true },
          { window: 'medium', long: '6h0m0s', short: '30m0s', burn: 6.1, limit: 6, firing: true },
          { window: 'slow', long: '72h0m0s', short: '6h0m0s', burn: 1.5, limit: 1, firing: false },
        ],
      },
      {
        name: 'dns-resolution',
        service: 'dns-edge',
        team: 'platform',
        objective: 0.999,
        window: '7d',
        attainment: 1,
        error_budget_remaining: 1,
        total_events: 12,
        cold_start: true,
        burn_rates: [
          { window: 'fast', long: '1h0m0s', short: '5m0s', burn: 0, limit: 14.4, firing: false },
        ],
      },
    ],
  }
}

function stubWith(resp: SLOsResponse) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/slos')) return jsonResponse(resp)
    if (url.endsWith('/v1/explorer/schema'))
      return jsonResponse({
        templates: [
          {
            id: 'slo-budget-burn',
            question: 'Which SLO error budgets are burning?',
            source: 'slo',
            dimensions: ['slo', 'service', 'team'],
            groupings: ['service'],
            measures: ['burn_rate', 'budget_remaining'],
            visualization: 'bar',
            evidence_path: '/slos',
          },
        ],
        visualizations: ['table', 'bar'],
        max_rows: 100,
      })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('SLO dashboard (S45)', () => {
  test('shows attainment, exhausted budget and firing burn windows', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/slos')

    const table = await screen.findByRole('table', { name: /slo statuses/i })
    expect(within(table).getByText('Checkout availability')).toBeInTheDocument()
    expect(within(table).getByText(/checkout · payments · 30d/)).toBeInTheDocument()
    expect(within(table).getByText('96.00%')).toBeInTheDocument()
    // Budget exhausted: 0% left.
    expect(within(table).getByText(/0.00% left/)).toBeInTheDocument()
    // Firing burn windows render as danger badges with the multiplier.
    expect(within(table).getByText(/fast 96.8x/)).toBeInTheDocument()
    expect(within(table).getByText(/slow 1.5x/)).toBeInTheDocument()
  })

  test('exports SLO rows as OpenSLO YAML', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/slos')

    const table = await screen.findByRole('table', { name: /slo statuses/i })
    const checkoutRow = within(table).getByText('Checkout availability').closest('tr')
    expect(checkoutRow).not.toBeNull()
    await userEvent.click(
      within(checkoutRow as HTMLElement).getByRole('button', { name: 'View as YAML' }),
    )

    const dialog = await screen.findByRole('dialog', {
      name: /export as code: checkout-availability/i,
    })
    expect(dialog).toHaveTextContent('apiVersion: openslo/v1')
    expect(dialog).toHaveTextContent('kind: SLO')
    expect(dialog).toHaveTextContent('target: 0.99')
    expect(dialog).toHaveTextContent('timeWindow: 30d')
  })

  test('shows the reset boundary and opens tenant-scoped filtered evidence', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/slos')

    const note = await screen.findByRole('note', { name: /slo evaluation window/i })
    expect(note).toHaveTextContent(/reset on control-plane restart/i)
    expect(note).toHaveTextContent(/cold start is not a healthy verdict/i)

    const table = screen.getByRole('table', { name: /slo statuses/i })
    const checkoutRow = within(table).getByText('Checkout availability').closest('tr')
    await userEvent.click(
      within(checkoutRow as HTMLElement).getByRole('button', { name: /inspect evidence/i }),
    )

    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()
    expect(screen.getByLabelText(/ask in natural language/i)).toHaveValue(
      'Which SLO error budgets are burning?',
    )
    expect(screen.getByLabelText(/filter exact value/i)).toHaveValue('checkout-availability')
  })

  test('cold start renders honestly, not as healthy', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/slos')
    const table = await screen.findByRole('table', { name: /slo statuses/i })
    expect(within(table).getByText('cold start')).toBeInTheDocument()
  })

  test('honesty: unwired engine renders as not wired', async () => {
    vi.stubGlobal('fetch', stubWith({ slo_running: false, items: [] }))
    renderApp('/slos')
    expect(await screen.findByText(/slo engine not wired/i)).toBeInTheDocument()
  })

  test('empty definitions point at PROBECTL_SLO_DIR', async () => {
    vi.stubGlobal('fetch', stubWith({ slo_running: true, items: [] }))
    renderApp('/slos')
    expect(await screen.findByText(/no slos defined/i)).toBeInTheDocument()
    expect(screen.getByText(/PROBECTL_SLO_DIR/)).toBeInTheDocument()
  })

  test('a11y: the SLO page passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    const { container } = renderApp('/slos')
    await screen.findByRole('table', { name: /slo statuses/i })
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })
})
