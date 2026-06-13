import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { SLOsResponse } from '../api/slos'

/** S45 surface: the SLO dashboard — attainment, error budgets, burn rates. */

function fixture(): SLOsResponse {
  return {
    slo_running: true,
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
