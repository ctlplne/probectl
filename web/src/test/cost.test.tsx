import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { CostResponse } from '../api/cost'

/** S44 surface: the FinOps cost summary — showback, chatty pairs, budgets. */

function summaryFixture(): CostResponse {
  return {
    cost_running: true,
    summary: {
      priced: true,
      zones_mapped: true,
      pricing_source: 'public cloud pricing pages (representative list rates)',
      pricing_as_of: '2026-06-01',
      total_bytes: 17 * 2 ** 30,
      total_usd: 0.38,
      by_class: {
        inter_az: { bytes: 10 * 2 ** 30, usd: 0.1 },
        internet_egress: { bytes: 2 * 2 ** 30, usd: 0.18 },
      },
      by_service: {
        checkout: { bytes: 12 * 2 ** 30, usd: 0.38 },
      },
      by_team: {
        payments: { bytes: 12 * 2 ** 30, usd: 0.38 },
        '(unattributed)': { bytes: 5 * 2 ** 30, usd: 0 },
      },
      chatty_pairs: [
        {
          service: 'checkout', src_zone: 'us-east-1a', dst_zone: 'us-east-1b',
          class: 'inter_az', bytes: 10 * 2 ** 30, usd: 0.1, chatty: true,
        },
        {
          service: 'inventory', src_zone: 'us-east-1b', dst_zone: 'us-east-1a',
          class: 'inter_az', bytes: 2 ** 20, usd: 0, chatty: false,
        },
      ],
      trend: [{ hour: '2026-06-04T12:00:00Z', bytes: 17 * 2 ** 30, usd: 0.38 }],
      budgets: [
        { kind: 'team', name: 'payments', monthly_usd: 0.15, spent_usd: 0.38, exceeded: true },
        { kind: 'service', name: 'analytics', monthly_usd: 100, spent_usd: 1.2, exceeded: false },
      ],
    },
  }
}

function stubWith(resp: CostResponse, carbon?: unknown) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/cost/summary')) return jsonResponse(resp)
    if (url.endsWith('/v1/carbon')) return jsonResponse(carbon ?? { carbon_running: false })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

const carbonFixture = {
  carbon_running: true,
  summary: {
    total_bytes: 12 * 2 ** 30, total_kwh: 0.22, total_gco2e: 88,
    by_class: { inter_az: { bytes: 10 * 2 ** 30, kwh: 0.1, gco2e: 40 } },
    by_service: { checkout: { bytes: 10 * 2 ** 30, kwh: 0.1, gco2e: 40 } },
    by_team: {
      payments: { bytes: 10 * 2 ** 30, kwh: 0.1, gco2e: 40 },
      '(unattributed)': { bytes: 2 * 2 ** 30, kwh: 0.12, gco2e: 48 },
    },
    trend: [],
    methodology: {
      measured: false, grid_gco2e_per_kwh: 400,
      source: 'fixed-network transmission coefficients (Aslan et al. 2017 band, scaled by locality); operator-set grid intensity',
      note: 'coefficient-based ESTIMATE of network transmission energy — not measured device power',
    },
  },
}

describe('cost / FinOps summary (S44)', () => {
  test('shows totals, team showback, chatty pairs and budget breach', async () => {
    vi.stubGlobal('fetch', stubWith(summaryFixture()))
    renderApp('/cost')

    // Totals + pricing provenance (freshness surfaced).
    expect((await screen.findAllByText('$0.38')).length).toBeGreaterThan(0)
    expect(screen.getByText(/as of 2026-06-01/)).toBeInTheDocument()

    // Showback table sorted by spend.
    const showback = screen.getByRole('table', { name: /spend by team/i })
    expect(within(showback).getByText('payments')).toBeInTheDocument()
    expect(within(showback).getByText('(unattributed)')).toBeInTheDocument()

    // Chatty cross-AZ pair flagged; quiet pair not.
    const pairs = screen.getByRole('table', { name: /chatty zone pairs/i })
    expect(within(pairs).getByText('chatty')).toBeInTheDocument()
    expect(within(pairs).getByText(/us-east-1a → us-east-1b/)).toBeInTheDocument()
    expect(within(pairs).getByText('ok')).toBeInTheDocument()

    // Budget breach badge.
    const budgets = screen.getByRole('table', { name: /budget status/i })
    expect(within(budgets).getByText('exceeded')).toBeInTheDocument()
    expect(within(budgets).getByText('within')).toBeInTheDocument()
  })

  test('degradation honesty: volume-only mode never invents dollars', async () => {
    const resp = summaryFixture()
    resp.summary = {
      ...resp.summary!,
      priced: false,
      total_usd: 0,
      pricing_source: undefined,
      pricing_as_of: undefined,
    }
    vi.stubGlobal('fetch', stubWith(resp))
    renderApp('/cost')

    expect(await screen.findByRole('note', { name: /volume-only mode/i })).toBeInTheDocument()
    expect(screen.getByText('volume-only')).toBeInTheDocument()
    // Dollar columns show — instead of $0.00 fabrications.
    const showback = screen.getByRole('table', { name: /spend by team/i })
    expect(within(showback).getAllByText('—').length).toBeGreaterThan(0)
  })

  test('honesty: unwired engine renders as not wired', async () => {
    vi.stubGlobal('fetch', stubWith({ cost_running: false }))
    renderApp('/cost')
    expect(await screen.findByText(/cost engine not wired/i)).toBeInTheDocument()
  })

  test('carbon card (S48): the ESG estimate renders with the methodology stated', async () => {
    vi.stubGlobal('fetch', stubWith(summaryFixture(), carbonFixture))
    renderApp('/cost')

    const table = await screen.findByRole('table', { name: /carbon by team/i })
    expect(within(table).getByText('payments')).toBeInTheDocument()
    expect(within(table).getByText('40.0')).toBeInTheDocument() // gCO2e est.
    // The methodology honesty is front and center: an ESTIMATE, never measured.
    const note = screen.getByRole('note', { name: /carbon methodology/i })
    expect(within(note).getByText(/not measured power/)).toBeInTheDocument()
    expect(within(note).getByText(/grid 400 gCO2e\/kWh/)).toBeInTheDocument()
    expect(within(note).getByText('estimate')).toBeInTheDocument() // the badge
  })

  test('carbon honesty: unwired engine renders as not wired', async () => {
    vi.stubGlobal('fetch', stubWith(summaryFixture(), { carbon_running: false }))
    renderApp('/cost')
    expect(await screen.findByText(/carbon engine not wired/i)).toBeInTheDocument()
  })

  test('a11y: the cost page passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stubWith(summaryFixture(), carbonFixture))
    const { container } = renderApp('/cost')
    await screen.findAllByText('$0.38')
    await screen.findByRole('table', { name: /carbon by team/i })
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })
})
