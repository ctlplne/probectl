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

function stubWith(resp: CostResponse) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/cost/summary')) return jsonResponse(resp)
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
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

  test('a11y: the cost page passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stubWith(summaryFixture()))
    const { container } = renderApp('/cost')
    await screen.findAllByText('$0.38')
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })
})
