import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { RUMResponse } from '../api/rum'

/** S47b surface: RUM folds into the endpoint/DEM view — the convergence
 * verdicts (with honesty wording) + the enforced privacy posture. */

function fixture(): RUMResponse {
  return {
    rum_running: true,
    apps: [
      {
        app: 'storefront', host: 'web.acme.example',
        window_views: 120, error_rate: 0.12, p75_lcp_ms: 4200, p75_ttfb_ms: 300,
        rum_degraded: true, synthetic_observed: true, synthetic_degraded: true,
        verdict: 'user_impact_confirmed',
        pages: [{ page: '/checkout/:id', views: 80, error_rate: 0.15, p75_lcp_ms: 4600 }],
      },
      {
        app: 'admin', host: 'admin.acme.example',
        window_views: 40, error_rate: 0, p75_lcp_ms: 1200,
        rum_degraded: false, synthetic_observed: true, synthetic_degraded: true,
        verdict: 'synthetic_only_no_user_impact',
        pages: [{ page: '/', views: 40, error_rate: 0 }],
      },
      {
        app: 'docs', host: 'docs.acme.example',
        window_views: 60, error_rate: 0.2, p75_lcp_ms: 5100,
        rum_degraded: true, synthetic_observed: false, synthetic_degraded: false,
        verdict: 'user_only_synthetic_blind',
        pages: [{ page: '/guides', views: 60, error_rate: 0.2 }],
      },
    ],
    privacy: {
      consent_required: true, url_redaction: true, ip_stored: false,
      rejected_no_consent: 7, rejected_malformed: 1, rejected_invalid_field: 0,
      accepted_page_views: 220,
    },
    coverage_notes: ['RUM reflects pages instrumented with the probectl beacon and users who consented — uninstrumented apps and opted-out users are invisible, and absence of RUM data is not proof of health'],
  }
}

function stubWith(rum: RUMResponse) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/rum')) return jsonResponse(rum)
    if (url.endsWith('/v1/endpoints')) return jsonResponse({ items: [], collector_running: true })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('rum convergence on the DEM surface (S47b)', () => {
  test('renders all three convergence verdicts with honesty wording + page grouping', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/endpoints')

    const table = (await screen.findByRole('table', { name: /rum convergence by application/i })) as HTMLTableElement
    // The exit-criterion row: synthetic + RUM correlate for the same service.
    expect(within(table).getByText('storefront')).toBeInTheDocument()
    expect(within(table).getByText('user impact confirmed')).toBeInTheDocument()
    // Honesty wording: observed-scope claims, never absolutes.
    expect(within(table).getByText('synthetic only — no user impact observed')).toBeInTheDocument()
    expect(within(table).getByText('users degraded — synthetic blind spot')).toBeInTheDocument()
    expect(within(table).getByText('none for this host')).toBeInTheDocument()
    // Redacted page grouping rides the UI.
    expect(within(table).getByText(/\/checkout\/:id \(80\)/)).toBeInTheDocument()

    // The enforced privacy posture is front and center.
    const note = screen.getByRole('note', { name: /rum privacy posture/i })
    expect(within(note).getByText(/consent required/)).toBeInTheDocument()
    expect(within(note).getByText(/7 beacons rejected without consent/)).toBeInTheDocument()
    expect(within(note).getByText(/absence of RUM data is not proof of health/)).toBeInTheDocument()
  })

  test('honesty: unwired RUM renders as not wired (with the enable pointers)', async () => {
    vi.stubGlobal('fetch', stubWith({ rum_running: false }))
    renderApp('/endpoints')
    expect(await screen.findByText(/rum not wired/i)).toBeInTheDocument()
    expect(screen.getByText(/PROBECTL_RUM_ENABLED/)).toBeInTheDocument()
  })

  test('running but quiet: points at the embed snippet', async () => {
    vi.stubGlobal('fetch', stubWith({ rum_running: true, apps: [], privacy: undefined }))
    renderApp('/endpoints')
    expect(await screen.findByText(/no real-user views in the window/i)).toBeInTheDocument()
    expect(screen.getByText(/who consented/)).toBeInTheDocument()
  })

  test('a11y: the DEM surface with the RUM card passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    const { container } = renderApp('/endpoints')
    await screen.findByRole('table', { name: /rum convergence by application/i })
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })
})
