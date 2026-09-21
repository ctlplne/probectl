// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import axe from 'axe-core'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { OutagesResponse } from '../api/outages'

/** S47a surface: the collective internet-outage view — external events
 * correlated with the tenant's affected tests, vantage detections, feed
 * health/AUP, and the no-global-fleet honesty notes. */

function fixture(): OutagesResponse {
  return {
    outage_running: true,
    feeds_enabled: true,
    scope_resolution: true,
    events: [
      {
        id: 'ioda:bgp:asn:AS64500:1',
        source: 'ioda',
        scope: { kind: 'asn', code: 'AS64500', name: 'Testland Telecom' },
        severity: 'critical',
        confidence: 1,
        title: 'Internet outage: Testland Telecom (AS64500)',
        summary: 'IODA bgp signal, score 620',
        start: '2026-06-05T10:00:00Z',
        evidence_url: 'https://ioda.inetintel.cc.gatech.edu/asn/64500',
        ongoing: true,
        affected_tests: [
          {
            canary_type: 'http',
            target: 'web.testland.example:443',
            failures: 3,
            last_failure: '2026-06-05T10:20:00Z',
          },
        ],
      },
      {
        id: 'cloudflare_radar:ann-1:country:TL',
        source: 'cloudflare_radar',
        scope: { kind: 'country', code: 'TL', name: 'Testland' },
        severity: 'warning',
        confidence: 0.9,
        title: 'Internet outage: Testland (TL)',
        start: '2026-06-05T08:00:00Z',
        end: '2026-06-05T09:00:00Z',
        ongoing: false,
      },
    ],
    vantage_events: [
      {
        id: 'vantage:t1:asn:AS64500:1780689600',
        source: 'vantage',
        scope: { kind: 'asn', code: 'AS64500', name: 'Testland Telecom' },
        severity: 'warning',
        confidence: 0.9,
        title: 'Vantage-detected outage: Testland Telecom (AS64500)',
        summary:
          '2 of 2 observed targets in Testland Telecom (AS64500) failing over the last 15m0s',
        start: '2026-06-05T10:05:00Z',
        ongoing: true,
      },
    ],
    feeds: [
      {
        name: 'ioda',
        status: 'ok',
        last_success: '2026-06-05T10:30:00Z',
        events: 12,
        license: 'IODA data-usage terms (academic project; attribution requested)',
        attribution: 'IODA, Georgia Institute of Technology',
        commercial_use: 'unknown',
        url: 'https://ioda.inetintel.cc.gatech.edu/',
      },
      {
        name: 'cloudflare_radar',
        status: 'failed',
        last_error: 'status 429',
        events: 0,
        license: 'CC BY-NC 4.0 (non-commercial)',
        attribution: 'Cloudflare Radar',
        commercial_use: 'restricted',
        url: 'https://radar.cloudflare.com/about',
      },
    ],
    coverage_notes: [
      'coverage = your vantage points + public open-data feeds — probectl does not operate a global probe fleet',
    ],
  }
}

function stubWith(resp: OutagesResponse) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/outages')) return jsonResponse(resp)
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('outages / collective internet-outage view (S47a)', () => {
  test('renders external events correlated with affected tests + vantage detections', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    renderApp('/outages')

    // External events with the customer-impact correlation (the exit criterion).
    const events = await screen.findByRole('table', { name: /external outage events/i })
    expect(
      within(events).getByText('Internet outage: Testland Telecom (AS64500)'),
    ).toBeInTheDocument()
    expect(
      within(events).getByText(/web\.testland\.example:443 \(3 failures\)/),
    ).toBeInTheDocument()
    expect(within(events).getByText('ongoing')).toBeInTheDocument()
    expect(within(events).getByText('ended')).toBeInTheDocument()
    expect(within(events).getByText('critical')).toBeInTheDocument()
    expect(within(events).getByRole('link', { name: 'evidence' })).toHaveAttribute(
      'href',
      'https://ioda.inetintel.cc.gatech.edu/asn/64500',
    )

    // The tenant's own vantage detections render separately.
    const vantage = screen.getByRole('table', { name: /vantage-detected outages/i })
    expect(
      within(vantage).getByText('Vantage-detected outage: Testland Telecom (AS64500)'),
    ).toBeInTheDocument()

    // Honesty note is front and center.
    const note = screen.getByRole('note', { name: /coverage notes/i })
    expect(within(note).getByText(/does not operate a global probe fleet/i)).toBeInTheDocument()

    // Feed health + AUP provenance (a failed feed is shown honestly).
    const feeds = screen.getByRole('table', { name: /outage feeds/i })
    expect(within(feeds).getByText('ok')).toBeInTheDocument()
    expect(within(feeds).getByText('failed')).toBeInTheDocument()
    expect(within(feeds).getByText(/commercial use: restricted/)).toBeInTheDocument()
    expect(within(feeds).getByText(/Georgia Institute of Technology/)).toBeInTheDocument()
  })

  test('honesty: unwired engine renders as not wired', async () => {
    vi.stubGlobal('fetch', stubWith({ outage_running: false }))
    renderApp('/outages')
    expect(await screen.findByText(/outage view not wired/i)).toBeInTheDocument()
  })

  test('feeds-off empty state points at the opt-in env var', async () => {
    vi.stubGlobal(
      'fetch',
      stubWith({
        outage_running: true,
        feeds_enabled: false,
        scope_resolution: true,
        events: [],
        vantage_events: [],
        coverage_notes: [
          'external feeds are disabled (PROBECTL_OUTAGE_FEEDS_ENABLED) — the view shows only your own vantage detections',
        ],
      }),
    )
    renderApp('/outages')
    expect(await screen.findByText(/no outage signals/i)).toBeInTheDocument()
    expect(screen.getAllByText(/PROBECTL_OUTAGE_FEEDS_ENABLED/).length).toBeGreaterThan(0)
  })

  test('a11y: the outages page passes the axe baseline', async () => {
    vi.stubGlobal('fetch', stubWith(fixture()))
    const { container } = renderApp('/outages')
    await screen.findByRole('table', { name: /external outage events/i })
    const results = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } },
    })
    expect(results.violations).toEqual([])
  })
})
