// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '../renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from '../fetchStub'
import {
  JourneyRecorder,
  assertRequestsUseSessionTenant,
  type MeasuredRequest,
} from './measurement'

const incident = {
  id: 'inc-room',
  tenant_id: '00000000-0000-0000-0000-000000000001',
  status: 'open',
  severity: 'critical',
  title: 'checkout failures after edge route change',
  target: 'checkout.probectl.test',
  prefix: '192.0.2.0/24',
  started_at: '2026-07-14T12:00:00Z',
  last_seen_at: '2026-07-14T12:05:00Z',
  signal_count: 507,
  signals_truncated: true,
  signals_limit: 500,
  signals: [
    {
      plane: 'network',
      kind: 'http.failure',
      severity: 'critical',
      title: 'checkout synthetic failures',
      summary: 'All external checkout probes began failing.',
      target: 'checkout.probectl.test',
      occurred_at: '2026-07-14T12:00:00Z',
    },
    {
      plane: 'bgp',
      kind: 'bgp.more_specific',
      severity: 'critical',
      title: 'unexpected more-specific route',
      summary: 'AS64550 announced 192.0.2.0/25 immediately before impact.',
      prefix: '192.0.2.0/24',
      occurred_at: '2026-07-14T12:01:00Z',
    },
    {
      plane: 'flow',
      kind: 'flow.path_shift',
      severity: 'warning',
      title: 'traffic shifted to transit-b',
      summary: 'Egress traffic shifted from transit-a to transit-b.',
      target: 'edge-r1',
      occurred_at: '2026-07-14T12:02:00Z',
    },
    {
      plane: 'device',
      kind: 'interface.errors',
      severity: 'warning',
      title: 'edge-r1 interface errors',
      summary: 'Interface xe-0/0/0 error rate increased.',
      target: 'edge-r1',
      attributes: { device: 'edge-r1' },
      occurred_at: '2026-07-14T12:03:00Z',
    },
    {
      plane: 'ebpf',
      kind: 'tcp.retransmits',
      severity: 'warning',
      title: 'checkout TCP retransmits',
      summary: 'Checkout pods saw retransmits toward the edge.',
      target: 'checkout-api',
      attributes: { service: 'checkout-api', node: 'worker-7' },
      occurred_at: '2026-07-14T12:04:00Z',
    },
  ],
}

describe('J2 unified incident room', () => {
  test('reaches a cited likely cause without typing or leaving the incident', async () => {
    const user = userEvent.setup()
    const requests: MeasuredRequest[] = []
    const base = defaultFetch()

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        assertNoDoublePrefix(input)
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        requests.push({
          url: String(input),
          method,
          headers: Object.fromEntries(new Headers(init?.headers).entries()),
          body: init?.body,
        })

        if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
        if (path === '/v1/incidents/inc-room') return jsonResponse(incident)
        if (path === '/v1/incidents/inc-room/changes') {
          return jsonResponse({
            items: [
              {
                event: {
                  id: 'change-edge-route',
                  source: 'git',
                  kind: 'routing.policy',
                  title: 'edge export policy changed',
                  summary: 'Deployment changed the transit-b export policy.',
                  target: 'edge-r1',
                  occurred_at: '2026-07-14T11:59:30Z',
                },
                score: 0.94,
                reason: 'same edge and 30 seconds before the first failed probe',
              },
            ],
          })
        }
        if (path === '/v1/remediation/proposals' && method === 'GET') {
          return jsonResponse({ items: [], approvals_enabled: false })
        }
        if (path === '/v1/ai/ask' && method === 'POST') {
          return jsonResponse({
            id: 'answer-room',
            tenant: incident.tenant_id,
            question: 'What caused incident inc-room?',
            root_cause:
              'The edge export-policy change likely enabled the unexpected more-specific route.',
            root_cause_citations: [{ evidence_id: 'E-bgp' }],
            root_cause_grounded: true,
            confidence: 'high',
            model: 'builtin',
            reasoning: {
              adapter: 'builtin',
              execution: 'builtin_local',
              egress_consent: 'not_required',
            },
            insufficient_evidence: false,
            findings: [
              {
                statement: 'The route appeared before all five planes showed impact.',
                citations: [{ evidence_id: 'E-bgp' }],
              },
            ],
            evidence: [
              {
                id: 'E-bgp',
                domain: 'routing',
                plane: 'bgp',
                severity: 'critical',
                title: 'unexpected more-specific route',
                summary: 'AS64550 announced 192.0.2.0/25 immediately before impact.',
                occurred_at: '2026-07-14T12:01:00Z',
                ref: 'incident:inc-room',
                fields: { id: 'inc-room:1', prefix: '192.0.2.0/24' },
              },
            ],
          })
        }
        return base(input, init)
      }),
    )

    renderApp('/incidents')

    const room = await screen.findByRole('region', {
      name: /unified five-plane incident room/i,
    })
    for (const plane of [
      /synthetic & path/i,
      /bgp & routing/i,
      /flow analytics/i,
      /device telemetry/i,
      /ebpf host & l7/i,
    ]) {
      expect(within(room).getByRole('region', { name: plane })).toBeInTheDocument()
    }
    expect(within(room).getByText(/showing 5 of 507 signals/i)).toBeInTheDocument()
    // Appears twice by design: clock timeline marker + candidate-change row.
    expect(within(room).getAllByText(/edge export policy changed/i).length).toBeGreaterThan(0)
    expect(within(room).getByText('checkout-api')).toBeInTheDocument()
    expect(within(room).getByText(/nothing runs automatically/i)).toBeInTheDocument()

    // Scoped to the plane region: the clock timeline carries a marker with the
    // same accessible name, and this step exercises the evidence ROW.
    const flowPlane = within(room).getByRole('region', { name: /flow analytics/i })
    const flowRow = within(flowPlane).getByRole('button', {
      name: /traffic shifted to transit-b/i,
    })
    await user.click(flowRow)
    const inspector = within(room).getByLabelText(/incident evidence inspector/i)
    expect(within(inspector).getByText(/egress traffic shifted/i)).toBeInTheDocument()

    await user.click(within(room).getByRole('button', { name: /explain this view/i }))
    const inlineRCA = await within(room).findByRole('region', {
      name: /explanation inspector/i,
    })
    expect(within(inlineRCA).getByText(/export-policy change likely/i)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /ask \(ai\)/i })).not.toBeInTheDocument()

    await user.click(within(inlineRCA).getAllByRole('link', { name: 'E-bgp' })[0])
    const bgpPlane = within(room).getByRole('region', { name: /bgp & routing/i })
    const bgpRow = within(bgpPlane).getByRole('button', {
      name: /unexpected more-specific route/i,
    })
    await waitFor(() => expect(bgpRow).toHaveAttribute('aria-pressed', 'true'))
    expect(flowRow).toHaveAttribute('aria-pressed', 'false')
    expect(within(inspector).getByText(/AS64550 announced/i)).toBeInTheDocument()
    expect(document.activeElement).toHaveAttribute('id', 'ev-E-bgp')

    const clock = within(room).getByRole('list', { name: /one time axis/i })
    const selectedClockMarker = within(clock).getByText('bgp').closest('button')
    expect(selectedClockMarker).toHaveAttribute('aria-pressed', 'true')

    assertRequestsUseSessionTenant(requests)
    const measurement = new JourneyRecorder('J2', 'incident to cited RCA to share')
      .pointer(1)
      .activeTimeProxy({
        min_ms: 15_000,
        max_ms: 45_000,
        basis: 'auto-selected firing incident plus one inline likely-cause action',
      })
      .incomplete('cited RCA is complete; stable incident share ships in X6')
      .snapshot()

    expect(measurement.pointer_interactions).toBeLessThanOrEqual(3)
    expect(measurement.typed_characters).toBe(0)
    expect(measurement.context_breaks).toBe(0)
  })
})
