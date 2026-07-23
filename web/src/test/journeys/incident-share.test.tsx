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

const tenantID = '00000000-0000-0000-0000-000000000001'
const incident = {
  id: 'inc-share',
  tenant_id: tenantID,
  status: 'open',
  severity: 'critical',
  title: 'checkout failures after route change',
  target: 'checkout.probectl.test',
  prefix: '192.0.2.0/24',
  started_at: '2026-07-14T12:00:00Z',
  last_seen_at: '2026-07-14T12:05:00Z',
  signal_count: 2,
  signals: [
    {
      plane: 'flow',
      kind: 'flow.path_shift',
      severity: 'warning',
      title: 'traffic shifted to transit-b',
      summary: 'Egress traffic moved away from the expected transit.',
      target: 'edge-r1',
      occurred_at: '2026-07-14T12:02:00Z',
    },
    {
      plane: 'bgp',
      kind: 'bgp.more_specific',
      severity: 'critical',
      title: 'unexpected more-specific route',
      summary: 'AS64550 announced a more-specific route immediately before impact.',
      prefix: '192.0.2.0/24',
      occurred_at: '2026-07-14T12:01:00Z',
    },
  ],
}

const answer = {
  id: 'answer-share',
  tenant: tenantID,
  question: 'What caused incident inc-share?',
  root_cause: 'The unexpected more-specific route likely shifted checkout traffic.',
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
      statement: 'The route appeared before the observed path shift.',
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
      summary: 'AS64550 announced a more-specific route immediately before impact.',
      occurred_at: '2026-07-14T12:01:00Z',
      ref: 'incident:inc-share',
      fields: { id: 'inc-share:1', prefix: '192.0.2.0/24' },
    },
  ],
}

describe('J2 cited incident sharing', () => {
  test('copies and replays one stable tenant-safe snapshot in four clicks and no typing', async () => {
    const user = userEvent.setup()
    const requests: MeasuredRequest[] = []
    const clipboardWrite = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: clipboardWrite },
    })
    const base = defaultFetch()
    let artifact: Record<string, unknown> | undefined

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
        if (path === '/v1/incidents/inc-share') return jsonResponse(incident)
        if (path === '/v1/incidents/inc-share/changes') return jsonResponse({ items: [] })
        if (path === '/v1/remediation/proposals') {
          return jsonResponse({ items: [], approvals_enabled: false })
        }
        if (path === '/v1/ai/ask' && method === 'POST') return jsonResponse(answer)
        if (path === '/v1/incidents/inc-share/shares' && method === 'POST') {
          const request = JSON.parse(String(init?.body)) as {
            context: Record<string, unknown>
          }
          artifact = {
            id: 'share_0123456789abcdef',
            incident: { ...incident, tenant_id: '' },
            context: request.context,
            answer: { ...answer, tenant: '' },
            created_at: '2026-07-14T12:06:00Z',
            expires_at: '2026-07-21T12:06:00Z',
          }
          return jsonResponse(artifact, 201)
        }
        if (path === '/v1/incident-shares/share_0123456789abcdef' && method === 'GET') {
          return artifact ? jsonResponse(artifact) : jsonResponse({ error: 'not found' }, 404)
        }
        return base(input, init)
      }),
    )

    const first = renderApp('/incidents?incident_status=open')
    const room = await screen.findByRole('region', {
      name: /unified five-plane incident room/i,
    })

    // Scoped: the clock timeline carries a marker with the same accessible
    // name; this step exercises the evidence ROW inside the flow plane region.
    const flowPlane = within(room).getByRole('region', { name: /flow analytics/i })
    await user.click(
      within(flowPlane).getByRole('button', { name: /traffic shifted to transit-b/i }),
    )
    await user.click(within(room).getByRole('button', { name: /explain this view/i }))
    const explanation = await within(room).findByRole('region', {
      name: /explanation inspector/i,
    })
    await user.click(within(explanation).getAllByRole('link', { name: 'E-bgp' })[0])
    await user.click(await within(room).findByRole('button', { name: /copy cited share link/i }))

    await waitFor(() => expect(clipboardWrite).toHaveBeenCalledTimes(1))
    const copied = String(clipboardWrite.mock.calls[0][0])
    const copiedURL = new URL(copied)
    expect(copiedURL.pathname).toBe('/incidents')
    expect(Array.from(copiedURL.searchParams.keys())).toEqual(['share'])
    expect(copied).not.toContain(tenantID)
    expect(copied).not.toMatch(/token|secret|password/i)

    const create = requests.find(
      (request) =>
        new URL(request.url, 'https://probectl.invalid').pathname ===
          '/v1/incidents/inc-share/shares' && request.method === 'POST',
    )
    expect(create).toBeDefined()
    const createBody = JSON.parse(String(create?.body)) as {
      context: {
        from: string
        to: string
        filters: Record<string, string>
        selection: { kind: string; id: string }
      }
    }
    expect(createBody.context).toEqual({
      from: new Date(incident.started_at).toISOString(),
      to: new Date(incident.last_seen_at).toISOString(),
      filters: { incident_status: 'open' },
      selection: { kind: 'evidence', id: 'inc-share:1' },
    })
    expect(JSON.stringify(createBody)).not.toContain(tenantID)

    first.unmount()
    const replayRequestStart = requests.length
    renderApp(`${copiedURL.pathname}${copiedURL.search}`)
    const replay = await screen.findByRole('region', {
      name: /unified five-plane incident room/i,
    })
    expect(within(replay).getByText(/fixed, tenant-authorized snapshot/i)).toBeInTheDocument()
    expect(within(replay).getByText('incident_status=open')).toBeInTheDocument()
    expect(within(replay).getByText('inc-share:1')).toBeInTheDocument()
    expect(within(replay).getByText(/more-specific route likely shifted/i)).toBeInTheDocument()
    expect(within(replay).getByText(/built-in.*local\/air-gapped/i)).toBeInTheDocument()
    expect(within(replay).getAllByRole('link', { name: 'E-bgp' }).length).toBeGreaterThan(0)
    // Scoped to the plane region — the clock marker shares this accessible
    // name and, by design, the same pressed selection state.
    const replayBgpPlane = within(replay).getByRole('region', { name: /bgp & routing/i })
    expect(
      within(replayBgpPlane).getByRole('button', { name: /unexpected more-specific route/i }),
    ).toHaveAttribute('aria-pressed', 'true')
    expect(within(replay).queryByRole('button', { name: /resolve/i })).not.toBeInTheDocument()
    const replayPaths = requests
      .slice(replayRequestStart)
      .map((request) => new URL(request.url, 'https://probectl.invalid').pathname)
    expect(replayPaths).toContain('/v1/incident-shares/share_0123456789abcdef')
    expect(replayPaths).not.toContain('/v1/incidents')
    expect(replayPaths).not.toContain('/v1/incidents/inc-share')
    expect(replayPaths).not.toContain('/v1/incidents/inc-share/changes')
    expect(replayPaths).not.toContain('/v1/remediation/proposals')

    assertRequestsUseSessionTenant(requests)
    const measurement = new JourneyRecorder('J2', 'incident to cited RCA to share')
      .pointer(4)
      .activeTimeProxy({
        min_ms: 15_000,
        max_ms: 45_000,
        basis: 'select evidence, run inline RCA, follow its citation, and copy one stable link',
      })
      .complete(
        'four pointer interactions and zero typed characters',
        'copied URL contains only a random share artifact ID',
        'authenticated replay restores absolute time, filters, selection, citations, and reasoning provenance',
      )
      .snapshot()

    expect(measurement.pointer_interactions).toBeLessThanOrEqual(5)
    expect(measurement.typed_characters).toBe(0)
    expect(measurement.context_breaks).toBe(0)
    expect(measurement.outcome.status).toBe('complete')
  })
})
