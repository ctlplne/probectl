// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import type { Proposal } from '../api/remediation'

const incident = {
  id: 'inc-1',
  tenant_id: 't',
  status: 'open',
  severity: 'critical',
  title: 'high loss to 192.0.2.10',
  target: '192.0.2.10',
  prefix: '',
  started_at: '2026-01-01T00:00:00Z',
  last_seen_at: '2026-01-01T00:01:00Z',
  signal_count: 2,
  signals: [
    {
      plane: 'network',
      kind: 'alert.firing',
      severity: 'warning',
      title: 'high loss to 192.0.2.10',
      target: '192.0.2.10',
      occurred_at: '2026-01-01T00:00:00Z',
    },
    {
      id: '00000000-0000-4000-8000-000000000002',
      plane: 'bgp',
      kind: 'bgp.possible_hijack',
      severity: 'critical',
      title: 'possible hijack of 192.0.2.0/24',
      target: '192.0.2.0/24',
      attributes: {
        'correlation.state': 'grouped',
        'correlation.parent_incident_id': 'inc-1',
        'correlation.reason': 'within_window_and_shared_target_or_prefix',
        'correlation.match_confidence': '1.00',
        'correlation.confidence_scope': 'deterministic_match_not_root_cause_probability',
        'correlation.freshness_seconds': '60',
      },
      occurred_at: '2026-01-01T00:01:00Z',
    },
  ],
}

function stubIncidents(items: unknown[] = [incident]) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/v1/incidents')) return jsonResponse({ items })
      if (url.endsWith('/v1/incidents/inc-1')) return jsonResponse(incident)
      return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
    }),
  )
}

describe('unified incident room', () => {
  test('lists incidents and overlays network + BGP signals on one clock', async () => {
    stubIncidents()
    renderApp('/incidents')

    await screen.findByRole('heading', { name: /incidents/i })
    // The incident appears in the list as a selectable button.
    await screen.findByRole('button', { name: /high loss to 192\.0\.2\.10/i })

    // The first incident is auto-selected; its unified clock overlays both planes.
    const timeline = await screen.findByRole('list', {
      name: /incident evidence on one time axis/i,
    })
    expect(within(timeline).getByText('network')).toBeInTheDocument()
    expect(within(timeline).getByText('bgp')).toBeInTheDocument()
    // The hijack signal now appears twice by design: as a clock marker's
    // accessible name and as its evidence row.
    expect(screen.getAllByText(/possible hijack/i).length).toBeGreaterThan(0)
    expect(
      screen.getByText(/flow analytics evidence is missing.*coverage gap, not a healthy zero/i),
    ).toBeInTheDocument()
  })

  test('explains grouping and completes audited ungroup then reversal journey', async () => {
    const user = userEvent.setup()
    const base = defaultFetch()
    let active = false
    const override = {
      id: '00000000-0000-4000-8000-000000000099',
      tenant_id: 't',
      source_incident_id: 'inc-1',
      detached_incident_id: 'inc-2',
      source_signal_id: '00000000-0000-4000-8000-000000000002',
      plane: 'bgp',
      kind: 'bgp.possible_hijack',
      target: '192.0.2.0/24',
      prefix: '',
      reason: 'route change is independently actionable',
      active: true,
      created_by: 'operator@example.test',
      created_at: '2026-01-01T00:02:00Z',
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      const method = init?.method ?? 'GET'
      if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
      if (path === '/v1/incidents/inc-1' && method === 'GET') {
        return jsonResponse(active ? { ...incident, correlation_overrides: [override] } : incident)
      }
      if (path === '/v1/incidents/inc-1/correlation-overrides' && method === 'POST') {
        active = true
        return jsonResponse(
          { override, detached_incident: { ...incident, id: 'inc-2', signal_count: 1 } },
          201,
        )
      }
      if (
        path === `/v1/incidents/inc-1/correlation-overrides/${override.id}/reverse` &&
        method === 'POST'
      ) {
        active = false
        return jsonResponse({ ...override, active: false, reversed_at: '2026-01-01T00:03:00Z' })
      }
      return base(input, init)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderApp('/incidents', {
      me: { permissions: ['incident.read', 'incident.write', 'ai.query'] },
    })

    const routingTable = await screen.findByRole('table', {
      name: /BGP & routing incident evidence/i,
    })
    await user.click(within(routingTable).getByRole('button', { name: /possible hijack/i }))
    expect(await screen.findByRole('heading', { name: /grouping decision/i })).toBeInTheDocument()
    expect(screen.getByText('within_window_and_shared_target_or_prefix')).toBeInTheDocument()
    expect(screen.getByText(/deterministic_match_not_root_cause_probability/)).toBeInTheDocument()

    await user.type(
      screen.getByRole('textbox', { name: /why is this signal independently important/i }),
      'route change is independently actionable',
    )
    await user.click(screen.getByRole('button', { name: /ungroup into independent incident/i }))
    expect(await screen.findByText(/override .*ACTIVE/i)).toBeInTheDocument()
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        pathOf(input) === '/v1/incidents/inc-1/correlation-overrides' && init?.method === 'POST',
    )
    expect(JSON.parse(String((createCall?.[1] as RequestInit).body))).toEqual({
      signal_id: '00000000-0000-4000-8000-000000000002',
      reason: 'route change is independently actionable',
    })

    await user.type(
      screen.getByRole('textbox', { name: /why reverse this override/i }),
      'operator confirmed regrouping is safe',
    )
    await user.click(screen.getByRole('button', { name: /reverse grouping override/i }))
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`/correlation-overrides/${override.id}/reverse`),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  test('shows an empty state when there are no incidents', async () => {
    stubIncidents([])
    renderApp('/incidents')
    expect(await screen.findByText(/no incidents/i)).toBeInTheDocument()
  })

  test('failed resolve keeps the incident open and shows a danger toast', async () => {
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
        if (path === '/v1/incidents/inc-1' && method === 'GET') return jsonResponse(incident)
        if (path === '/v1/incidents/inc-1' && method === 'PATCH') {
          return jsonResponse(
            { error: { code: 'unavailable', message: 'incident store unavailable' } },
            500,
          )
        }
        if (path === '/v1/remediation/proposals') {
          return jsonResponse(
            { error: { code: 'not_found', message: 'feature not licensed' } },
            404,
          )
        }
        return base(input, init)
      }),
    )
    renderApp('/incidents')

    await screen.findByRole('list', { name: /incident evidence on one time axis/i })
    await userEvent.click(screen.getByRole('button', { name: /^resolve$/i }))

    expect(await screen.findByText(/resolve failed/i)).toBeInTheDocument()
    expect(screen.getByText(/incident store unavailable/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^resolve$/i })).toBeInTheDocument()
  })

  test('the incidents page has no axe violations', async () => {
    stubIncidents()
    const { container } = renderApp('/incidents')
    await screen.findByRole('list', { name: /incident evidence on one time axis/i })
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  test('runs cited RCA inline and files an observe-only remediation proposal', async () => {
    const base = defaultFetch()
    const askCalls: Array<Record<string, unknown>> = []
    const proposalCalls: Array<Record<string, string>> = []
    let proposals: Proposal[] = []

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, string>) : {}

        if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
        if (path === '/v1/incidents/inc-1') return jsonResponse(incident)
        if (path === '/v1/ai/ask' && method === 'POST') {
          askCalls.push(body)
          return jsonResponse({
            id: 'ans_1',
            tenant: 't',
            question: body.question,
            root_cause: 'Most likely root cause: possible hijack of 192.0.2.0/24.',
            root_cause_citations: [{ evidence_id: 'E1' }],
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
                statement: 'The BGP event is the strongest root-cause signal.',
                citations: [{ evidence_id: 'E1' }],
              },
            ],
            evidence: [
              {
                id: 'E1',
                domain: 'routing',
                plane: 'bgp',
                severity: 'critical',
                title: 'possible hijack of 192.0.2.0/24',
                summary: 'AS64500 originated a more-specific route.',
                ref: 'incident:inc-1',
                fields: { id: 'inc-1:1', target: '192.0.2.10' },
              },
            ],
          })
        }
        if (path === '/v1/remediation/proposals' && method === 'GET') {
          return jsonResponse({ items: proposals, approvals_enabled: false })
        }
        if (path === '/v1/remediation/proposals' && method === 'POST') {
          proposalCalls.push(body)
          const row: Proposal = {
            id: 'rem-incident',
            kind: body.kind,
            title: body.title,
            rationale: body.rationale,
            target: body.target,
            incident_id: body.incident_id,
            dry_run: { blast_radius: -1, note: 'review-only test proposal' },
            state: 'proposed',
            proposed_by: 'user:operator@probectl.test',
            created_at: '2026-01-01T00:02:00Z',
          }
          proposals = [row]
          return jsonResponse(row, 201)
        }
        return base(input, init)
      }),
    )

    renderApp('/incidents')
    await userEvent.click(
      await screen.findByRole('button', { name: /high loss to 192\.0\.2\.10/i }),
    )
    await userEvent.click(await screen.findByRole('button', { name: /explain this view/i }))

    const inlineRCA = await screen.findByRole('region', {
      name: /explanation inspector/i,
    })
    expect(within(inlineRCA).getByText(/most likely root cause/i)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /ask \(ai\)/i })).not.toBeInTheDocument()
    expect(askCalls[0]).toMatchObject({
      question: expect.stringContaining('incident inc-1'),
      subject: { surface: 'incident', incident_id: 'inc-1', target: '192.0.2.10' },
    })
    expect(JSON.stringify(askCalls[0])).not.toContain('tenant_id')

    await userEvent.click(screen.getByRole('button', { name: /propose remediation/i }))
    expect(proposalCalls).toHaveLength(1)
    expect(proposalCalls[0]).toMatchObject({
      kind: 'open_ticket',
      incident_id: 'inc-1',
      target: '192.0.2.10',
    })
    expect(JSON.stringify(proposalCalls[0])).not.toContain('tenant_id')
    expect(JSON.stringify(proposalCalls[0])).toMatch(/human review only/i)
    expect(JSON.stringify(proposalCalls[0])).toMatch(/must not execute/i)
    expect(JSON.stringify(proposalCalls[0])).toMatch(/E1/)

    await userEvent.click(screen.getByRole('link', { name: /admin & settings/i }))
    expect(await screen.findByText(/ai remediation proposals/i)).toBeInTheDocument()
    expect(screen.getByText(/review rca/i)).toBeInTheDocument()
    expect(screen.getByText(/advisory-only/i)).toBeInTheDocument()
  })
})
