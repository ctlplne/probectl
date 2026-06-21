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
      plane: 'bgp',
      kind: 'bgp.possible_hijack',
      severity: 'critical',
      title: 'possible hijack of 192.0.2.0/24',
      target: '192.0.2.0/24',
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

describe('incidents timeline', () => {
  test('lists incidents and overlays network + BGP signals in one timeline', async () => {
    stubIncidents()
    renderApp('/incidents')

    await screen.findByRole('heading', { name: /incidents/i })
    // The incident appears in the list as a selectable button.
    await screen.findByRole('button', { name: /high loss to 192\.0\.2\.10/i })

    // The first incident is auto-selected; its unified timeline overlays both planes.
    const timeline = await screen.findByRole('list', { name: /incident timeline/i })
    expect(within(timeline).getByText('network')).toBeInTheDocument()
    expect(within(timeline).getByText('bgp')).toBeInTheDocument()
    expect(within(timeline).getByText(/possible hijack/i)).toBeInTheDocument()
  })

  test('shows an empty state when there are no incidents', async () => {
    stubIncidents([])
    renderApp('/incidents')
    expect(await screen.findByText(/no incidents/i)).toBeInTheDocument()
  })

  test('the incidents page has no axe violations', async () => {
    stubIncidents()
    const { container } = renderApp('/incidents')
    await screen.findByRole('list', { name: /incident timeline/i })
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  test('hands incident context to Ask and files an observe-only remediation proposal', async () => {
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
            confidence: 'high',
            model: 'builtin',
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
                fields: { target: '192.0.2.10' },
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
    await userEvent.click(await screen.findByRole('button', { name: /ask about this incident/i }))

    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    expect(screen.getByLabelText(/your question/i)).toHaveValue(
      'What caused incident inc-1: high loss to 192.0.2.10?',
    )

    await userEvent.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText(/most likely root cause/i)
    expect(askCalls[0]).toMatchObject({
      question: expect.stringContaining('incident inc-1'),
      subject: { incident_id: 'inc-1', target: '192.0.2.10' },
    })
    expect(JSON.stringify(askCalls[0])).not.toContain('tenant_id')

    await userEvent.click(await screen.findByRole('button', { name: /propose remediation/i }))
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
