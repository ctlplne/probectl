// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

const tenantID = '00000000-0000-0000-0000-000000000001'
const incident = {
  id: 'inc-journal',
  tenant_id: tenantID,
  status: 'open',
  severity: 'critical',
  title: 'checkout route investigation',
  target: 'checkout.probectl.test',
  prefix: '192.0.2.0/24',
  started_at: '2026-07-14T12:00:00Z',
  last_seen_at: '2026-07-14T12:05:00Z',
  signal_count: 1,
  signals: [
    {
      plane: 'bgp',
      kind: 'bgp.origin_change',
      severity: 'critical',
      title: 'unexpected route origin',
      summary: 'AS64550 originated the checkout prefix.',
      prefix: '192.0.2.0/24',
      occurred_at: '2026-07-14T12:01:00Z',
    },
  ],
}

const answer = {
  id: 'answer-journal',
  tenant: tenantID,
  question: 'What caused incident inc-journal?',
  root_cause: 'The route origin changed before checkout failed.',
  root_cause_citations: [{ evidence_id: 'E-route' }],
  root_cause_grounded: true,
  confidence: 'high',
  model: 'builtin',
  reasoning: {
    adapter: 'builtin',
    execution: 'builtin_local',
    egress_consent: 'not_required',
  },
  insufficient_evidence: false,
  findings: [],
  evidence: [
    {
      id: 'E-route',
      domain: 'events',
      plane: 'bgp',
      severity: 'critical',
      title: 'unexpected route origin',
      summary: 'AS64550 originated the checkout prefix.',
      occurred_at: '2026-07-14T12:01:00Z',
      ref: 'incident:inc-journal',
      fields: { id: 'inc-journal:0', prefix: '192.0.2.0/24' },
    },
  ],
}

const journalOperator = {
  me: { permissions: ['incident.read', 'incident.write', 'ai.query'] },
}

function incidentJournalFetch(
  journalHandler: (method: string, init?: RequestInit) => Response | Promise<Response>,
) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
    if (path === '/v1/incidents/inc-journal') return jsonResponse(incident)
    if (path === '/v1/incidents/inc-journal/changes') return jsonResponse({ items: [] })
    if (path === '/v1/incidents/inc-journal/journal') return journalHandler(method, init)
    if (path === '/v1/remediation/proposals') {
      return jsonResponse({ items: [], approvals_enabled: false })
    }
    if (path === '/v1/ai/ask' && method === 'POST') return jsonResponse(answer)
    if (path === '/v1/incidents/inc-journal/shares' && method === 'POST') {
      const request = JSON.parse(String(init?.body)) as { context: Record<string, unknown> }
      return jsonResponse(
        {
          id: 'share_0123456789abcdef0123456789abcdef',
          incident: { ...incident, tenant_id: '' },
          context: request.context,
          answer: { ...answer, tenant: '' },
          created_at: '2026-07-14T12:06:00Z',
          expires_at: '2026-07-21T12:06:00Z',
        },
        201,
      )
    }
    return base(input, init)
  })
}

describe('tenant-local incident investigation journal', () => {
  test('renders the corrected Spanish investigation copy from the shipped catalog', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      incidentJournalFetch(() => jsonResponse({ items: [], truncated: false, limit: 200 })),
    )

    renderApp('/incidents', { locale: 'es', ...journalOperator })

    expect(await screen.findByText('Diario de investigación')).toBeInTheDocument()
    expect(screen.getByText(/no puede ejecutar herramientas ni remediación/)).toBeInTheDocument()
    expect(screen.getByLabelText('Nota de investigación')).toHaveAttribute(
      'placeholder',
      'Registra una hipótesis, observación o conclusión...',
    )
    expect(await screen.findByText('Aún no hay entradas')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Tipo de entrada'), 'checkpoint')
    expect(screen.getByLabelText('Nota de investigación')).toHaveAttribute(
      'placeholder',
      'Explica qué confirma esta evidencia citada...',
    )
    expect(
      screen.getByText(/El punto de control referenciará un elemento exacto/),
    ).toBeInTheDocument()
  })

  test('shows the honest empty state and appends inert human text', async () => {
    const user = userEvent.setup()
    const entries: Record<string, unknown>[] = []
    let appendedBody: Record<string, unknown> | undefined
    vi.stubGlobal(
      'fetch',
      incidentJournalFetch((method, init) => {
        if (method === 'POST') {
          appendedBody = JSON.parse(String(init?.body)) as Record<string, unknown>
          const entry = {
            id: 'journal_0123456789abcdef0123456789abcdef',
            incident_id: incident.id,
            kind: 'note',
            format: 'plain_text',
            body: appendedBody.body,
            created_by: 'u_test',
            created_at: '2026-07-14T12:06:00Z',
            expires_at: '2026-10-12T12:06:00Z',
          }
          entries.push(entry)
          return jsonResponse(entry, 201)
        }
        return jsonResponse({ items: entries, truncated: false, limit: 200 })
      }),
    )

    renderApp('/incidents', journalOperator)
    expect(await screen.findByText('No journal entries yet')).toBeInTheDocument()
    await user.type(
      screen.getByLabelText('Investigation note'),
      '<script>tool.call("reboot")</script> is an inert hypothesis.',
    )
    await user.click(screen.getByRole('button', { name: 'Append to journal' }))

    await waitFor(() => expect(appendedBody).toBeDefined())
    expect(appendedBody).toEqual({
      kind: 'note',
      body: '<script>tool.call("reboot")</script> is an inert hypothesis.',
    })
    expect(JSON.stringify(appendedBody)).not.toContain(tenantID)
    expect(await screen.findByText(/tool\.call\("reboot"\).*inert hypothesis/)).toBeInTheDocument()
  })

  test('creates a cited snapshot before appending one exact checkpoint', async () => {
    const user = userEvent.setup()
    let checkpointBody: Record<string, unknown> | undefined
    vi.stubGlobal(
      'fetch',
      incidentJournalFetch((method, init) => {
        if (method === 'POST') {
          checkpointBody = JSON.parse(String(init?.body)) as Record<string, unknown>
          return jsonResponse(
            {
              id: 'journal_abcdef0123456789abcdef0123456789',
              incident_id: incident.id,
              kind: 'checkpoint',
              format: 'plain_text',
              body: checkpointBody.body,
              citation: {
                ...(checkpointBody.citation as Record<string, unknown>),
                state: 'available',
                plane: 'bgp',
                title: 'unexpected route origin',
              },
              created_by: 'u_test',
              created_at: '2026-07-14T12:07:00Z',
              expires_at: '2026-10-12T12:07:00Z',
            },
            201,
          )
        }
        return jsonResponse({ items: [], truncated: false, limit: 200 })
      }),
    )

    renderApp('/incidents', journalOperator)
    await user.click(await screen.findByRole('button', { name: 'Explain this view' }))
    await user.click(await screen.findByRole('button', { name: 'Copy cited share link' }))
    await user.selectOptions(screen.getByLabelText('Entry type'), 'checkpoint')
    expect(await screen.findByText('Ready to cite: unexpected route origin')).toBeInTheDocument()
    await user.type(
      screen.getByLabelText('Investigation note'),
      'Route origin change confirmed before impact.',
    )
    await user.click(screen.getByRole('button', { name: 'Append to journal' }))

    await waitFor(() => expect(checkpointBody).toBeDefined())
    expect(checkpointBody).toEqual({
      kind: 'checkpoint',
      body: 'Route origin change confirmed before impact.',
      citation: {
        share_id: 'share_0123456789abcdef0123456789abcdef',
        evidence_id: 'E-route',
      },
    })
    expect(JSON.stringify(checkpointBody)).not.toContain(tenantID)
  })

  test('renders truncated and revoked-citation states without implying complete evidence', async () => {
    vi.stubGlobal(
      'fetch',
      incidentJournalFetch(() =>
        jsonResponse({
          items: [
            {
              id: 'journal_fedcba9876543210fedcba9876543210',
              incident_id: incident.id,
              kind: 'checkpoint',
              format: 'plain_text',
              body: 'Earlier evidence checkpoint',
              citation: {
                share_id: 'share_expired',
                evidence_id: 'E-expired',
                state: 'unavailable',
              },
              created_by: 'u_test',
              created_at: '2026-07-14T12:07:00Z',
              expires_at: '2026-10-12T12:07:00Z',
            },
          ],
          truncated: true,
          limit: 200,
        }),
      ),
    )
    renderApp('/incidents', journalOperator)
    expect(await screen.findByText(/Showing the first 200 entries/)).toBeInTheDocument()
    expect(
      screen.getByText(/cited evidence is no longer authorized or available/i),
    ).toBeInTheDocument()
  })

  test('renders an explicit journal load error', async () => {
    vi.stubGlobal(
      'fetch',
      incidentJournalFetch(() => jsonResponse({ error: { code: 'internal' } }, 500)),
    )
    renderApp('/incidents', journalOperator)
    expect(
      await screen.findByText('Journal unavailable', undefined, { timeout: 4000 }),
    ).toBeInTheDocument()
    expect(screen.getByText('The investigation journal could not be loaded.')).toBeInTheDocument()
  })
})
