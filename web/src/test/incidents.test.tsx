import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

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
    }) as unknown as typeof fetch,
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
})
