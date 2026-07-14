import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { describe, expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AppRoutes } from '../routes/AppRoutes'
import { serializePivotContext } from '../routes/pivotContext'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const groundedAnswer = {
  id: 'answer-explain',
  tenant: 'server-scoped-tenant',
  question: 'Explain this view',
  root_cause: 'The routing change is the strongest supported cause.',
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
  findings: [
    {
      statement: 'The route changed inside the selected window.',
      citations: [{ evidence_id: 'E-route' }],
    },
  ],
  evidence: [
    {
      id: 'E-route',
      domain: 'events',
      plane: 'bgp',
      title: 'route changed',
      occurred_at: '2026-07-14T10:03:00Z',
      fields: { id: 'route-change-1' },
    },
  ],
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="route-location">{`${location.pathname}${location.search}`}</output>
}

function renderAt(path: string) {
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
        <LocationProbe />
      </MemoryRouter>
    </Providers>,
  )
}

function stubExplain(response: unknown = groundedAnswer) {
  const fallback = defaultFetch()
  const asks: Array<Record<string, unknown>> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === '/v1/ai/ask' && init?.method === 'POST') {
        asks.push(JSON.parse(String(init.body)) as Record<string, unknown>)
        return jsonResponse(response)
      }
      return fallback(input, init)
    }),
  )
  return asks
}

describe('Explain this view', () => {
  test.each([
    ['/incidents', 'Incidents'],
    ['/path', 'Path'],
    ['/topology', 'Topology'],
    ['/planes/bgp', 'BGP'],
    ['/planes/flow', 'Flow'],
    ['/planes/device', 'Device'],
    ['/planes/ebpf', 'eBPF'],
  ])('%s exposes the same in-place explanation action', async (path) => {
    stubExplain()
    renderAt(path)
    expect(await screen.findByRole('button', { name: 'Explain this view' })).toBeInTheDocument()
  })

  test('sends the current X3 context without resetting the view or selecting a tenant', async () => {
    const asks = stubExplain()
    const context = serializePivotContext(
      {
        from: '2026-07-14T10:00:00Z',
        to: '2026-07-14T10:05:00Z',
        filters: { topo_kind: 'service' },
        selection: { kind: 'entity', id: 'service:checkout' },
        expiresAt: '2099-01-01T00:00:00Z',
      },
      new Date('2026-07-14T10:00:00Z'),
    )
    const initial = `/topology?${context.toString()}`
    const { container } = renderAt(initial)

    const before = (await screen.findByTestId('route-location')).textContent
    await userEvent.click(await screen.findByRole('button', { name: 'Explain this view' }))
    const inspector = await screen.findByRole('region', { name: 'Explanation inspector' })

    expect(screen.getByTestId('route-location').textContent).toBe(before)
    expect(
      within(inspector).getByText(/routing change is the strongest supported cause/i),
    ).toBeInTheDocument()
    expect(asks).toHaveLength(1)
    expect(asks[0]).toMatchObject({
      range: {
        start: '2026-07-14T10:00:00.000Z',
        end: '2026-07-14T10:05:00.000Z',
      },
      subject: {
        surface: 'topology',
        node: 'service:checkout',
        filter_topo_kind: 'service',
      },
    })
    expect(JSON.stringify(asks[0]).toLowerCase()).not.toContain('tenant')

    await userEvent.click(within(inspector).getAllByRole('link', { name: 'E-route' })[0])
    expect(document.activeElement?.id).toBe('ev-E-route')
    expect(screen.getByTestId('route-location').textContent).toBe(before)
    expect(await axe(container)).toHaveNoViolations()
  })

  test('suppresses unresolved causal claims and names a consented external adapter from server state', async () => {
    const unresolvedHeadline = 'An uncited deployment caused the outage.'
    const unresolvedFinding = 'An invented peer corroborates the outage.'
    stubExplain({
      ...groundedAnswer,
      root_cause: unresolvedHeadline,
      root_cause_citations: [{ evidence_id: 'E-missing' }],
      root_cause_grounded: true,
      model: 'do-not-parse-this-as-local',
      reasoning: {
        adapter: 'openai:gpt-5.2',
        execution: 'external_adapter',
        egress_consent: 'granted',
      },
      findings: [
        groundedAnswer.findings[0],
        { statement: unresolvedFinding, citations: [{ evidence_id: 'E-cross-tenant' }] },
      ],
    })
    renderAt('/planes/flow')
    await userEvent.click(await screen.findByRole('button', { name: 'Explain this view' }))
    const inspector = await screen.findByRole('region', { name: 'Explanation inspector' })

    expect(within(inspector).queryByText(unresolvedHeadline)).not.toBeInTheDocument()
    expect(within(inspector).queryByText(unresolvedFinding)).not.toBeInTheDocument()
    expect(
      within(inspector).getByText(/insufficient evidence.*exact, authorized citations/i),
    ).toBeInTheDocument()
    const groundedFinding = within(inspector).getByText(/route changed inside the selected window/i)
    expect(
      within(groundedFinding.closest('li')!).getByRole('link', { name: 'E-route' }),
    ).toBeInTheDocument()
    expect(
      within(inspector).getByText(/2 unresolved causal claims suppressed/i),
    ).toBeInTheDocument()
    expect(
      within(inspector).getByText(/openai:gpt-5\.2 · external · tenant consent granted/i),
    ).toBeInTheDocument()
    expect(within(inspector).queryByText(/do-not-parse-this-as-local/i)).not.toBeInTheDocument()
  })

  test('drops copied tenant and evidence selectors before an AI subject is built', async () => {
    const asks = stubExplain()
    renderAt(
      '/topology?ctx_v=1&ctx_expires=2099-01-01T00%3A00%3A00.000Z&ctx_filter=tenant_id%3Aforeign&ctx_selected_kind=evidence&ctx_selected_id=foreign-evidence',
    )
    await userEvent.click(await screen.findByRole('button', { name: 'Explain this view' }))
    await screen.findByRole('region', { name: 'Explanation inspector' })
    await waitFor(() => expect(asks).toHaveLength(1))
    expect(JSON.stringify(asks[0]).toLowerCase()).not.toMatch(/tenant|foreign-evidence|evidence_id/)
  })
})
