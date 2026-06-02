import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const answer = {
  id: 'ans_1',
  tenant: 't',
  question: 'why is 192.0.2.0/24 unreachable?',
  root_cause: 'Most likely root cause: "possible hijack 192.0.2.0/24" (critical).',
  confidence: 'high',
  model: 'builtin',
  insufficient_evidence: false,
  findings: [
    { statement: 'The highest cause-likelihood signal is the routing event.', citations: [{ evidence_id: 'E1' }] },
    { statement: 'Corroborated by elevated latency.', citations: [{ evidence_id: 'E2' }] },
  ],
  evidence: [
    {
      id: 'E1', domain: 'entities', plane: 'bgp', severity: 'critical',
      title: 'possible hijack 192.0.2.0/24', summary: 'AS64500 originated a more-specific',
      ref: 'incident:inc-1', occurred_at: '2026-01-01T00:01:00Z',
      fields: { kind: 'incident', severity: 'critical' },
    },
    {
      id: 'E2', domain: 'metrics', plane: 'metrics', severity: 'warning',
      title: 'p95 latency elevated', summary: '950ms', occurred_at: '2026-01-01T00:00:00Z',
    },
  ],
}

function stubAI() {
  const calls: Array<{ url: string; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const body = init?.body ? JSON.parse(String(init.body)) : undefined
      calls.push({ url, body })
      if (url.endsWith('/v1/ai/ask')) return jsonResponse(answer)
      if (url.endsWith('/v1/ai/feedback')) return new Response(null, { status: 204 })
      return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
    }) as unknown as typeof fetch,
  )
  return calls
}

async function askAndRender() {
  const calls = stubAI()
  renderApp('/ask')
  await screen.findByRole('heading', { name: /ask \(ai\)/i })
  fireEvent.change(screen.getByLabelText(/your question/i), {
    target: { value: 'why is 192.0.2.0/24 unreachable?' },
  })
  fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))
  await screen.findByText(/most likely root cause:/i)
  return calls
}

describe('AI assistant surface', () => {
  test('renders a cited, trust-cued answer and submits feedback', async () => {
    await askAndRender()

    // The hijack text appears in both the root cause and its cited evidence.
    expect(screen.getAllByText(/possible hijack 192\.0\.2\.0\/24/i).length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/high confidence/i)).toBeTruthy()
    // Trust summary spells out the grounding breadth.
    expect(screen.getByText(/grounded in 2 signal\(s\) across 2 plane\(s\): bgp, metrics/i)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /yes, helpful/i }))
    await screen.findByText(/thanks/i)
  })

  test('groups evidence by plane, links citations to evidence, and shows backlinks', async () => {
    await askAndRender()

    // Evidence is grouped under per-plane subheadings.
    expect(screen.getByRole('heading', { level: 3, name: /bgp/i })).toBeTruthy()
    expect(screen.getByRole('heading', { level: 3, name: /metrics/i })).toBeTruthy()

    // Each evidence card backlinks to the findings that cite it.
    expect(screen.getByText(/cited in finding 1/i)).toBeTruthy()
    expect(screen.getByText(/cited in finding 2/i)).toBeTruthy()

    // Clicking a citation moves focus to the exact cited signal.
    fireEvent.click(screen.getByRole('link', { name: 'E1' }))
    expect(document.activeElement?.id).toBe('ev-E1')

    // Raw signal detail is available for drill-down.
    expect(screen.getByText(/raw signal/i)).toBeTruthy()
  })

  test('feedback carries an optional note', async () => {
    const calls = await askAndRender()

    fireEvent.change(screen.getByLabelText(/add a note/i), {
      target: { value: 'the real cause was the upstream peer' },
    })
    fireEvent.click(screen.getByRole('button', { name: /no, not helpful/i }))
    await screen.findByText(/thanks/i)

    const fb = calls.find((c) => c.url.endsWith('/v1/ai/feedback'))
    expect(fb?.body).toMatchObject({ rating: 'down', comment: 'the real cause was the upstream peer' })
  })

  test('the answered surface has no a11y violations', async () => {
    stubAI()
    const { container } = renderApp('/ask')
    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    fireEvent.change(screen.getByLabelText(/your question/i), { target: { value: 'what broke?' } })
    fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText(/most likely root cause:/i)
    expect(await axe(container)).toHaveNoViolations()
  })
})
