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
  ],
  evidence: [
    {
      id: 'E1', domain: 'entities', plane: 'bgp', severity: 'critical',
      title: 'possible hijack 192.0.2.0/24', summary: 'AS64500 originated a more-specific',
      ref: 'incident:inc-1', occurred_at: '2026-01-01T00:00:00Z',
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

describe('AI assistant surface', () => {
  test('asks a question and renders a cited, trust-cued answer; submits feedback', async () => {
    const calls = stubAI()
    renderApp('/ask')

    await screen.findByRole('heading', { name: /ask \(ai\)/i })

    fireEvent.change(screen.getByLabelText(/your question/i), {
      target: { value: 'why is 192.0.2.0/24 unreachable?' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))

    // Root cause + confidence trust cue + provenance. The hijack text appears in
    // both the root cause and its cited evidence, proving the answer is grounded.
    await screen.findByText(/most likely root cause:/i)
    expect(screen.getAllByText(/possible hijack 192\.0\.2\.0\/24/i).length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/high confidence/i)).toBeTruthy()
    expect(screen.getByText(/synthesized by builtin/i)).toBeTruthy()

    // The finding's citation chip links to the evidence anchor (citation integrity, visible).
    const chip = screen.getByRole('link', { name: 'E1' })
    expect(chip.getAttribute('href')).toBe('#ev-E1')

    // Feedback round-trips.
    fireEvent.click(screen.getByRole('button', { name: /yes, helpful/i }))
    await screen.findByText(/thanks/i)
    expect(calls.some((c) => c.url.endsWith('/v1/ai/feedback'))).toBe(true)
  })

  test('the surface has no a11y violations', async () => {
    stubAI()
    const { container } = renderApp('/ask')
    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    expect(await axe(container)).toHaveNoViolations()
  })
})
