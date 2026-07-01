import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { axe } from 'jest-axe'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const answer = {
  id: 'ans_1',
  tenant: 't',
  question: 'why is 192.0.2.0/24 unreachable?',
  root_cause: 'Most likely root cause: "possible hijack 192.0.2.0/24" (critical).',
  root_cause_citations: [{ evidence_id: 'E1' }],
  root_cause_grounded: true,
  degraded: false,
  confidence: 'high',
  model: 'builtin',
  insufficient_evidence: false,
  findings: [
    {
      statement: 'The highest cause-likelihood signal is the routing event.',
      citations: [{ evidence_id: 'E1' }],
    },
    { statement: 'Corroborated by elevated latency.', citations: [{ evidence_id: 'E2' }] },
  ],
  evidence: [
    {
      id: 'E1',
      domain: 'entities',
      plane: 'bgp',
      severity: 'critical',
      title: 'possible hijack 192.0.2.0/24',
      summary: 'AS64500 originated a more-specific',
      ref: 'incident:inc-1',
      occurred_at: '2026-01-01T00:01:00Z',
      fields: { kind: 'incident', severity: 'critical' },
    },
    {
      id: 'E2',
      domain: 'metrics',
      plane: 'metrics',
      severity: 'warning',
      title: 'p95 latency elevated',
      summary: '950ms',
      occurred_at: '2026-01-01T00:00:00Z',
    },
  ],
}

function stubAI(response = answer) {
  const calls: Array<{ url: string; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const body = init?.body ? JSON.parse(String(init.body)) : undefined
      calls.push({ url, body })
      if (url.endsWith('/v1/ai/ask')) return jsonResponse(response)
      if (url.endsWith('/v1/ai/feedback')) return new Response(null, { status: 204 })
      return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
    }),
  )
  return calls
}

async function askAndRender(response = answer) {
  const calls = stubAI(response)
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
    expect(screen.getAllByText(/possible hijack 192\.0\.2\.0\/24/i).length).toBeGreaterThanOrEqual(
      2,
    )
    expect(screen.getByText(/high confidence/i)).toBeTruthy()
    expect(screen.getAllByText(/root cause grounded/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/root cause cited:/i)).toBeTruthy()
    // Trust summary spells out the grounding breadth.
    expect(screen.getByText(/grounded in 2 signals across 2 planes: bgp, metrics/i)).toBeTruthy()

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
    fireEvent.click(screen.getAllByRole('link', { name: 'E1' })[0])
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
    expect(fb?.body).toMatchObject({
      rating: 'down',
      comment: 'the real cause was the upstream peer',
    })
  })

  test('renders degraded and ungrounded RCA trust state', async () => {
    await askAndRender({
      ...answer,
      root_cause_citations: [],
      root_cause_grounded: false,
      degraded: true,
    })

    expect(screen.getAllByText(/root cause ungrounded/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/degraded fallback/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/treat the cited findings as the source of truth/i)).toBeTruthy()
    expect(screen.getByText(/used a degraded fallback path/i)).toBeTruthy()
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

  test('citation links have a tokenized visible focus style', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/routes/ask.module.css'), 'utf8')

    expect(css).toMatch(
      /\.cite:focus-visible\s*{[^}]*border-color:\s*var\(--color-accent\);[^}]*outline:\s*2px\s+solid\s+var\(--color-focus\);[^}]*outline-offset:\s*2px;/s,
    )
  })
})
