// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import { messages, type Locale } from '../i18n/messages'

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
  reasoning: {
    adapter: 'builtin',
    execution: 'builtin_local',
    egress_consent: 'not_required',
    attempted_adapter: undefined as string | undefined,
  },
  insufficient_evidence: false,
  investigation_plan: [
    {
      step: 1,
      domain: 'entities',
      goal: 'Check correlated incidents and their already-stitched cross-plane signals.',
      limit: 50,
      read_only: true,
      status: 'queried',
      evidence_count: 1,
    },
    {
      step: 2,
      domain: 'events',
      goal: 'Check change, routing, flow, threat, and event-plane records near the question window.',
      limit: 50,
      read_only: true,
      status: 'blocked',
      reason: 'RBAC denied this read',
    },
    {
      step: 3,
      domain: 'topology',
      goal: 'Check anchored topology or path context without dumping the whole graph.',
      node_id: 'prefix:192.0.2.0/24',
      limit: 50,
      read_only: true,
      status: 'skipped',
      reason: 'source is not configured in this deployment',
    },
  ],
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

function stubAI(response: unknown = answer, feedbackStatus = 204) {
  const calls: Array<{ url: string; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const body = init?.body ? JSON.parse(String(init.body)) : undefined
      calls.push({ url, body })
      if (url.endsWith('/v1/ai/ask')) return jsonResponse(response)
      if (url.endsWith('/v1/ai/feedback')) {
        return feedbackStatus === 204
          ? new Response(null, { status: 204 })
          : jsonResponse(
              { error: { code: 'unavailable', message: 'feedback store unavailable' } },
              feedbackStatus,
            )
      }
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
    expect(screen.getByText(/built-in · local\/air-gapped/i)).toBeTruthy()
    expect(screen.getByText(/root cause cited:/i)).toBeTruthy()
    expect(screen.getByRole('heading', { name: /investigation plan/i })).toBeTruthy()
    expect(screen.getByText(/check correlated incidents/i)).toBeTruthy()
    expect(screen.getByText(/RBAC denied this read/i)).toBeTruthy()
    expect(screen.getByText(/source is not configured/i)).toBeTruthy()
    // Trust summary spells out the grounding breadth.
    expect(screen.getByText(/grounded in 2 signals across 2 planes: bgp, metrics/i)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /yes, helpful/i }))
    await screen.findByText(/thanks/i)
  })

  test('renders a server null collection as honest insufficient evidence instead of crashing', async () => {
    stubAI({
      ...answer,
      root_cause:
        'Insufficient evidence: no signals were found for this question within your scope.',
      root_cause_citations: null,
      root_cause_grounded: false,
      confidence: 'low',
      insufficient_evidence: true,
      investigation_plan: null,
      findings: null,
      evidence: null,
    })
    renderApp('/ask')
    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    fireEvent.change(screen.getByLabelText(/your question/i), {
      target: { value: 'what does the latest synthetic result show?' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))

    expect(await screen.findByText(/did not find enough evidence/i)).toBeInTheDocument()
    expect(screen.getAllByText(/root cause ungrounded/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/built-in · local\/air-gapped/i)).toBeInTheDocument()
    expect(screen.queryByText(/cannot read properties of null/i)).not.toBeInTheDocument()
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

  test('downloads the current answer locally from the keyboard without re-querying', async () => {
    const calls = await askAndRender()
    const createObjectURL = vi.fn((blob: Blob) => {
      void blob
      return 'blob:probectl-handoff'
    })
    const revokeObjectURL = vi.fn()
    const NativeURL = URL
    class DownloadURL extends NativeURL {}
    Object.assign(DownloadURL, { createObjectURL, revokeObjectURL })
    vi.stubGlobal('URL', DownloadURL)
    let filename = ''
    const anchorClick = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function captureDownload(this: HTMLAnchorElement) {
        filename = this.download
      })

    try {
      const user = userEvent.setup()
      const download = screen.getByRole('button', {
        name: /download investigation handoff/i,
      })
      download.focus()
      await user.keyboard('{Enter}')

      expect(createObjectURL).toHaveBeenCalledTimes(1)
      expect(createObjectURL.mock.calls[0][0]).toBeInstanceOf(Blob)
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:probectl-handoff')
      expect(filename).toBe('probectl-ask-handoff-ans_1.md')
      expect(calls.filter((call) => call.url.endsWith('/v1/ai/ask'))).toHaveLength(1)
    } finally {
      anchorClick.mockRestore()
    }
  })

  test.each([
    ['es-MX', 'es'],
    ['ar-EG', 'ar'],
    ['en-XA', 'en-xa'],
  ] as const)(
    'localizes the handoff control for %s without a raw English fallback',
    async (requestedLocale, catalogLocale) => {
      stubAI()
      renderApp('/ask', { locale: requestedLocale })
      const localized = messages[catalogLocale as Locale]
      await screen.findByRole('heading', { name: localized['ask.page.title'] })
      fireEvent.change(screen.getByLabelText(localized['ask.question.label']), {
        target: { value: 'what happened?' },
      })
      fireEvent.click(screen.getByRole('button', { name: localized['ask.submit'] }))

      expect(
        await screen.findByRole('button', { name: localized['ask.handoff.download'] }),
      ).toBeInTheDocument()
      expect(
        screen.queryByRole('button', { name: 'Download investigation handoff' }),
      ).not.toBeInTheDocument()
    },
  )

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

  test('failed feedback shows an accessible danger toast', async () => {
    stubAI(answer, 500)
    renderApp('/ask')
    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    fireEvent.change(screen.getByLabelText(/your question/i), {
      target: { value: 'why is 192.0.2.0/24 unreachable?' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText(/most likely root cause:/i)

    fireEvent.click(screen.getByRole('button', { name: /yes, helpful/i }))

    expect(await screen.findByText(/feedback not saved/i)).toBeInTheDocument()
    expect(screen.getByText(/feedback store unavailable/i)).toBeInTheDocument()
    expect(screen.queryByText(/^thanks/i)).not.toBeInTheDocument()
  })

  test('renders degraded and ungrounded RCA trust state', async () => {
    const malformedRoot = 'This unresolved causal sentence must never render.'
    stubAI({
      ...answer,
      root_cause: malformedRoot,
      root_cause_citations: [],
      root_cause_grounded: false,
      degraded: true,
      reasoning: {
        adapter: 'builtin',
        execution: 'builtin_fallback',
        egress_consent: 'granted',
        attempted_adapter: 'openai:gpt-test',
      },
    })
    renderApp('/ask')
    await screen.findByRole('heading', { name: /ask \(ai\)/i })
    fireEvent.change(screen.getByLabelText(/your question/i), {
      target: { value: 'what broke?' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))
    await screen.findByText(/treat the cited findings as the source of truth/i)

    expect(screen.getAllByText(/root cause ungrounded/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/degraded fallback/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/treat the cited findings as the source of truth/i)).toBeTruthy()
    expect(screen.getByText(/used a degraded fallback path/i)).toBeTruthy()
    expect(screen.queryByText(malformedRoot)).not.toBeInTheDocument()
    expect(screen.getByText(/unresolved causal claim.*suppressed/i)).toBeInTheDocument()
    expect(screen.getByText(/built-in fallback · local\/air-gapped/i)).toBeInTheDocument()
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
