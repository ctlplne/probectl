// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { axe } from 'jest-axe'
import type { Answer } from '../api/ai'
import { citedTestTagReferences } from '../routes/RCATestTagContext'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const testID = '11111111-1111-4111-8111-111111111111'
const revision = '9007199254740993'
const answerFor = (tenant: string): Answer => ({
  id: 'answer-current-tags',
  tenant,
  question: 'Why is this test slow?',
  root_cause: 'The cited test metric has elevated latency.',
  root_cause_citations: [{ evidence_id: 'E1' }],
  root_cause_grounded: true,
  confidence: 'medium',
  findings: [],
  model: 'builtin',
  reasoning: { adapter: 'builtin', execution: 'builtin_local', egress_consent: 'not_required' },
  insufficient_evidence: false,
  evidence: [
    {
      id: 'E1',
      domain: 'metrics',
      title: 'Test latency',
      fields: { test_id: testID, target: 'https://same.example' },
    },
    {
      id: 'E2',
      domain: 'metrics',
      fields: { test_id: '22222222-2222-4222-8222-222222222222', target: 'https://same.example' },
    },
  ],
})

async function openAnswer(
  answer: Answer,
  permissions = ['tags.read', 'test.read'],
  tenant = answer.tenant,
) {
  const reads: Array<{ tenant: string | null; body: unknown }> = []
  const wide = '🌐'.repeat(24000)
  let refuse = false
  const original = JSON.stringify(answer)
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/v1/ai/ask')) return jsonResponse(answer)
      if (url.endsWith('/v1/tags/tests/resolve')) {
        reads.push({
          tenant: new Headers(init?.headers).get('X-Probectl-Tenant'),
          body: JSON.parse(String(init?.body)),
        })
        if (refuse)
          return jsonResponse(
            { error: { code: 'forbidden', message: 'Current metadata refused' } },
            403,
          )
        return jsonResponse({
          tag_revision: revision,
          as_of: '2026-11-03T00:00:00Z',
          items: [
            {
              context_id: '33333333-3333-4333-8333-333333333333',
              target_kind: 'test',
              target_id: testID,
              tag_revision: revision,
              as_of: '2026-11-03T00:00:00Z',
              items: [
                {
                  tag_id: '44444444-4444-4444-8444-444444444444',
                  key: 'customer',
                  value: wide,
                  source: 'rule',
                },
              ],
            },
          ],
        })
      }
      return jsonResponse({ error: { code: 'not_found', message: 'No fixture route' } }, 404)
    }),
  )
  const view = renderApp('/ask', { me: { tenant_id: tenant, permissions } })
  await screen.findByLabelText(/your question/i)
  fireEvent.change(screen.getByLabelText(/your question/i), { target: { value: answer.question } })
  fireEvent.click(screen.getByRole('button', { name: /^ask$/i }))
  await screen.findByText(answer.root_cause)
  return {
    ...view,
    reads,
    wide,
    original,
    refuse: () => {
      refuse = true
    },
  }
}

describe('current test metadata beside cited RCA evidence (simulated UI)', () => {
  test.each(['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'])(
    'looks up only exact cited IDs under the current tenant %s and clears refused refresh',
    async (tenant) => {
      const answer = answerFor(tenant)
      const view = await openAnswer(answer)
      expect(view.reads).toEqual([])
      fireEvent.click(screen.getByRole('button', { name: 'Show current test tags' }))
      await screen.findByText(revision)
      expect(view.reads).toEqual([{ tenant, body: { test_ids: [testID] } }])
      expect(view.container.querySelector('[data-tag-value-full]')?.textContent).toBe(view.wide)
      const details = view.container.querySelector('details:has([data-tag-value-full])')
      expect(details).toBeTruthy()
      fireEvent.click(details!.querySelector('summary')!)
      expect(screen.getByText(/loaded separately after this answer/)).toBeTruthy()
      expect(await axe(view.container)).toHaveNoViolations()
      view.refuse()
      fireEvent.click(screen.getByRole('button', { name: 'Refresh current test tags' }))
      await screen.findByText(/Current test tag context could not be loaded/)
      expect(view.container.querySelector('[data-tag-value-full]')).toBeNull()
      expect(screen.queryByText(revision)).toBeNull()
      expect(JSON.stringify(answer)).toBe(view.original)
      expect(screen.getByText(answer.root_cause)).toBeTruthy()
    },
  )

  test.each(['legacy', 'missing-grant', 'foreign-answer'])(
    '%s does not acquire current metadata through target matching',
    async (mode) => {
      const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
      const answer = answerFor(mode === 'foreign-answer' ? 'foreign-tenant' : tenant)
      if (mode === 'legacy')
        answer.evidence[0].fields = { target: 'https://same.example', id: testID }
      const view = await openAnswer(
        answer,
        mode === 'missing-grant' ? ['test.read'] : ['tags.read', 'test.read'],
        tenant,
      )
      expect(screen.queryByRole('button', { name: 'Show current test tags' })).toBeNull()
      expect(view.reads).toEqual([])
    },
  )

  test('unresolved, ambiguous, non-metric and ungrounded citations supply no references', () => {
    const base = answerFor('tenant-a')
    expect(citedTestTagReferences(base)).toEqual([testID])
    const unresolved = { ...base, root_cause_citations: [{ evidence_id: 'absent' }] }
    const ambiguous = { ...base, evidence: [...base.evidence, { ...base.evidence[0] }] }
    const nonMetric = {
      ...base,
      evidence: base.evidence.map((row) => ({ ...row, domain: 'entities' })),
    }
    for (const answer of [
      unresolved,
      ambiguous,
      nonMetric,
      { ...base, root_cause_grounded: false },
    ])
      expect(citedTestTagReferences(answer)).toEqual([])
    // A separately grounded finding may nominate its own metric, even when the
    // headline was suppressed. Uncited rows still cannot nominate any ID.
    expect(
      citedTestTagReferences({
        ...unresolved,
        findings: [{ statement: 'Observed metric', citations: [{ evidence_id: 'E1' }] }],
      }),
    ).toEqual([testID])
  })
})
