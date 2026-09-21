// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const discover = {
  proposals: [
    {
      spec: {
        name: '203.0.113.10 (ICMP)',
        type: 'icmp',
        target: '203.0.113.10',
        interval_seconds: 60,
        timeout_seconds: 3,
        enabled: true,
      },
      rationale: 'Observed 9× on the flow plane with no monitoring test; suggest icmp.',
      score: 9,
      source: 'flow',
    },
  ],
}

const proposal = {
  spec: {
    name: '9.9.9.9 (ICMP)',
    type: 'icmp',
    target: '9.9.9.9',
    interval_seconds: 60,
    timeout_seconds: 3,
    enabled: true,
  },
  rationale: 'Detected an IP address in the request.',
  source: 'heuristic',
}

function stub() {
  const posts: Array<{ url: string; body: Record<string, unknown> | undefined }> = []
  const createdTargets = new Set<string>()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const body = init?.body
        ? (JSON.parse(String(init.body)) as Record<string, unknown>)
        : undefined
      if (init?.method === 'POST') posts.push({ url, body })
      if (url.endsWith('/v1/tests') && init?.method === 'POST') {
        if (typeof body?.target === 'string') createdTargets.add(body.target)
        return jsonResponse({ id: 't9', ...body, params: {}, created_at: '', updated_at: '' }, 201)
      }
      if (url.endsWith('/v1/tests')) return jsonResponse({ items: [] })
      if (url.endsWith('/v1/agents')) return jsonResponse({ items: [] })
      if (url.endsWith('/v1/ai/discover')) {
        return jsonResponse({
          proposals: discover.proposals.filter((p) => !createdTargets.has(p.spec.target)),
        })
      }
      if (url.endsWith('/v1/ai/author')) return jsonResponse(proposal)
      return jsonResponse({ error: { code: 'x', message: 'no route' } }, 404)
    }),
  )
  return posts
}

describe('AI test authoring', () => {
  test('lists suggestions and creates an authored test on confirmation (review-and-apply)', async () => {
    const posts = stub()
    renderApp('/targets', { me: { permissions: ['ai.query', 'test.write'] } })
    await screen.findByRole('heading', { name: /author with ai/i })

    // Auto-discovery proposes an observed-but-unmonitored target.
    await screen.findByText('203.0.113.10')
    expect(screen.getByText(/observed 9× on the flow plane/i)).toBeInTheDocument()

    // Author from natural language → a proposal appears (nothing created yet).
    fireEvent.change(screen.getByLabelText(/describe a test/i), {
      target: { value: 'ping 9.9.9.9' },
    })
    fireEvent.click(screen.getByRole('button', { name: /propose a test/i }))
    await screen.findByText('9.9.9.9 (ICMP)')
    const code = screen.getByLabelText('View as YAML')
    expect(code).toHaveTextContent('kind: Test')
    expect(code).toHaveTextContent('target: 9.9.9.9')
    expect(posts.some((p) => p.url.endsWith('/v1/tests'))).toBe(false) // not created on propose

    // Confirm → the test is created.
    fireEvent.click(screen.getByRole('button', { name: /create test/i }))
    await screen.findByText(/test created/i)
    expect(posts.some((p) => p.url.endsWith('/v1/tests') && p.body?.target === '9.9.9.9')).toBe(
      true,
    )
  })

  test('keeps a flow-derived suggestion propose-only until the operator presses Add', async () => {
    const posts = stub()
    renderApp('/targets', { me: { permissions: ['ai.query', 'test.write'] } })
    await screen.findByText('203.0.113.10')
    expect(screen.getByText(/observed 9× on the flow plane/i)).toBeInTheDocument()
    expect(posts.some((p) => p.url.endsWith('/v1/tests'))).toBe(false)

    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    await screen.findByText(/test created/i)
    expect(
      posts.some(
        (p) =>
          p.url.endsWith('/v1/tests') &&
          p.body?.target === '203.0.113.10' &&
          p.body?.type === 'icmp',
      ),
    ).toBe(true)
    await screen.findByText(/no suggestions yet/i)
    expect(screen.queryByRole('button', { name: 'Add' })).not.toBeInTheDocument()
    expect(posts.filter((p) => p.url.endsWith('/v1/ai/discover'))).toHaveLength(2)
  })

  test('the authoring surface has no a11y violations', async () => {
    stub()
    const { container } = renderApp('/targets', {
      me: { permissions: ['ai.query', 'test.write'] },
    })
    await screen.findByRole('heading', { name: /author with ai/i })
    await screen.findByText('203.0.113.10')
    expect(await axe(container)).toHaveNoViolations()
  })
})
