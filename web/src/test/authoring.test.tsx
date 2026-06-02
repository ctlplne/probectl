import { describe, expect, test, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const discover = {
  proposals: [
    {
      spec: { name: 'payments.svc (HTTP)', type: 'http', target: 'https://payments.svc', interval_seconds: 60, timeout_seconds: 3, enabled: true },
      rationale: 'Observed 50× on the service plane with no monitoring test.',
      score: 52,
      source: 'service',
    },
  ],
}

const proposal = {
  spec: { name: '9.9.9.9 (ICMP)', type: 'icmp', target: '9.9.9.9', interval_seconds: 60, timeout_seconds: 3, enabled: true },
  rationale: 'Detected an IP address in the request.',
  source: 'heuristic',
}

function stub() {
  const posts: Array<{ url: string; body: Record<string, unknown> | undefined }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
      if (init?.method === 'POST') posts.push({ url, body })
      if (url.endsWith('/v1/tests') && init?.method === 'POST') {
        return jsonResponse({ id: 't9', ...body, params: {}, created_at: '', updated_at: '' }, 201)
      }
      if (url.endsWith('/v1/tests')) return jsonResponse({ items: [] })
      if (url.endsWith('/v1/agents')) return jsonResponse({ items: [] })
      if (url.endsWith('/v1/ai/discover')) return jsonResponse(discover)
      if (url.endsWith('/v1/ai/author')) return jsonResponse(proposal)
      return jsonResponse({ error: { code: 'x', message: 'no route' } }, 404)
    }) as unknown as typeof fetch,
  )
  return posts
}

describe('AI test authoring', () => {
  test('lists suggestions and creates an authored test on confirmation (review-and-apply)', async () => {
    const posts = stub()
    renderApp('/targets')
    await screen.findByRole('heading', { name: /author with ai/i })

    // Auto-discovery proposes an observed-but-unmonitored target.
    await screen.findByText(/payments\.svc/i)

    // Author from natural language → a proposal appears (nothing created yet).
    fireEvent.change(screen.getByLabelText(/describe a test/i), { target: { value: 'ping 9.9.9.9' } })
    fireEvent.click(screen.getByRole('button', { name: /propose a test/i }))
    await screen.findByText('9.9.9.9 (ICMP)')
    expect(posts.some((p) => p.url.endsWith('/v1/tests'))).toBe(false) // not created on propose

    // Confirm → the test is created.
    fireEvent.click(screen.getByRole('button', { name: /create test/i }))
    await screen.findByText(/test created/i)
    expect(posts.some((p) => p.url.endsWith('/v1/tests') && p.body?.target === '9.9.9.9')).toBe(true)
  })

  test('the authoring surface has no a11y violations', async () => {
    stub()
    const { container } = renderApp('/targets')
    await screen.findByRole('heading', { name: /author with ai/i })
    await screen.findByText(/payments\.svc/i)
    expect(await axe(container)).toHaveNoViolations()
  })
})
