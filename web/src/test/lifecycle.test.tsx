import { describe, expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'

/** S-T5 surface: the Data lifecycle card on Admin — self-service export,
 *  the retention control, residency/isolation visibility. Core in every
 *  edition (a compliance right). */

describe('tenant data lifecycle (S-T5)', () => {
  test('the card renders export, isolation visibility, and the retention control', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')
    expect(await screen.findByText(/data lifecycle/i)).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /export my data/i })).toHaveAttribute('href', '/v1/lifecycle/export')
    expect(screen.getByRole('link', { name: /redacted export/i })).toHaveAttribute('href', '/v1/lifecycle/export?redact=true')
    expect(screen.getByText('pooled')).toBeInTheDocument()
    expect(screen.getByLabelText(/flow retention days/i)).toBeInTheDocument()
  })

  test('residency + isolation render for a siloed tenant', async () => {
    const base = defaultFetch() as unknown as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/v1/lifecycle/retention') && (init?.method ?? 'GET') === 'GET')
        return jsonResponse({ flow_retention_days: 30, isolation_model: 'siloed', residency: 'eu' })
      return base(input, init)
    }) as unknown as typeof fetch)
    renderApp('/admin')
    expect(await screen.findByText('siloed')).toBeInTheDocument()
    expect(screen.getByText(/residency eu/i)).toBeInTheDocument()
  })

  test('saving retention PUTs the right payload (blank = deployment default)', async () => {
    const base = defaultFetch() as unknown as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>
    const stub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/v1/lifecycle/retention') && init?.method === 'PUT')
        return jsonResponse({ flow_retention_days: 14 })
      return base(input, init)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', stub)
    renderApp('/admin')
    await userEvent.type(await screen.findByLabelText(/flow retention days/i), '14')
    await userEvent.click(screen.getByRole('button', { name: /save retention/i }))
    expect(await screen.findByText(/retention saved/i)).toBeInTheDocument()
    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls
    const put = calls.find((c) => String(c[0]).endsWith('/v1/lifecycle/retention') && (c[1] as RequestInit | undefined)?.method === 'PUT')
    expect(JSON.parse(String((put![1] as RequestInit).body))).toEqual({ flow_retention_days: 14 })
  })
})
