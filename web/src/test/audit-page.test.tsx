import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const auditEvents = [
  {
    seq: 1,
    actor: 'alice@example.com',
    action: 'alert.create',
    target: 'alert/api',
    data: { name: 'api latency' },
    hash: 'aaaabbbbcccc1111',
    created_at: '2026-06-30T10:00:00Z',
  },
  {
    seq: 2,
    actor: 'bob@example.com',
    action: 'test.delete',
    target: 'test/db',
    data: {},
    hash: 'ddddeeeeffff2222',
    created_at: '2026-06-30T10:01:00Z',
  },
  {
    seq: 3,
    actor: 'alice@example.com',
    action: 'security.key_rotate',
    target: 'tenant/current',
    data: { key: 'managed' },
    hash: '1111222233334444',
    created_at: '2026-06-30T10:02:00Z',
  },
]

function urlOf(input: RequestInfo | URL): URL {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  return new URL(raw, 'http://probectl.test')
}

describe('native audit route', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  test('/audit renders filtered cursor pages, verify, and export affordance', async () => {
    const requests: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = urlOf(input)
        requests.push(`${url.pathname}${url.search}`)
        if (url.pathname === '/branding') return jsonResponse({ product_name: 'probectl' })
        if (url.pathname === '/v1/audit/verify') return jsonResponse({ ok: true })
        if (url.pathname === '/v1/audit') {
          const actor = url.searchParams.get('actor')?.toLowerCase() ?? ''
          const action = url.searchParams.get('action')?.toLowerCase() ?? ''
          const target = url.searchParams.get('target')?.toLowerCase() ?? ''
          const after = Number(url.searchParams.get('after') ?? '0')
          const items = auditEvents.filter(
            (ev) =>
              ev.seq > after &&
              ev.actor.toLowerCase().includes(actor) &&
              ev.action.toLowerCase().includes(action) &&
              ev.target.toLowerCase().includes(target),
          )
          return jsonResponse({ items, next: items.at(-1)?.seq ?? 0 })
        }
        return jsonResponse({ error: { code: 'not_found', message: `unstubbed ${url.pathname}` } }, 404)
      }),
    )

    renderApp('/audit', { me: { permissions: ['audit.read'] } })

    expect(await screen.findByText('Auditor read-only')).toBeDefined()
    const table = await screen.findByRole('table', { name: 'Audit events' })
    expect(within(table).getAllByText('alice@example.com').length).toBeGreaterThan(0)
    expect(within(table).getByText('alert.create')).toBeDefined()

    await userEvent.type(screen.getByLabelText('Actor'), 'alice')
    await userEvent.type(screen.getByLabelText('Action'), 'alert')
    await userEvent.type(screen.getByLabelText('Target'), 'api')
    await userEvent.click(screen.getByRole('button', { name: /Apply/ }))

    await waitFor(() =>
      expect(
        requests.some((r) => r.includes('/v1/audit?') && r.includes('actor=alice')),
      ).toBe(true),
    )
    expect(requests.some((r) => r.includes('action=alert') && r.includes('target=api'))).toBe(true)
    expect(within(screen.getByRole('table', { name: 'Audit events' })).queryByText('bob@example.com')).toBeNull()

    const exportLink = screen.getByRole('link', { name: 'Export JSON' })
    expect(exportLink.getAttribute('href')).toContain('/v1/audit')
    expect(exportLink.getAttribute('href')).toContain('actor=alice')

    await userEvent.click(screen.getByRole('button', { name: /Verify chain/ }))
    expect(await screen.findByText('Chain intact')).toBeDefined()

    await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(requests.some((r) => r.includes('after=1'))).toBe(true))
  })
})
