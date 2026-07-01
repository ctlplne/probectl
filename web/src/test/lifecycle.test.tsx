import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch, pathOf } from './fetchStub'

/** S-T5 surface: the Data lifecycle card on Admin — self-service export,
 *  the retention control, residency/isolation visibility. Core in every
 *  edition (a compliance right). */

describe('tenant data lifecycle (S-T5)', () => {
  test('the card renders export, isolation visibility, and the retention control', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')
    expect(await screen.findByText(/data lifecycle/i)).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /export my data/i })).toHaveAttribute(
      'href',
      '/v1/lifecycle/export',
    )
    expect(screen.getByRole('link', { name: /redacted export/i })).toHaveAttribute(
      'href',
      '/v1/lifecycle/export?redact=true',
    )
    expect(screen.getByText('pooled')).toBeInTheDocument()
    expect(screen.getByLabelText(/flow retention days/i)).toBeInTheDocument()
    expect(screen.getByText(/PROBECTL_AUDIT_RETENTION defaults to keep forever/i)).toBeInTheDocument()
    expect(screen.getByText(/unexported evidence stays/i)).toBeInTheDocument()
  })

  test('residency + isolation render for a siloed tenant', async () => {
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith('/v1/lifecycle/retention') && (init?.method ?? 'GET') === 'GET')
          return jsonResponse({
            flow_retention_days: 30,
            isolation_model: 'siloed',
            residency: 'eu',
          })
        return base(input, init)
      }),
    )
    renderApp('/admin')
    expect(await screen.findByText('siloed')).toBeInTheDocument()
    expect(screen.getByText(/residency eu/i)).toBeInTheDocument()
  })

  test('saving retention PUTs the right payload (blank = deployment default)', async () => {
    const base = defaultFetch()
    const stub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/v1/lifecycle/retention') && init?.method === 'PUT')
        return jsonResponse({
          tenant_id: '00000000-0000-0000-0000-000000000001',
          flow_retention_days: 14,
          isolation_model: 'pooled',
        })
      return base(input, init)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', stub)
    renderApp('/admin')
    await userEvent.type(await screen.findByLabelText(/flow retention days/i), '14')
    await userEvent.click(screen.getByRole('button', { name: /save retention/i }))
    expect(await screen.findByText(/retention saved/i)).toBeInTheDocument()
    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls
    const put = calls.find(
      (c) =>
        String(c[0]).endsWith('/v1/lifecycle/retention') &&
        (c[1] as RequestInit | undefined)?.method === 'PUT',
    )
    expect(JSON.parse(String((put![1] as RequestInit).body))).toEqual({ flow_retention_days: 14 })
  })

  test('saving retention surfaces structured API errors', async () => {
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith('/v1/lifecycle/retention') && init?.method === 'PUT')
          return jsonResponse({ error: { message: 'flow_retention_days must be >= 1' } }, 400)
        return base(input, init)
      }),
    )
    renderApp('/admin')
    await userEvent.type(await screen.findByLabelText(/flow retention days/i), '0')
    await userEvent.click(screen.getByRole('button', { name: /save retention/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/flow_retention_days must be >= 1/)
  })

  test('saving retention uses the shared 401 reauth path', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: '', pathname: '/' })
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith('/v1/lifecycle/retention') && init?.method === 'PUT')
          return jsonResponse({ error: { message: 'authentication required' } }, 401)
        return base(input, init)
      }),
    )
    renderApp('/admin')
    await userEvent.type(await screen.findByLabelText(/flow retention days/i), '14')
    await userEvent.click(screen.getByRole('button', { name: /save retention/i }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/auth/login'))
  })

  test('typed slug confirmation rejects mistakes and renders the erasure receipt', async () => {
    const base = defaultFetch()
    const eraseBodies: Array<Record<string, string>> = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        if (path === '/v1/lifecycle/erase' && method === 'POST') {
          const body = JSON.parse(String(init?.body)) as Record<string, string>
          eraseBodies.push(body)
          if (body.confirm !== 'acme-prod') {
            return jsonResponse(
              {
                error: {
                  message: 'confirm must equal the tenant slug exactly - erasure is irreversible',
                },
              },
              400,
            )
          }
          return jsonResponse({
            format_version: 1,
            tenant_id: '00000000-0000-0000-0000-000000000001',
            tenant_slug: 'acme-prod',
            actor: 'tenant:00000000-0000-0000-0000-000000000001',
            started_at: '2026-01-01T00:00:00Z',
            finished_at: '2026-01-01T00:00:03Z',
            stores: [
              { store: 'postgres', deleted: 12, verified_zero: true },
              { store: 'flows', deleted: 0, verified_zero: true, notes: 'store not deployed' },
            ],
            backup_policy: '30d',
            backup_retention_days: 30,
            backup_erasure_deadline: '2026-01-31T00:00:03Z',
            complete: true,
            report_sha256: 'abc123def456',
          })
        }
        return base(input, init)
      }),
    )

    renderApp('/admin')
    await userEvent.click(await screen.findByRole('button', { name: /^erase tenant data$/i }))
    const dialog = await screen.findByRole('dialog', { name: /erase tenant data/i })
    const confirm = within(dialog).getByLabelText(/tenant slug confirmation/i)

    await userEvent.type(confirm, 'wrong-slug')
    await waitFor(() => expect(confirm).toHaveValue('wrong-slug'))
    await userEvent.click(within(dialog).getByRole('button', { name: /^erase tenant data$/i }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      /confirm must equal the tenant slug exactly/i,
    )
    expect(eraseBodies[0]).toEqual({ confirm: 'wrong-slug' })
    expect(JSON.stringify(eraseBodies[0])).not.toContain('tenant_id')

    await userEvent.clear(confirm)
    await userEvent.type(confirm, 'acme-prod')
    await waitFor(() => expect(confirm).toHaveValue('acme-prod'))
    await userEvent.click(within(dialog).getByRole('button', { name: /^erase tenant data$/i }))

    const receipt = await screen.findByRole('dialog', { name: /erasure receipt/i })
    expect(within(receipt).getByText('complete')).toBeInTheDocument()
    expect(within(receipt).getByText(/abc123def456/)).toBeInTheDocument()
    expect(within(receipt).getByText('postgres')).toBeInTheDocument()
    expect(within(receipt).getByText('flows')).toBeInTheDocument()
    expect(eraseBodies[1]).toEqual({ confirm: 'acme-prod' })
    expect(JSON.stringify(eraseBodies[1])).not.toContain('tenant_id')
  })
})
