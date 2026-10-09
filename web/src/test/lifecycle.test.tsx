// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { holdLoginRedirect } from '../api/client'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch, pathOf } from './fetchStub'

/** S-T5 surface: the Data lifecycle card on Admin — self-service export,
 *  the retention control, residency/isolation visibility. Core in every
 *  edition (a compliance right). */

describe('tenant data lifecycle (S-T5)', () => {
  afterEach(() => holdLoginRedirect(false))

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
    expect(screen.getByLabelText(/flow days/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/otlp days/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/audit days/i)).toBeInTheDocument()
    expect(
      screen.getByText(/tenant value can only shorten a positive deployment maximum/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/tenant pruning always waits for its SIEM export cursor/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/provider pruning always waits for WORM evidence/i)).toBeInTheDocument()
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

  test('editing one retention field preserves the others in the PUT body (WEB-08)', async () => {
    const base = defaultFetch()
    const stub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/v1/lifecycle/retention') && (init?.method ?? 'GET') === 'GET')
        return jsonResponse({
          tenant_id: '00000000-0000-0000-0000-000000000001',
          flow_retention_days: 30,
          audit_retention_days: 90,
          ai_answer_retention_days: 7,
          isolation_model: 'pooled',
        })
      if (url.endsWith('/v1/lifecycle/retention') && init?.method === 'PUT')
        return jsonResponse({
          tenant_id: '00000000-0000-0000-0000-000000000001',
          flow_retention_days: 14,
          isolation_model: 'pooled',
        })
      return base(input, init)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', stub)
    renderApp('/admin')
    // The form pre-fills the loaded policy; editing only Flow must not clear the
    // others (previously every un-retyped field was sent as null and reset).
    const flow = await screen.findByLabelText(/flow days/i)
    await waitFor(() => expect((flow as HTMLInputElement).value).toBe('30'))
    await userEvent.clear(flow)
    await userEvent.type(flow, '14')
    await userEvent.click(screen.getByRole('button', { name: /save retention/i }))
    expect(await screen.findByText(/retention saved/i)).toBeInTheDocument()
    const calls = (stub as unknown as ReturnType<typeof vi.fn>).mock.calls
    const put = calls.find(
      (c) =>
        String(c[0]).endsWith('/v1/lifecycle/retention') &&
        (c[1] as RequestInit | undefined)?.method === 'PUT',
    )
    const body = JSON.parse(String((put![1] as RequestInit).body))
    expect(body.flow_retention_days).toBe(14)
    expect(body.audit_retention_days).toBe(90)
    expect(body.ai_answer_retention_days).toBe(7)
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
    await userEvent.type(await screen.findByLabelText(/flow days/i), '0')
    await userEvent.click(screen.getByRole('button', { name: /save retention/i }))
    expect(await screen.findByText(/flow_retention_days must be >= 1/)).toHaveAttribute(
      'role',
      'alert',
    )
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
    await userEvent.type(await screen.findByLabelText(/flow days/i), '14')
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

  // The erasure removes the tenant's users and sessions with its data, so every
  // later call answers 401. The shared 401 handler used to send the browser to
  // the login page at once, and the receipt the admin erased the data for
  // vanished before it could be read or kept.
  test('the erasure receipt outlives the session the erasure ended', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: '', pathname: '/' })
    const base = defaultFetch()
    let erased = false
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        if (erased)
          return jsonResponse(
            { error: { code: 'unauthorized', message: 'authentication required' } },
            401,
          )
        if (path === '/v1/lifecycle/erase' && init?.method === 'POST') {
          erased = true
          return jsonResponse({
            format_version: 1,
            tenant_id: '00000000-0000-0000-0000-000000000001',
            tenant_slug: 'acme-prod',
            actor: 'ada@acme.example',
            started_at: '2026-01-01T00:00:00Z',
            finished_at: '2026-01-01T00:00:03Z',
            stores: [{ store: 'postgres', deleted: 12, verified_zero: true }],
            backup_policy: '30d',
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
    await userEvent.type(within(dialog).getByLabelText(/tenant slug confirmation/i), 'acme-prod')
    await userEvent.click(within(dialog).getByRole('button', { name: /^erase tenant data$/i }))
    const receipt = await screen.findByRole('dialog', { name: /erasure receipt/i })
    await new Promise((resolve) => setTimeout(resolve, 100))
    expect(assign).not.toHaveBeenCalled()
    expect(within(receipt).getByText(/abc123def456/)).toBeInTheDocument()

    const download = within(receipt).getByRole('link', { name: /download receipt/i })
    expect(download).toHaveAttribute('download', 'probectl-erasure-receipt-acme-prod.json')
    const href = download.getAttribute('href') ?? ''
    expect(href.startsWith('data:application/json')).toBe(true)
    const kept = JSON.parse(decodeURIComponent(href.slice(href.indexOf(',') + 1))) as {
      report_sha256: string
      stores: unknown[]
    }
    expect(kept.report_sha256).toBe('abc123def456')
    expect(kept.stores).toHaveLength(1)

    await userEvent.click(within(receipt).getByRole('button', { name: /^done$/i }))
    expect(assign).toHaveBeenCalledWith('/auth/login')
  })
})
