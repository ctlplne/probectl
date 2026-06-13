import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { ActiveAlert, AlertRule } from '../api/alerts'

/** A stateful stub standing in for the S16 backend: rules CRUD + an "engine"
 *  whose silence/ack mutations return engine truth (the UI must render what
 *  the engine answered, never its own derived state). */
function alertsBackend() {
  const since = '2026-06-04T12:00:00Z'
  const state = {
    rules: [
      {
        id: 'r1',
        tenant_id: 't',
        name: 'rtt high',
        enabled: true,
        metric: 'probectl_result_rtt_ms',
        type: 'threshold',
        comparison: 'gt',
        threshold: 100,
        for_n: 1,
        severity: 'critical',
        created_at: since,
        updated_at: since,
      } as AlertRule,
    ],
    active: [
      {
        fingerprint: 'fp-1',
        rule_id: 'r1',
        rule_name: 'rtt high',
        severity: 'critical',
        metric: 'probectl_result_rtt_ms',
        labels: { target: 'db', tenant_id: 't' },
        value: 250,
        reason: 'probectl_result_rtt_ms=250 gt 100',
        since,
        last_seen_at: since,
      } as ActiveAlert,
      {
        fingerprint: 'fp-2',
        rule_id: 'r1',
        rule_name: 'rtt high',
        severity: 'warning',
        metric: 'probectl_result_rtt_ms',
        labels: { target: 'web', tenant_id: 't' },
        value: 120,
        reason: 'probectl_result_rtt_ms=120 gt 100',
        since,
        last_seen_at: since,
      } as ActiveAlert,
    ],
    requests: [] as { method: string; url: string }[],
  }

  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    state.requests.push({ method, url })
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {}

    if (url.endsWith('/v1/alerts/active') && method === 'GET') {
      return jsonResponse({ items: state.active, evaluator_running: true })
    }
    if (url.endsWith('/v1/alerts/active/silence') && method === 'POST') {
      const a = state.active.find((x) => x.fingerprint === body.fingerprint)
      if (!a) return jsonResponse({ error: { code: 'not_found', message: 'no firing alert' } }, 404)
      const mins = Number(body.duration_minutes ?? 0)
      a.silenced_until = mins > 0 ? '2026-06-04T13:00:00Z' : undefined
      return jsonResponse(a)
    }
    if (url.endsWith('/v1/alerts/active/ack') && method === 'POST') {
      const a = state.active.find((x) => x.fingerprint === body.fingerprint)
      if (!a) return jsonResponse({ error: { code: 'not_found', message: 'no firing alert' } }, 404)
      a.acked_by = 'dev@probectl.local' // the ENGINE decides who acked (server-side principal)
      a.acked_at = '2026-06-04T12:05:00Z'
      return jsonResponse(a)
    }
    if (url.endsWith('/v1/alerts') && method === 'GET') {
      return jsonResponse({ items: state.rules })
    }
    if (url.endsWith('/v1/alerts') && method === 'POST') {
      const rule = {
        ...(body as unknown as AlertRule),
        id: `r${state.rules.length + 1}`,
        tenant_id: 't',
        created_at: '2026-06-04T12:10:00Z',
        updated_at: '2026-06-04T12:10:00Z',
      }
      state.rules.push(rule)
      return jsonResponse(rule, 201)
    }
    const ruleMatch = url.match(/\/v1\/alerts\/(r\d+)$/)
    if (ruleMatch && method === 'PUT') {
      const r = state.rules.find((x) => x.id === ruleMatch[1])
      if (!r) return jsonResponse({ error: { code: 'not_found', message: 'no rule' } }, 404)
      Object.assign(r, body)
      return jsonResponse(r)
    }
    if (ruleMatch && method === 'DELETE') {
      state.rules = state.rules.filter((x) => x.id !== ruleMatch[1])
      return new Response(null, { status: 204 })
    }
    return jsonResponse(
      { error: { code: 'not_found', message: `unstubbed ${method} ${url}` } },
      404,
    )
  }) as unknown as typeof fetch

  return { state, fetcher }
}

describe('alerting surface (S-FE1)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  test('lists active alerts (engine truth) and rules; filters by state + severity', async () => {
    const { fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    // Both firing series render with severity badges.
    expect(await screen.findByText(/target=db/)).toBeDefined()
    const table = screen.getByRole('table', { name: 'Active alerts' })
    expect(within(table).getAllByText('rtt high').length).toBe(2)
    expect(within(table).getByText('critical')).toBeDefined()

    // Severity filter narrows to the warning series only.
    await userEvent.selectOptions(
      screen.getByLabelText('Severity', { selector: 'select' }),
      'warning',
    )
    await waitFor(() => {
      const rows = within(screen.getByRole('table', { name: 'Active alerts' })).getAllByRole('row')
      expect(rows.length).toBe(2) // header + 1
    })
    expect(
      within(screen.getByRole('table', { name: 'Active alerts' })).queryByText(/target=db/),
    ).toBeNull()

    // The rules table shows the configured rule.
    expect(
      within(screen.getByRole('table', { name: 'Alert rules' })).getByText('gt 100'),
    ).toBeDefined()
  })

  test('silence + acknowledge act through the API and render the ENGINE state', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    // Open the detail for the db series.
    await screen.findByText(/target=db/)
    await userEvent.click(screen.getAllByRole('button', { name: 'Details' })[0])
    const dialog = await screen.findByRole('dialog')

    // Silence -> the API was called and the UI reflects the engine's answer.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Silence' }))
    await waitFor(() => {
      expect(
        state.requests.some(
          (r) => r.url.endsWith('/v1/alerts/active/silence') && r.method === 'POST',
        ),
      ).toBe(true)
    })
    expect(await within(dialog).findByText('Silenced until')).toBeDefined()
    expect(within(dialog).getByRole('button', { name: 'Unsilence' })).toBeDefined()

    // Acknowledge -> identity comes from the server response, not the client.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Acknowledge' }))
    expect(await within(dialog).findByText(/dev@probectl\.local/)).toBeDefined()

    // The list reflects engine state after refetch: one silenced badge.
    await userEvent.click(within(dialog).getByRole('button', { name: /close/i }))
    await waitFor(() => {
      expect(
        within(screen.getByRole('table', { name: 'Active alerts' })).getByText('silenced'),
      ).toBeDefined()
    })
  })

  test('creates an alert rule through the form', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    await screen.findByText(/target=db/)
    await userEvent.click(screen.getByRole('button', { name: 'Create rule' }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'loss high')
    await userEvent.type(within(dialog).getByLabelText('Metric'), 'probectl_result_loss_pct')
    await userEvent.clear(within(dialog).getByLabelText('Threshold'))
    await userEvent.type(within(dialog).getByLabelText('Threshold'), '5')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))

    await waitFor(() => expect(state.rules.length).toBe(2))
    expect(state.rules[1].name).toBe('loss high')
    expect(state.rules[1].metric).toBe('probectl_result_loss_pct')
    // The new rule appears in the table (cache invalidated -> refetched).
    await waitFor(() => {
      expect(
        within(screen.getByRole('table', { name: 'Alert rules' })).getByText('loss high'),
      ).toBeDefined()
    })
  })

  test('tenant scoping: the page renders only what the tenant-scoped API returns and never sends tenant params', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')
    await screen.findByText(/target=db/)

    // The client never selects a tenant — identity is the session, the server
    // scopes (S8a API contract). No tenant_id ever appears in a request URL.
    expect(state.requests.every((r) => !r.url.includes('tenant'))).toBe(true)

    // And the rendered rows are exactly the API's items (no synthesis).
    const rows = within(screen.getByRole('table', { name: 'Active alerts' })).getAllByRole('row')
    expect(rows.length).toBe(1 + state.active.length)
  })

  test('evaluator-off is stated, not guessed', async () => {
    const { fetcher } = alertsBackend()
    const offFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/v1/alerts/active') && (init?.method ?? 'GET') === 'GET') {
        return jsonResponse({ items: [], evaluator_running: false })
      }
      return fetcher(input, init)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', offFetcher)
    renderApp('/alerts')
    expect(await screen.findByText(/evaluator is not running/)).toBeDefined()
  })
})
