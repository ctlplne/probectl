// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi, beforeEach } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import type { ActiveAlert, AlertRule, MaintenanceWindow } from '../api/alerts'

/** A stateful stub standing in for the S16 backend: rules CRUD + an "engine"
 *  whose silence/ack mutations return engine truth (the UI must render what
 *  the engine answered, never its own derived state). */
function alertsBackend() {
  const since = '2026-06-04T12:00:00Z'
  const now = Date.now()
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
        channels: [{ type: 'webhook', url: 'https://hooks.example/alerts', secret: 'top-secret' }],
        created_at: since,
        updated_at: since,
      } as AlertRule,
    ],
    active: [
      {
        fingerprint: 'fp-1',
        evaluation_fingerprint: 'eval:db-series',
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
        evaluation_fingerprint: 'eval:web-series',
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
    maintenance: [
      {
        id: 'mw-1',
        tenant_id: 't',
        name: 'database patch',
        starts_at: new Date(now - 60_000).toISOString(),
        ends_at: new Date(now + 3_600_000).toISOString(),
        recurrence: '',
        rule_ids: ['r1'],
        match: { target: 'db' },
        reason: 'planned database work',
        created_by: 'operator@probectl.test',
        audit_ref: 'audit:1:maintenance-hash',
        created_at: since,
        updated_at: since,
      } as MaintenanceWindow,
    ],
    oncall: {
      id: 'oncall',
      name: 'On-call + ITSM',
      summary:
        'On-call and ITSM integration is configured with 1 outbound connector(s) and 1 inbound webhook(s)',
      configured: true,
      dispatcher_running: true,
      outbound_configured: true,
      inbound_configured: true,
      outbound_connector_count: 1,
      inbound_webhook_count: 1,
      tls_required: true,
      secrets_redacted: true,
      providers: [{ provider: 'pagerduty', outbound_connector_count: 1, inbound_webhook_count: 0 }],
      outbound: [
        {
          id: 'pagerduty-1',
          provider: 'pagerduty',
          tenant_routed: true,
          endpoint_configured: true,
          endpoint_tls_configured: true,
          endpoint_host: 'events.pagerduty.com',
          credential_configured: true,
          endpoint_secrets_redacted: true,
        },
      ],
      inbound: [
        {
          id: 'snow-a',
          provider: 'servicenow',
          path: '/ingest/itsm/servicenow/snow-a',
          credential_configured: true,
        },
      ],
      supported_providers: ['pagerduty', 'opsgenie', 'slack', 'teams', 'servicenow', 'jira'],
    },
    channelTests: [] as Record<string, unknown>[],
    connectorTests: [] as string[],
    workflowOperations: [] as Array<{
      action: 'acknowledged' | 'silenced' | 'unsilenced'
      actor: string
      reason: string
      started_at: string
      expires_at?: string
      delivery_status: string
      audit_ref: string
    }>,
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
    if (
      url.includes('/v1/alerts/r1/evaluations?fingerprint=eval%3Adb-series') &&
      method === 'GET'
    ) {
      return jsonResponse({
        contract_version: 'probectl.alert-evaluations/v1',
        items: [
          {
            contract_version: 'probectl.alert-evaluation/v1',
            fingerprint: 'eval:db-series',
            rule_id: 'r1',
            rule_revision: since,
            state: 'normal',
            observed_at: '2026-06-04T11:58:00Z',
            observed_value: 80,
            expectation: { kind: 'threshold', comparison: 'gt', threshold: 100 },
            breach_count: 0,
            required_breaches: 1,
            reason: 'probectl_result_rtt_ms=80 gt 100',
            labels: { target: 'db' },
          },
          {
            contract_version: 'probectl.alert-evaluation/v1',
            fingerprint: 'eval:db-series',
            rule_id: 'r1',
            rule_revision: since,
            state: 'firing',
            observed_at: since,
            observed_value: 250,
            expectation: { kind: 'threshold', comparison: 'gt', threshold: 100 },
            breach_count: 1,
            required_breaches: 1,
            reason: 'probectl_result_rtt_ms=250 gt 100',
            labels: { target: 'db' },
          },
        ],
        truncated: false,
        limit: 64,
        freshness: 'current',
        latest_at: since,
        evaluator_running: true,
        persistence_running: true,
        retention: { max_per_series: 64, max_per_rule: 256, expires_days: 7 },
      })
    }
    if (url.endsWith('/v1/alerts/active/silence') && method === 'POST') {
      const a = state.active.find((x) => x.fingerprint === body.fingerprint)
      if (!a) return jsonResponse({ error: { code: 'not_found', message: 'no firing alert' } }, 404)
      const mins = Number(body.duration_minutes ?? 0)
      a.silenced_until = mins > 0 ? '2026-06-04T13:00:00Z' : undefined
      state.workflowOperations.push({
        action: mins > 0 ? 'silenced' : 'unsilenced',
        actor: 'dev@probectl.local',
        reason: String(body.reason || 'Operator silence'),
        started_at: '2026-06-04T12:05:00Z',
        ...(mins > 0 ? { expires_at: '2026-06-04T13:00:00Z' } : {}),
        delivery_status: 'not_applicable',
        audit_ref: `audit:${state.workflowOperations.length + 2}:silence-hash`,
      })
      return jsonResponse({
        ...a,
        persistence_running: true,
        operation_actor: 'dev@probectl.local',
        operation_reason: body.reason,
        operation_started_at: '2026-06-04T12:05:00Z',
      })
    }
    if (url.endsWith('/v1/alerts/active/ack') && method === 'POST') {
      const a = state.active.find((x) => x.fingerprint === body.fingerprint)
      if (!a) return jsonResponse({ error: { code: 'not_found', message: 'no firing alert' } }, 404)
      a.acked_by = 'dev@probectl.local' // the ENGINE decides who acked (server-side principal)
      a.acked_at = '2026-06-04T12:05:00Z'
      state.workflowOperations.push({
        action: 'acknowledged',
        actor: 'dev@probectl.local',
        reason: String(body.reason || 'Investigation accepted'),
        started_at: '2026-06-04T12:05:00Z',
        delivery_status: 'not_applicable',
        audit_ref: `audit:${state.workflowOperations.length + 2}:ack-hash`,
      })
      return jsonResponse({
        ...a,
        persistence_running: true,
        operation_actor: 'dev@probectl.local',
        operation_reason: body.reason,
        operation_started_at: '2026-06-04T12:05:00Z',
      })
    }
    if (url.includes('/v1/alerts/active/fp-1/workflow') && method === 'GET') {
      return jsonResponse({
        alert: state.active[0],
        operations: state.workflowOperations,
        incident: {
          id: 'inc-alert',
          tenant_id: 't',
          status: 'open',
          severity: 'critical',
          title: 'rtt high firing',
          target: 'db',
          started_at: since,
          last_seen_at: since,
          signal_count: 1,
        },
        deliveries: [
          {
            connector: 'pagerduty',
            external_ref: 'PD-123',
            status: 'open',
            created_at: since,
            updated_at: since,
            receipt_ref: 'connector:pagerduty:PD-123',
          },
        ],
        evaluator_running: true,
        persistence_running: true,
        connector_running: true,
      })
    }
    if (url.endsWith('/v1/incidents') && method === 'GET') {
      return jsonResponse({
        items: [
          {
            id: 'inc-alert',
            tenant_id: 't',
            status: 'open',
            severity: 'critical',
            title: 'rtt high firing',
            target: 'db',
            started_at: since,
            last_seen_at: since,
            signal_count: 1,
          },
        ],
      })
    }
    if (url.endsWith('/v1/alerts') && method === 'GET') {
      return jsonResponse({ items: state.rules })
    }
    if (url.endsWith('/v1/alerts/maintenance') && method === 'GET') {
      return jsonResponse({ items: state.maintenance, evaluator_running: true })
    }
    if (url.endsWith('/v1/alerts/maintenance') && method === 'POST') {
      const win = {
        ...(body as unknown as MaintenanceWindow),
        id: String(body.id || `mw-${state.maintenance.length + 1}`),
        tenant_id: 't',
        created_at: '2026-06-04T12:10:00Z',
        updated_at: '2026-06-04T12:10:00Z',
        created_by: 'dev@probectl.local',
        audit_ref: `audit:${state.maintenance.length + 10}:maintenance-hash`,
      }
      const idx = state.maintenance.findIndex((w) => w.id === win.id)
      if (idx >= 0) state.maintenance[idx] = win
      else state.maintenance.push(win)
      return jsonResponse(win)
    }
    const maintenanceMatch = url.match(/\/v1\/alerts\/maintenance\/([^/]+)$/)
    if (maintenanceMatch && method === 'DELETE') {
      state.maintenance = state.maintenance.filter((x) => x.id !== maintenanceMatch[1])
      return new Response(null, { status: 204 })
    }
    if (url.endsWith('/v1/alerts/test-channel') && method === 'POST') {
      state.channelTests.push(body)
      return jsonResponse({ accepted: true, type: (body.channel as { type?: string })?.type }, 202)
    }
    if (url.endsWith('/v1/oncall/status') && method === 'GET') {
      return jsonResponse(state.oncall)
    }
    if (url.endsWith('/v1/oncall/test') && method === 'POST') {
      state.connectorTests.push(String(body.connector_id))
      return jsonResponse(
        {
          accepted: true,
          connector_id: body.connector_id,
          provider: 'pagerduty',
          status: 'triggered',
        },
        202,
      )
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
    const table = await screen.findByRole('table', { name: 'Active alerts' })
    expect(within(table).getByText(/target=db/)).toBeDefined()
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

  test('shows active maintenance badges and schedules timezone-aware windows', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    const activeTable = await screen.findByRole('table', { name: 'Active alerts' })
    await waitFor(() => {
      expect(within(activeTable).getByText('maintenance')).toBeDefined()
    })
    expect(
      within(screen.getByRole('table', { name: 'Maintenance windows' })).getByText(
        'database patch',
      ),
    ).toBeDefined()

    await userEvent.click(screen.getByRole('button', { name: 'Schedule window' }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'kernel patch')
    fireEvent.change(within(dialog).getByLabelText('Starts at'), {
      target: { value: '2026-06-05T01:00' },
    })
    fireEvent.change(within(dialog).getByLabelText('Ends at'), {
      target: { value: '2026-06-05T02:30' },
    })
    await userEvent.selectOptions(within(dialog).getByLabelText('Time zone'), 'UTC')
    await userEvent.selectOptions(within(dialog).getByLabelText('Recurrence'), 'weekly')
    await userEvent.type(within(dialog).getByLabelText('Rule IDs'), 'r1')
    await userEvent.type(within(dialog).getByLabelText('Match labels'), 'target=db')
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'kernel upgrade')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Schedule window' }))

    await waitFor(() => expect(state.maintenance.some((w) => w.name === 'kernel patch')).toBe(true))
    const saved = state.maintenance.find((w) => w.name === 'kernel patch')
    expect(saved).toMatchObject({
      starts_at: '2026-06-05T01:00:00.000Z',
      ends_at: '2026-06-05T02:30:00.000Z',
      recurrence: 'weekly',
      rule_ids: ['r1'],
      match: { target: 'db' },
      reason: 'kernel upgrade',
    })
  })

  test('exports alert rules and maintenance windows as redacted YAML', async () => {
    const { fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    const rulesTable = await screen.findByRole('table', { name: 'Alert rules' })
    await userEvent.click(within(rulesTable).getByRole('button', { name: 'View as YAML' }))
    let dialog = await screen.findByRole('dialog', { name: /export as code: rtt high/i })
    expect(dialog).toHaveTextContent('kind: AlertRule')
    expect(dialog).toHaveTextContent('url: https://hooks.example/alerts')
    expect(dialog).toHaveTextContent('secret: <redacted-by-probectl>')
    expect(dialog).not.toHaveTextContent('top-secret')

    await userEvent.click(within(dialog).getByRole('button', { name: /close/i }))

    const maintenanceTable = screen.getByRole('table', { name: 'Maintenance windows' })
    await userEvent.click(within(maintenanceTable).getByRole('button', { name: 'View as YAML' }))
    dialog = await screen.findByRole('dialog', { name: /export as code: database patch/i })
    expect(dialog).toHaveTextContent('kind: MaintenanceWindow')
    expect(dialog).toHaveTextContent('rule_ids:')
    expect(dialog).toHaveTextContent('target: db')
  })

  test('silence + acknowledge act through the API and render the ENGINE state', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    // Open the detail for the db series.
    expect(
      within(await screen.findByRole('table', { name: 'Active alerts' })).getByText(/target=db/),
    ).toBeDefined()
    await userEvent.click(screen.getAllByRole('button', { name: 'Details' })[0])
    const dialog = await screen.findByRole('dialog')
    const timeline = await within(dialog).findByRole('list', {
      name: 'Deterministic evaluation receipts',
    })
    expect(within(timeline).getByText('normal')).toBeDefined()
    expect(within(timeline).getByText('firing')).toBeDefined()
    expect(within(timeline).getAllByText('gt 100')).toHaveLength(2)
    expect(within(timeline).getByText('0 / 1 breaches')).toBeDefined()
    expect(within(timeline).getByText('1 / 1 breaches')).toBeDefined()
    expect(dialog).not.toHaveTextContent('tenant_id')

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
    expect((await within(dialog).findAllByText(/dev@probectl\.local/)).length).toBeGreaterThan(0)

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

    expect(
      within(await screen.findByRole('table', { name: 'Active alerts' })).getByText(/target=db/),
    ).toBeDefined()
    await userEvent.click(screen.getByRole('button', { name: 'Create rule' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/probectl_probe_rtt_avg_ms/)).toBeInTheDocument()
    expect(within(dialog).getByText(/dots with underscores/i)).toBeInTheDocument()
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

  test('configures alert-channel delivery and tests tenant-routed incident connectors with redacted secrets', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')

    const connectors = await screen.findByRole('table', { name: 'Incident connectors' })
    expect(within(connectors).getByText('Pagerduty')).toBeDefined()
    expect(within(connectors).getByText('current tenant')).toBeDefined()
    expect(within(connectors).getByText('events.pagerduty.com')).toBeDefined()
    expect(screen.queryByText(/routing-key|secret/i)).toBeNull()

    await userEvent.click(within(connectors).getByRole('button', { name: 'Test' }))
    await waitFor(() => expect(state.connectorTests).toEqual(['pagerduty-1']))

    await userEvent.click(screen.getByRole('button', { name: 'Create rule' }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'webhook delivery')
    await userEvent.type(within(dialog).getByLabelText('Metric'), 'probectl_result_loss_pct')
    await userEvent.selectOptions(within(dialog).getByLabelText('Delivery channel'), 'webhook')
    await userEvent.type(
      within(dialog).getByLabelText('Webhook URL'),
      'https://hooks.example/alerts',
    )
    await userEvent.type(within(dialog).getByLabelText('Webhook secret'), 'super-secret')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Test channel' }))
    await waitFor(() => expect(state.channelTests.length).toBe(1))
    expect(screen.queryByText('super-secret')).toBeNull()

    await userEvent.click(within(dialog).getByRole('button', { name: 'Create rule' }))
    await waitFor(() => expect(state.rules.length).toBe(2))
    expect(state.rules[1].channels?.[0]).toMatchObject({
      type: 'webhook',
      url: 'https://hooks.example/alerts',
      secret: 'super-secret',
    })
  })

  test('tenant scoping: the page renders only what the tenant-scoped API returns and never sends tenant params', async () => {
    const { state, fetcher } = alertsBackend()
    vi.stubGlobal('fetch', fetcher)
    renderApp('/alerts')
    expect(
      within(await screen.findByRole('table', { name: 'Active alerts' })).getByText(/target=db/),
    ).toBeDefined()

    // The client never selects a tenant — identity is the session, the server
    // scopes (S8a API contract). No tenant_id ever appears in a request URL.
    expect(state.requests.every((r) => !r.url.includes('tenant'))).toBe(true)

    // And the rendered rows are exactly the API's items (no synthesis).
    const rows = within(screen.getByRole('table', { name: 'Active alerts' })).getAllByRole('row')
    expect(rows.length).toBe(1 + state.active.length)
  })

  test('alerting inactive is a persistent page warning with setup docs', async () => {
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
    const warning = await screen.findByRole('alert', { name: /stored rules will not fire/i })
    expect(warning).toHaveTextContent(/no query-capable TSDB backend/i)
    expect(warning).toHaveTextContent(/not evaluated/i)
    expect(
      within(warning).getByRole('link', { name: /open alerting setup docs/i }),
    ).toHaveAttribute('href', '/docs/api#alerting-setup')
    expect(screen.getByRole('table', { name: 'Alert rules' })).toBeDefined()
  })
})
