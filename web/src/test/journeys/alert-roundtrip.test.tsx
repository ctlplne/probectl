// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { describe, expect, test, vi } from 'vitest'
import { Providers } from '../../App'
import { AppRoutes } from '../../routes/AppRoutes'
import { parsePivotContext } from '../../routes/pivotContext'
import { defaultFetch, jsonResponse, pathOf } from '../fetchStub'

const SINCE = '2026-07-14T10:00:00.000Z'
const LAST_SEEN = '2026-07-14T10:05:00.000Z'

const incident = {
  id: 'inc-alert-roundtrip',
  tenant_id: 'server-only',
  status: 'open',
  severity: 'critical',
  title: 'Database latency alert',
  target: 'db',
  started_at: SINCE,
  last_seen_at: LAST_SEEN,
  signal_count: 1,
  signals: [
    {
      plane: 'network',
      kind: 'alert.firing',
      severity: 'critical',
      title: 'Database latency alert',
      target: 'db',
      occurred_at: SINCE,
    },
  ],
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="route-location">{`${location.pathname}${location.search}`}</output>
}

function renderWithLocation(path: string) {
  return render(
    <Providers>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
        <LocationProbe />
      </MemoryRouter>
    </Providers>,
  )
}

function currentURL(): URL {
  return new URL(
    screen.getByTestId('route-location').textContent ?? '/',
    'https://probectl.invalid',
  )
}

type Operation = {
  action: 'acknowledged' | 'silenced' | 'unsilenced'
  actor: string
  reason: string
  started_at: string
  expires_at?: string
  delivery_status: string
  audit_ref: string
}

function roundtripBackend(options: { expiredSilence?: boolean; connectorBlocked?: boolean } = {}) {
  const fallback = defaultFetch()
  const active = {
    fingerprint: 'fp-roundtrip',
    evaluation_fingerprint: 'eval:roundtrip-series',
    rule_id: 'rule-db-latency',
    rule_name: 'Database latency',
    severity: 'critical',
    metric: 'probectl_result_rtt_ms',
    labels: { target: 'db' },
    value: 250,
    reason: 'p95 RTT 250ms is above 100ms',
    since: SINCE,
    last_seen_at: LAST_SEEN,
    acked_by: undefined as string | undefined,
    acked_at: undefined as string | undefined,
    silenced_until: undefined as string | undefined,
  }
  const operations: Operation[] = options.expiredSilence
    ? [
        {
          action: 'silenced',
          actor: 'prior-operator@probectl.test',
          reason: 'Past deploy window',
          started_at: '2000-01-01T00:00:00.000Z',
          expires_at: '2000-01-01T01:00:00.000Z',
          delivery_status: 'not_applicable',
          audit_ref: 'audit:40:expired-silence-hash',
        },
      ]
    : []
  const requests: Array<{ method: string; path: string; body?: Record<string, unknown> }> = []

  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined
    requests.push({ method, path, body })

    if (path === '/v1/alerts/active' && method === 'GET') {
      return jsonResponse({ items: [active], evaluator_running: true })
    }
    if (path === '/v1/alerts/rule-db-latency/evaluations' && method === 'GET') {
      return jsonResponse({
        contract_version: 'probectl.alert-evaluations/v1',
        items: [
          {
            contract_version: 'probectl.alert-evaluation/v1',
            fingerprint: active.evaluation_fingerprint,
            rule_id: active.rule_id,
            rule_revision: SINCE,
            state: 'firing',
            observed_at: LAST_SEEN,
            observed_value: 250,
            expectation: { kind: 'threshold', comparison: 'gt', threshold: 100 },
            breach_count: 2,
            required_breaches: 2,
            reason: 'probectl_result_rtt_ms=250 gt 100',
            labels: { target: 'db' },
          },
        ],
        truncated: false,
        limit: 64,
        freshness: 'current',
        latest_at: LAST_SEEN,
        evaluator_running: true,
        persistence_running: true,
        retention: { max_per_series: 64, max_per_rule: 256, expires_days: 7 },
      })
    }
    if (path === '/v1/alerts/active/ack' && method === 'POST') {
      active.acked_by = 'operator@probectl.test'
      active.acked_at = '2026-07-14T10:06:00.000Z'
      operations.push({
        action: 'acknowledged',
        actor: active.acked_by,
        reason: String(body?.reason),
        started_at: active.acked_at,
        delivery_status: 'not_applicable',
        audit_ref: 'audit:41:ack-hash',
      })
      return jsonResponse({
        ...active,
        persistence_running: true,
        operation_actor: active.acked_by,
        operation_reason: body?.reason,
        operation_started_at: active.acked_at,
        audit_ref: 'audit:41:ack-hash',
      })
    }
    if (path === '/v1/alerts/active/silence' && method === 'POST') {
      active.silenced_until = '2026-07-14T11:06:00.000Z'
      operations.push({
        action: 'silenced',
        actor: 'operator@probectl.test',
        reason: String(body?.reason),
        started_at: '2026-07-14T10:06:00.000Z',
        expires_at: active.silenced_until,
        delivery_status: 'not_applicable',
        audit_ref: 'audit:42:silence-hash',
      })
      return jsonResponse({
        ...active,
        persistence_running: true,
        operation_actor: 'operator@probectl.test',
        operation_reason: body?.reason,
        operation_started_at: '2026-07-14T10:06:00.000Z',
        audit_ref: 'audit:42:silence-hash',
      })
    }
    if (path === '/v1/alerts/active/fp-roundtrip/workflow' && method === 'GET') {
      return jsonResponse({
        alert: active,
        operations,
        incident,
        deliveries: options.connectorBlocked
          ? []
          : [
              {
                connector: 'servicenow',
                external_ref: 'INC0012345',
                status: 'open',
                created_at: SINCE,
                updated_at: LAST_SEEN,
                receipt_ref: 'connector:servicenow:INC0012345',
              },
            ],
        evaluator_running: true,
        persistence_running: true,
        connector_running: !options.connectorBlocked,
      })
    }
    if (path === '/v1/alerts') {
      return jsonResponse({
        items: [
          {
            id: 'rule-db-latency',
            tenant_id: 'server-only',
            name: 'Database latency',
            enabled: true,
            metric: 'probectl_result_rtt_ms',
            type: 'threshold',
            comparison: 'gt',
            threshold: 100,
            severity: 'critical',
            created_at: SINCE,
            updated_at: SINCE,
          },
        ],
      })
    }
    if (path === '/v1/alerts/maintenance') {
      return jsonResponse({ items: [], evaluator_running: true })
    }
    if (path === '/v1/oncall/status') {
      return jsonResponse({
        id: 'oncall',
        name: 'On-call + ITSM',
        summary: options.connectorBlocked ? 'No connector configured' : 'ServiceNow configured',
        configured: !options.connectorBlocked,
        dispatcher_running: !options.connectorBlocked,
        outbound_configured: !options.connectorBlocked,
        inbound_configured: false,
        outbound_connector_count: options.connectorBlocked ? 0 : 1,
        inbound_webhook_count: 0,
        tls_required: true,
        secrets_redacted: true,
        providers: [],
        outbound: [],
        inbound: [],
        supported_providers: ['servicenow'],
      })
    }
    if (path === '/v1/incidents') return jsonResponse({ items: [incident] })
    if (path === `/v1/incidents/${incident.id}`) return jsonResponse(incident)
    if (path === `/v1/incidents/${incident.id}/changes`) return jsonResponse({ items: [] })
    return fallback(input, init)
  }) as unknown as typeof fetch

  return { fetcher, requests }
}

describe('alert-to-postmortem round trip (X11)', () => {
  test('completes acknowledgment, bounded silence, delivery receipt, and postmortem in four interactions', async () => {
    const { fetcher, requests } = roundtripBackend()
    vi.stubGlobal('fetch', fetcher)
    renderWithLocation('/alerts?alert_state=firing')

    let interactions = 0
    const activeTable = await screen.findByRole('table', { name: 'Active alerts' })
    await userEvent.click(within(activeTable).getByRole('button', { name: 'Details' }))
    interactions += 1
    let dialog = await screen.findByRole('dialog', { name: 'Database latency' })
    const evaluationTimeline = await within(dialog).findByRole('list', {
      name: 'Deterministic evaluation receipts',
    })
    expect(evaluationTimeline).toHaveTextContent('firing')
    expect(evaluationTimeline).toHaveTextContent('gt 100')
    expect(evaluationTimeline).toHaveTextContent('2 / 2 breaches')

    await userEvent.click(within(dialog).getByRole('button', { name: 'Acknowledge' }))
    interactions += 1
    await waitFor(() =>
      expect(
        within(screen.getByRole('list', { name: 'Immutable alert operation receipts' })).getByText(
          'acknowledged',
        ),
      ).toBeInTheDocument(),
    )

    dialog = screen.getByRole('dialog', { name: 'Database latency' })
    await userEvent.click(within(dialog).getByRole('button', { name: 'Silence' }))
    interactions += 1
    await waitFor(() =>
      expect(
        within(screen.getByRole('list', { name: 'Immutable alert operation receipts' })).getByText(
          'silenced',
        ),
      ).toBeInTheDocument(),
    )
    dialog = screen.getByRole('dialog', { name: 'Database latency' })
    const receipts = within(dialog).getByRole('list', {
      name: 'Immutable alert operation receipts',
    })
    expect(receipts).toHaveTextContent('operator@probectl.test')
    expect(receipts).toHaveTextContent('Investigating the firing alert')
    expect(receipts).toHaveTextContent('Expiry:')
    expect(receipts).toHaveTextContent('Delivery: not_applicable')
    expect(receipts).toHaveTextContent('audit:41:ack-hash')
    expect(receipts).toHaveTextContent('audit:42:silence-hash')

    const delivery = within(dialog).getByLabelText('On-call and ticket receipts')
    expect(delivery).toHaveTextContent('Servicenow')
    expect(delivery).toHaveTextContent('INC0012345')
    expect(delivery).toHaveTextContent('connector:servicenow:INC0012345')

    await userEvent.click(
      within(dialog).getByRole('link', { name: 'Open incident & postmortem context' }),
    )
    interactions += 1
    expect(await screen.findByRole('heading', { name: 'Incidents' })).toBeInTheDocument()
    expect(interactions).toBeLessThanOrEqual(8)

    const url = currentURL()
    const context = parsePivotContext(url.searchParams).context
    expect(url.pathname).toBe('/incidents')
    expect(context).toMatchObject({
      incidentId: incident.id,
      from: SINCE,
      to: LAST_SEEN,
      returnTo: '/alerts?alert_state=firing&alert=eval%3Aroundtrip-series',
    })
    expect(url.search.toLowerCase()).not.toContain('tenant')
    expect(
      requests.filter((request) =>
        ['/v1/alerts/active/ack', '/v1/alerts/active/silence'].includes(request.path),
      ),
    ).toHaveLength(2)
    expect(requests.every((request) => !request.path.includes('tenant'))).toBe(true)
  })

  test('restores the same alert detail from the opaque return context', async () => {
    const { fetcher } = roundtripBackend()
    vi.stubGlobal('fetch', fetcher)
    renderWithLocation('/alerts?alert=eval%3Aroundtrip-series')

    const dialog = await screen.findByRole('dialog', { name: 'Database latency' })
    expect(dialog).toHaveTextContent('db')
    expect(currentURL().searchParams.get('alert')).toBe('eval:roundtrip-series')

    const incidentLink = await within(dialog).findByRole('link', {
      name: 'Open incident & postmortem context',
    })
    const incidentURL = new URL(
      incidentLink.getAttribute('href') ?? '/',
      'https://probectl.invalid',
    )
    expect(parsePivotContext(incidentURL.searchParams).context.returnTo).toBe(
      '/alerts?alert=eval%3Aroundtrip-series',
    )
    expect(incidentURL.search.toLowerCase()).not.toContain('tenant')
  })

  test('expired silence visibly returns to firing and a missing connector has one safe action', async () => {
    const { fetcher } = roundtripBackend({ expiredSilence: true, connectorBlocked: true })
    vi.stubGlobal('fetch', fetcher)
    renderWithLocation('/alerts')

    const activeTable = await screen.findByRole('table', { name: 'Active alerts' })
    expect(within(activeTable).getByText('firing')).toBeInTheDocument()
    await userEvent.click(within(activeTable).getByRole('button', { name: 'Details' }))
    const dialog = await screen.findByRole('dialog', { name: 'Database latency' })
    expect(await within(dialog).findByText('silence expired · firing resumed')).toBeInTheDocument()
    const blocked = within(dialog)
      .getByText('Connector delivery blocked')
      .closest('[role="status"]')
    expect(blocked).not.toBeNull()
    expect(within(blocked as HTMLElement).getAllByRole('link')).toHaveLength(1)
    expect(within(blocked as HTMLElement).getByRole('link')).toHaveAttribute(
      'href',
      '/docs/api#oncall-setup',
    )
  })
})
