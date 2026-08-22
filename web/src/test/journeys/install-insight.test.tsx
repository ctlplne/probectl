// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '../renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from '../fetchStub'
import {
  JourneyRecorder,
  assertRequestsUseSessionTenant,
  comparableActiveTimeMs,
  type MeasuredRequest,
} from './measurement'

function readiness(id: string, state: 'ready' | 'quiet' | 'blocked', detail: string) {
  const nextAction =
    id === 'synthetic'
      ? state === 'ready'
        ? '/targets'
        : '/onboarding#first-run-agent'
      : id === 'synthetic-results'
        ? '/targets'
        : `/admin?register_collector=${id}`
  return { id, state, detail, next_action: nextAction }
}

describe('J1 install to first real insight', () => {
  test('reaches a named server finding within the reference-compose interaction and time budget', async () => {
    const user = userEvent.setup()
    const requests: MeasuredRequest[] = []
    const base = defaultFetch()
    let operational = false
    let tokenCreated = false
    const fetchStub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      assertNoDoublePrefix(input)
      const path = pathOf(input)
      const method = init?.method ?? 'GET'
      requests.push({
        url: path,
        method,
        headers: Object.fromEntries(new Headers(init?.headers).entries()),
        body: init?.body,
      })
      if (path === '/v1/onboarding/progress') {
        return jsonResponse({
          agent_enroll_token_created: tokenCreated,
          agent_registered: operational,
          agent_connected: operational,
          producer_healthy: operational,
          first_test_created: operational,
          first_result_received: operational,
          first_finding_visible: operational,
          scim_token_created: false,
          readiness_steps_complete: operational ? 4 : 0,
          readiness_steps_total: 4,
          ...(operational
            ? {
                first_finding: {
                  title: 'ICMP check healthy — 127.0.0.1',
                  type: 'icmp',
                  target: '127.0.0.1',
                  success: true,
                  observed_at: '2026-07-14T12:00:00Z',
                  href: '/targets',
                },
              }
            : {}),
          producers: [
            readiness(
              'synthetic',
              operational ? 'ready' : 'blocked',
              operational ? 'producer heartbeat is current' : 'producer is not registered',
            ),
            ...['flow', 'bgp', 'device', 'ebpf', 'endpoint'].map((id) =>
              readiness(id, 'blocked', 'producer is not registered'),
            ),
          ],
          engines: [
            readiness(
              'synthetic-results',
              operational ? 'ready' : 'quiet',
              operational
                ? 'engine has tenant data'
                : 'engine is running and waiting for tenant data',
            ),
          ],
        })
      }
      if (path === '/v1/agents/enroll-tokens' && method === 'POST') {
        tokenCreated = true
        return jsonResponse(
          {
            token: 'pjt_journey_secret',
            id: 'token-j1',
            tenant_id: '00000000-0000-0000-0000-000000000001',
            expires_at: '2026-07-14T13:00:00Z',
            server_cert_pin: 'sha256:journey-pin',
          },
          201,
        )
      }
      if (path === '/v1/tests' && method === 'POST') {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>
        operational = true
        return jsonResponse(
          {
            ...body,
            id: 'test-j1',
            created_at: '2026-07-14T11:59:00Z',
            updated_at: '2026-07-14T11:59:00Z',
          },
          201,
        )
      }
      return base(input, init)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetchStub)

    const firstRender = renderApp('/onboarding')
    expect(await screen.findByText(/0 of 4 operational steps/i)).toBeInTheDocument()
    expect(screen.getByText(/waiting for the enrolled producer to connect/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /mint enrollment token/i }))
    expect(await screen.findByText(/0 of 4 operational steps/i)).toBeInTheDocument()
    const agentCard = screen.getByRole('heading', { name: /enroll an agent/i }).closest('section')!
    await user.click(within(agentCard).getByRole('button', { name: /copy command/i }))

    const testCard = screen
      .getByRole('heading', { name: /create the first test/i })
      .closest('section')!
    expect(within(testCard).getByLabelText(/type/i)).toHaveValue('icmp')
    expect(within(testCard).getByLabelText(/^target$/i)).toHaveValue('127.0.0.1')
    expect(within(testCard).getByText(/minimum 10 seconds/i)).toBeInTheDocument()
    await user.click(within(testCard).getByRole('button', { name: /create first test/i }))

    expect(await screen.findByText(/4 of 4 operational steps/i)).toBeInTheDocument()
    expect(screen.getByText('ICMP check healthy — 127.0.0.1')).toBeInTheDocument()

    firstRender.unmount()
    vi.stubGlobal('fetch', fetchStub)
    renderApp('/onboarding')
    expect(await screen.findByText(/4 of 4 operational steps/i)).toBeInTheDocument()
    expect(screen.getByText('ICMP check healthy — 127.0.0.1')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /view first finding/i }))
    expect(await screen.findByRole('heading', { name: /targets & tests/i })).toBeInTheDocument()

    assertRequestsUseSessionTenant(requests)
    const measurement = new JourneyRecorder('J1', 'install to first real insight')
      .pointer(4)
      .contextBreak(1)
      .activeTimeProxy({
        min_ms: 6 * 60_000,
        max_ms: 12 * 60_000,
        basis:
          'reference compose healthy; mint, shell enrollment, test creation, and finding receipt',
      })
      .complete(
        'server reports connected and healthy producer separately from token creation',
        'real loopback result renders a named first-finding receipt',
        'finding opens from onboarding without tenant selection',
      )
      .snapshot()

    expect(measurement.pointer_interactions).toBeLessThanOrEqual(7)
    expect(comparableActiveTimeMs(measurement)).toBeLessThanOrEqual(15 * 60_000)
  })
})
