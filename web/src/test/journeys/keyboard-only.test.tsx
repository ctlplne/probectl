// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent, { type UserEvent } from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import baseline from '../../../../docs/ux/journey-baseline.json'
import { renderApp } from '../renderApp'
import { defaultFetch, jsonResponse, pathOf, sampleExplorerTemplates } from '../fetchStub'
import { stubPathHistoryFetch } from '../pathHistoryFixture'

async function activate(user: UserEvent, element: HTMLElement) {
  element.focus()
  expect(element).toHaveFocus()
  await user.keyboard('{Enter}')
}

function watchPointerEvents() {
  const pointer = vi.fn()
  document.addEventListener('pointerdown', pointer)
  return () => {
    document.removeEventListener('pointerdown', pointer)
    expect(pointer).not.toHaveBeenCalled()
  }
}

async function runPaletteCommand(user: UserEvent, label: string) {
  await user.keyboard('{Meta>}k{/Meta}')
  const input = await screen.findByRole('combobox', { name: /search commands/i })
  expect(input).toHaveFocus()
  await user.keyboard(label)
  await user.keyboard('{Enter}')
}

function readiness(id: string, state: 'ready' | 'quiet' | 'blocked', detail: string) {
  return {
    id,
    state,
    detail,
    next_action:
      id === 'synthetic'
        ? state === 'ready'
          ? '/targets'
          : '/onboarding#first-run-agent'
        : id === 'synthetic-results'
          ? '/targets'
          : `/admin?register_collector=${id}`,
  }
}

function installJourneyFetch() {
  const base = defaultFetch()
  let operational = false
  let tokenCreated = false
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
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
        ],
        engines: [
          readiness(
            'synthetic-results',
            operational ? 'ready' : 'quiet',
            operational ? 'engine has tenant data' : 'engine is waiting for tenant data',
          ),
        ],
      })
    }
    if (path === '/v1/agents/enroll-tokens' && method === 'POST') {
      tokenCreated = true
      return jsonResponse(
        {
          token: 'pjt_keyboard_secret',
          id: 'token-keyboard',
          tenant_id: 'server-only',
          expires_at: '2026-07-14T13:00:00Z',
          server_cert_pin: 'sha256:keyboard-pin',
        },
        201,
      )
    }
    if (path === '/v1/tests' && method === 'POST') {
      operational = true
      return jsonResponse(
        {
          ...JSON.parse(String(init?.body)),
          id: 'test-keyboard',
          created_at: '2026-07-14T11:59:00Z',
          updated_at: '2026-07-14T11:59:00Z',
        },
        201,
      )
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

function fleetAgent() {
  return {
    id: 'skew',
    name: 'skew-edge',
    hostname: 'skew-edge.example',
    agent_version: 'v1.1.0',
    status: 'online',
    capabilities: ['flow'],
    heartbeat_age_seconds: 30,
    heartbeat_state: 'ready',
    heartbeat_reason: 'Heartbeat is fresh.',
    version_state: 'unsupported',
    version_reason: 'Minor-version skew exceeds the supported window.',
    readiness_state: 'version_skew',
    readiness_reason: 'Minor-version skew exceeds the supported window.',
    rollout_halted: false,
    last_failure: 'Unsupported version.',
    next_safe_action: {
      kind: 'review_staged_rollout',
      label: 'Review staged rollout',
      reason: 'A human may plan a signed, cohort-gated rollout or rollback.',
      href: '/docs/api#rollouts',
    },
  }
}

function incidentAnswer() {
  return {
    id: 'answer-keyboard',
    tenant: 'server-only',
    question: 'What caused this incident?',
    root_cause: 'HTTP latency and the flow spike overlap in the incident clock.',
    root_cause_citations: [{ evidence_id: 'E-synthetic' }],
    root_cause_grounded: true,
    degraded: false,
    confidence: 'high',
    model: 'builtin',
    reasoning: {
      adapter: 'builtin',
      execution: 'builtin_local',
      egress_consent: 'not_required',
    },
    insufficient_evidence: false,
    findings: [
      {
        statement: 'The synthetic latency signal is inside the shared clock.',
        citations: [{ evidence_id: 'E-synthetic' }],
      },
    ],
    evidence: [
      {
        id: 'E-synthetic',
        domain: 'synthetic',
        plane: 'synthetic',
        title: 'HTTP latency above SLO',
        occurred_at: '2026-06-04T11:55:00Z',
        fields: { id: 'inc-dashboard:0' },
      },
    ],
  }
}

function providerJourneyFetch() {
  const operator = {
    id: 'operator-1',
    email: 'root@msp.example',
    name: 'Root Operator',
    role: 'admin',
    status: 'active',
    enrolled: true,
  }
  const tenant = {
    id: 'tenant-acme',
    slug: 'acme',
    name: 'Acme',
    status: 'active',
    isolation_model: 'pooled',
  }
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.endsWith('/provider/v1/me')) return jsonResponse({ operator })
    if (url.endsWith('/provider/v1/license'))
      return jsonResponse({ tier: 'msp', pricing_model: 'consumption', state: 'active' })
    if (url.endsWith('/provider/v1/fleet'))
      return jsonResponse({
        items: [
          {
            tenant_id: tenant.id,
            tenant_slug: tenant.slug,
            tenant_name: tenant.name,
            tenant_status: tenant.status,
            agents_total: 3,
            agents_online: 2,
            agents_stale: 1,
            versions: { 'v1.4.0': 2, 'v1.3.0': 1 },
          },
        ],
      })
    if (url.endsWith('/provider/v1/tenants') && method === 'GET')
      return jsonResponse({ items: [tenant] })
    if (url.endsWith('/provider/v1/tenants') && method === 'POST')
      return jsonResponse({ ...tenant, id: 'tenant-silo', isolation_model: 'siloed' }, 201)
    if (url.endsWith('/provider/v1/breakglass') && method === 'GET')
      return jsonResponse({ items: [] })
    if (url.includes('/provider/v1/usage') && method === 'GET')
      return jsonResponse({
        items: [
          {
            tenant_id: tenant.id,
            tenant_slug: tenant.slug,
            meter: 'agents',
            kind: 'gauge',
            period_start: '2026-07-01T00:00:00Z',
            period_end: '2026-07-14T00:00:00Z',
            value: 3,
            unit: 'count',
          },
        ],
      })
    if (url.endsWith('/provider/v1/fairness')) return jsonResponse({ items: [] })
    if (url.endsWith('/provider/v1/operators')) return jsonResponse({ items: [operator] })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('J1-J6 keyboard-only completion', () => {
  test('the declared keyboard counts are complete and never exceed pointer budgets', () => {
    expect(baseline.measurements).toHaveLength(6)
    for (const measurement of baseline.measurements) {
      expect(measurement.keyboard_interactions).toBeLessThanOrEqual(
        measurement.pointer_interactions,
      )
      expect(measurement.outcome.status).toBe('complete')
    }
  })

  test('J1 mints, copies, creates, and opens the real first finding without a pointer', async () => {
    const user = userEvent.setup()
    const stopPointerWatch = watchPointerEvents()
    vi.stubGlobal('fetch', installJourneyFetch())
    renderApp('/onboarding')
    expect(await screen.findByText(/0 of 5 readiness steps/i)).toBeInTheDocument()

    await activate(user, screen.getByRole('button', { name: /mint enrollment token/i }))
    const agentCard = screen.getByRole('heading', { name: /enroll an agent/i }).closest('section')!
    await activate(user, within(agentCard).getByRole('button', { name: /copy command/i }))
    const testCard = screen
      .getByRole('heading', { name: /create the first test/i })
      .closest('section')!
    await activate(user, within(testCard).getByRole('button', { name: /create first test/i }))

    expect(await screen.findByText(/5 of 5 readiness steps/i)).toBeInTheDocument()
    await activate(user, screen.getByRole('button', { name: /view first finding/i }))
    expect(await screen.findByRole('heading', { name: /targets & tests/i })).toBeInTheDocument()
    stopPointerWatch()
  })

  test('J2 selects evidence, cites RCA, and shares the fixed snapshot in four keyboard actions', async () => {
    const user = userEvent.setup()
    const stopPointerWatch = watchPointerEvents()
    const base = defaultFetch()
    const answer = incidentAnswer()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        if (path === '/v1/ai/ask' && method === 'POST') return jsonResponse(answer)
        if (
          path === '/v1/incidents/30000000-0000-4000-8000-000000000001/shares' &&
          method === 'POST'
        ) {
          const request = JSON.parse(String(init?.body)) as { context: Record<string, unknown> }
          return jsonResponse(
            {
              id: 'share_keyboard_01234567',
              incident: {
                id: '30000000-0000-4000-8000-000000000001',
                status: 'open',
                severity: 'warning',
                title: 'checkout latency burn',
                target: 'https://checkout.probectl.test',
                started_at: '2026-06-04T11:45:00Z',
                last_seen_at: '2026-06-04T12:00:00Z',
                signal_count: 0,
                signals: [],
              },
              context: request.context,
              answer: { ...answer, tenant: '' },
              created_at: '2026-07-14T12:06:00Z',
              expires_at: '2026-07-21T12:06:00Z',
            },
            201,
          )
        }
        return base(input, init)
      }),
    )
    renderApp('/incidents?incident_status=open')
    const room = await screen.findByRole('region', { name: /unified five-plane incident room/i })

    // J2's first keyboard action selects the signal directly on the incident
    // clock timeline — the marker and the evidence row share one selection.
    const clock = within(room).getByRole('list', { name: /one time axis/i })
    await activate(user, within(clock).getByRole('button', { name: /HTTP latency above SLO/i }))
    await activate(user, within(room).getByRole('button', { name: /explain this view/i }))
    const explanation = await within(room).findByRole('region', {
      name: /explanation inspector/i,
    })
    await activate(user, within(explanation).getAllByRole('link', { name: 'E-synthetic' })[0])
    await runPaletteCommand(user, 'Share cited incident RCA')

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce())
    const shared = String(writeText.mock.calls[0][0])
    expect(shared).toContain('share=share_keyboard_01234567')
    expect(shared.toLowerCase()).not.toContain('tenant')
    stopPointerWatch()
  })

  test('J3 executes all ten canonical questions with twenty keyboard actions', async () => {
    const user = userEvent.setup()
    const stopPointerWatch = watchPointerEvents()
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/explore')
    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()

    for (const template of sampleExplorerTemplates) {
      await activate(user, screen.getByRole('button', { name: String(template.question) }))
      await activate(user, screen.getByRole('button', { name: 'Run query' }))
      await waitFor(() =>
        expect(screen.getByLabelText('Ask in natural language')).toHaveValue(template.question),
      )
    }
    stopPointerWatch()
  }, 15_000)

  test('J4 inspects, compares, shares, and pivots through equivalent exact controls', async () => {
    const user = userEvent.setup()
    const stopPointerWatch = watchPointerEvents()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    stubPathHistoryFetch([])
    renderApp('/path')

    const inspect = await screen.findByRole('button', { name: /inspect worst hop/i })
    await activate(user, inspect)
    const dialog = await screen.findByRole('dialog', { name: /hop 2 .*10\.0\.0\.2/i })
    await user.keyboard('{Escape}')
    await waitFor(() => expect(dialog).not.toBeInTheDocument())
    expect(inspect).toHaveFocus()

    const compare = within(
      screen.getByRole('region', { name: /path history and comparison/i }),
    ).getByLabelText(/compare with/i)
    compare.focus()
    await user.keyboard('{ArrowDown}')
    // jsdom does not implement the browser's default option movement for a
    // keydown on <select>; dispatch only the resulting change, never a pointer.
    fireEvent.change(compare, { target: { value: 'round-previous' } })
    await waitFor(() => expect(compare).toHaveValue('round-previous'))

    await activate(user, screen.getByRole('button', { name: /copy stable path link/i }))
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce())
    const exactTable = screen.getByRole('table', { name: /path to .* by hop/i })
    expect(within(exactTable).getByRole('button', { name: 'Selected' })).toBeInTheDocument()

    await activate(
      user,
      screen.getByRole('link', { name: /open incident evidence: loss on one ecmp branch/i }),
    )
    expect(
      await screen.findByRole('region', { name: /unified five-plane incident room/i }),
    ).toBeInTheDocument()
    stopPointerWatch()
  })

  test('J5 opens the exception filter and evidence-only safe action in two keyboard actions', async () => {
    const user = userEvent.setup()
    const stopPointerWatch = watchPointerEvents()
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/agents'
          ? jsonResponse({ items: [fleetAgent()], rollouts_available: true })
          : base(input, init),
      ),
    )
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })

    await runPaletteCommand(user, 'Review unhealthy fleet')
    const table = await screen.findByRole('table', { name: /registered agents/i })
    expect(screen.getByLabelText('Fleet health')).toHaveValue('needs_action')
    const action = within(table).getByRole('button', { name: /review staged rollout/i })
    await activate(user, action)
    const dialog = await screen.findByRole('dialog', { name: /safe action for skew-edge/i })
    expect(within(dialog).getByText(/never updates an agent/i)).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(action).toHaveFocus()
    stopPointerWatch()
  })

  test('J6 completes ranked provider operations in eight keyboard actions after MFA', async () => {
    const user = userEvent.setup()
    const stopPointerWatch = watchPointerEvents()
    const stub = providerJourneyFetch()
    vi.stubGlobal('fetch', stub)
    renderApp('/provider')

    const nav = await screen.findByRole('navigation', { name: /provider tasks/i })
    const fleet = await screen.findByRole('table', { name: /fleet across tenants/i })
    await activate(user, within(fleet).getByRole('button', { name: /triage acme exception/i }))
    await activate(user, within(nav).getByRole('link', { name: /provision & lifecycle/i }))

    const isolation = await screen.findByLabelText(/^isolation$/i)
    isolation.focus()
    await user.keyboard('{ArrowDown}')
    fireEvent.change(isolation, { target: { value: 'siloed' } })
    await waitFor(() => expect(isolation).toHaveValue('siloed'))
    const residency = screen.getByLabelText(/residency/i)
    residency.focus()
    await user.keyboard('eu')
    const slug = screen.getByLabelText(/new tenant slug/i)
    slug.focus()
    await user.keyboard('silo-co')
    const name = screen.getByLabelText(/display name/i)
    name.focus()
    await user.keyboard('Silo Co')
    await activate(user, screen.getByRole('button', { name: /^provision$/i }))

    const exportLink = within(nav).getByRole('link', { name: /export usage csv/i })
    exportLink.addEventListener('click', (event) => event.preventDefault(), { once: true })
    await activate(user, exportLink)
    expect(stub).toHaveBeenCalledWith(
      expect.stringContaining('/provider/v1/tenants'),
      expect.objectContaining({ method: 'POST' }),
    )
    stopPointerWatch()
  })
})
