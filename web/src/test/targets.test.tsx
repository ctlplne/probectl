// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { messages, type Locale } from '../i18n/messages'

describe('Targets & Tests (live /v1/tests CRUD)', () => {
  test('filters native cross-plane debt and preserves explicit unknowns', async () => {
    const user = userEvent.setup()
    renderApp('/targets')

    const debtMap = await screen.findByRole('table', {
      name: /cross-plane coverage debt map/i,
    })
    expect(within(debtMap).getByText('Stale')).toBeInTheDocument()
    expect(within(debtMap).getByText('Unknown')).toBeInTheDocument()
    expect(within(debtMap).getByText('No exact evidence')).toBeInTheDocument()
    expect(
      screen.getByText(/routing \/ bgp: unregistered · 0 registered · 0 evidence/i),
    ).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Signal plane'), 'routing')
    expect(within(debtMap).getByText('Unknown')).toBeInTheDocument()
    expect(within(debtMap).queryByText('Stale')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Debt state'), 'unknown')
    const pivot = within(debtMap).getByRole('button', { name: 'Inspect topology' })
    await user.click(pivot)
    expect(await screen.findByRole('heading', { name: 'Topology' })).toBeInTheDocument()
  })

  test('does not present an unwired empty debt response as healthy', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) !== '/v1/coverage/debt') return fallback(input, init)
        return jsonResponse({
          items: [],
          producers: [],
          as_of: '2026-07-27T12:00:00Z',
          stale_after_seconds: 900,
          entity_limit: 500,
          candidate_limit: 5000,
          candidates_truncated: false,
          results_truncated: false,
          entities_truncated: false,
          topology_truncated: false,
          partial_reasons: ['topology evidence store is not wired'],
        })
      }),
    )

    renderApp('/targets')
    expect(
      await screen.findByText(/incomplete: topology evidence store is not wired/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/no entity rows can be treated as an authoritative empty inventory/i),
    ).toBeInTheDocument()
  })

  test('renders and filters honest owned-vantage states without mutating', async () => {
    const user = userEvent.setup()
    const tests = [
      {
        id: 't1',
        name: 'edge-dns',
        type: 'dns',
        target: '1.1.1.1',
        interval_seconds: 60,
        timeout_seconds: 3,
        params: {},
        enabled: true,
        created_at: '',
        updated_at: '',
      },
      {
        id: 't2',
        name: 'apac-api',
        type: 'http',
        target: 'https://api.example',
        interval_seconds: 60,
        timeout_seconds: 3,
        params: {},
        enabled: true,
        created_at: '',
        updated_at: '',
      },
      {
        id: 't3',
        name: 'edge-dns',
        type: 'dns',
        target: '9.9.9.9',
        interval_seconds: 60,
        timeout_seconds: 3,
        params: {},
        enabled: true,
        created_at: '',
        updated_at: '',
      },
      {
        id: 't4',
        name: 'legacy-tcp',
        type: 'tcp',
        target: 'db.internal:5432',
        interval_seconds: 60,
        timeout_seconds: 3,
        params: {},
        enabled: true,
        created_at: '',
        updated_at: '',
      },
    ]
    const coverage = [
      {
        test_id: 't1',
        test_name: 'edge-dns',
        region: 'eu-west',
        site: 'dub-1',
        agent_readiness: 'ready',
        agent_count: 1,
        ready_agent_count: 1,
        probe_family: 'dns',
        target: '1.1.1.1',
        last_evidence_at: '2026-07-26T11:59:00Z',
        independent_vantage_count: 1,
        stale_after_seconds: 300,
        status: 'non_redundant',
        execution_cadence: {
          state: 'gaps_observed',
          reason: 'missed_rounds',
          attribution: 'exact_test_id',
          configured_interval_seconds: 60,
          window_seconds: 360,
          expected_rounds: 6,
          observed_rounds: 4,
          missed_rounds: 2,
          max_gap_seconds: 180,
          observed_agent_count: 1,
          history_complete: true,
          current_assignment_verified: false,
        },
        next_action: {
          kind: 'author_test',
          label: 'Author another test',
          href: '/targets?create=test',
        },
      },
      {
        test_id: 't2',
        test_name: 'apac-api',
        region: 'ap-south',
        site: 'unlabeled',
        agent_readiness: 'unavailable',
        agent_count: 0,
        ready_agent_count: 0,
        probe_family: 'http',
        target: 'https://api.example',
        independent_vantage_count: 0,
        stale_after_seconds: 300,
        status: 'uncovered',
        execution_cadence: {
          state: 'never_observed',
          reason: 'no_exact_test_evidence',
          attribution: 'none',
          configured_interval_seconds: 60,
          window_seconds: 360,
          expected_rounds: 0,
          observed_rounds: 0,
          missed_rounds: 0,
          max_gap_seconds: 0,
          observed_agent_count: 0,
          history_complete: true,
          current_assignment_verified: false,
        },
        next_action: {
          kind: 'enroll_vantage',
          label: 'Enroll or restore a vantage',
          href: '/admin',
        },
      },
      {
        test_id: 't3',
        test_name: 'edge-dns',
        region: 'us-east',
        site: 'iad-1',
        agent_readiness: 'ready',
        agent_count: 1,
        ready_agent_count: 1,
        probe_family: 'dns',
        target: '9.9.9.9',
        last_evidence_at: '2026-07-26T11:59:00Z',
        independent_vantage_count: 1,
        stale_after_seconds: 300,
        status: 'covered',
        execution_cadence: {
          state: 'on_cadence',
          reason: 'on_cadence',
          attribution: 'exact_test_id',
          configured_interval_seconds: 60,
          window_seconds: 360,
          expected_rounds: 6,
          observed_rounds: 6,
          missed_rounds: 0,
          max_gap_seconds: 60,
          observed_agent_count: 1,
          history_complete: true,
          current_assignment_verified: true,
        },
      },
      {
        test_id: 't4',
        test_name: 'legacy-tcp',
        region: 'us-east',
        site: 'iad-2',
        agent_readiness: 'degraded',
        agent_count: 1,
        ready_agent_count: 0,
        probe_family: 'tcp',
        target: 'db.internal:5432',
        independent_vantage_count: 0,
        stale_after_seconds: 300,
        status: 'stale',
        execution_cadence: {
          state: 'unknown',
          reason: 'legacy_schedule_metadata',
          attribution: 'none',
          configured_interval_seconds: 60,
          window_seconds: 360,
          expected_rounds: 0,
          observed_rounds: 2,
          missed_rounds: 0,
          max_gap_seconds: 0,
          observed_agent_count: 1,
          history_complete: false,
          current_assignment_verified: false,
        },
        next_action: {
          kind: 'enroll_vantage',
          label: 'Restore this vantage',
          href: '/admin',
        },
      },
    ]
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const path = pathOf(input)
        if (path === '/v1/tests') return jsonResponse({ items: tests })
        if (path.startsWith('/v1/tests/')) {
          const id = path.split('/').pop()
          const test = tests.find((item) => item.id === id)
          return test
            ? jsonResponse(test)
            : jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
        }
        if (path === '/v1/coverage/vantages')
          return jsonResponse({
            items: coverage,
            as_of: '2026-07-26T12:00:00Z',
            evidence_running: true,
            candidate_limit: 5000,
            truncated: false,
          })
        if (path === '/v1/ai/discover') return jsonResponse({ proposals: [] })
        return jsonResponse({ error: { code: 'x', message: 'no route' } }, 404)
      }),
    )

    renderApp('/targets')
    const matrix = await screen.findByRole('table', { name: /owned-vantage coverage matrix/i })
    expect(within(matrix).getByText('Non-redundant')).toBeInTheDocument()
    expect(within(matrix).getByText('Uncovered')).toBeInTheDocument()
    expect(within(matrix).getAllByText('Never')).toHaveLength(2)
    expect(within(matrix).getByText('Gaps observed')).toBeInTheDocument()
    expect(within(matrix).getByText('Never observed')).toBeInTheDocument()
    expect(within(matrix).getByText('Unknown')).toBeInTheDocument()
    expect(within(matrix).getAllByText(/Current local assignment is not verified/)).toHaveLength(3)
    expect(screen.getByText('1 cadence gap')).toBeInTheDocument()
    expect(
      within(matrix).getByRole('button', { name: 'Inspect test edge-dns (t1)' }),
    ).toBeInTheDocument()
    expect(
      within(matrix).getByRole('button', { name: 'Inspect test apac-api (t2)' }),
    ).toBeInTheDocument()
    expect(
      within(matrix).getByRole('button', { name: 'Inspect test legacy-tcp (t4)' }),
    ).toBeInTheDocument()
    expect(
      within(matrix).queryByRole('button', { name: 'Inspect test edge-dns (t3)' }),
    ).not.toBeInTheDocument()
    const mobileT1 = document.querySelector<HTMLElement>(
      '[data-coverage-mobile-record][data-test-id="t1"]',
    )
    const mobileT2 = document.querySelector<HTMLElement>(
      '[data-coverage-mobile-record][data-test-id="t2"]',
    )
    expect(mobileT1).not.toBeNull()
    expect(mobileT2).not.toBeNull()
    expect(mobileT1!.querySelector('[data-coverage-evidence] time')).toHaveAttribute(
      'datetime',
      '2026-07-26T11:59:00.000Z',
    )
    expect(within(mobileT1!).getByText('1 independent vantage')).toBeInTheDocument()
    expect(within(mobileT2!).getByText('Never')).toBeInTheDocument()
    expect(within(mobileT2!).getByText('0 independent vantages')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Coverage state'), 'uncovered')
    expect(within(matrix).getByText('apac-api')).toBeInTheDocument()
    expect(within(matrix).queryByText('edge-dns')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Coverage state'), 'all')
    await user.click(within(matrix).getByRole('button', { name: 'Inspect test edge-dns (t1)' }))
    const inventory = await screen.findByRole('table', { name: 'Synthetic tests' })
    await waitFor(() => expect(within(inventory).getAllByRole('row')).toHaveLength(2))
    expect(within(inventory).getByText('1.1.1.1')).toBeInTheDocument()
    expect(within(inventory).queryByText('9.9.9.9')).not.toBeInTheDocument()
    expect(
      within(inventory).getByRole('button', { name: 'Results for edge-dns' }),
    ).toBeInTheDocument()
    expect(
      within(inventory).getByRole('button', { name: 'View YAML for edge-dns' }),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Author another test' }))
    expect(await screen.findByRole('dialog', { name: /create test/i })).toBeInTheDocument()
  })

  test('fails closed when an exact-ID test lookup is unavailable', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        if (path === '/v1/tests')
          return jsonResponse({
            items: [
              {
                id: 'visible-but-not-requested',
                name: 'same-human-name',
                type: 'dns',
                target: '192.0.2.10',
                interval_seconds: 60,
                timeout_seconds: 3,
                params: {},
                enabled: true,
                created_at: '',
                updated_at: '',
              },
            ],
          })
        if (path === '/v1/tests/missing-id')
          return jsonResponse({ error: { code: 'not_found', message: 'test not found' } }, 404)
        return fallback(input, init)
      }),
    )

    renderApp('/targets?test_id=missing-id')

    expect(
      await screen.findByText(/server did not return an authoritative tenant-scoped result/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/test not found/i)).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'Synthetic tests' })).not.toBeInTheDocument()
    expect(screen.queryByText('192.0.2.10')).not.toBeInTheDocument()
  })

  test.each([
    ['es', 'Brechas detectadas', 'Una o más rondas configuradas no tienen un resultado exacto'],
    ['ar', 'فجوات مرصودة', 'لا توجد نتيجة مطابقة لجولة مهيأة واحدة أو أكثر'],
    [
      'en-xa',
      messages['en-xa']['coverage.cadence.state.gapsObserved'],
      messages['en-xa']['coverage.cadence.reason.missedRounds'],
    ],
  ] as const)(
    'localizes the complete cadence receipt in %s without changing its exact-ID action',
    async (locale, stateLabel, reasonLabel) => {
      const fallback = defaultFetch()
      vi.stubGlobal(
        'fetch',
        vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
          if (pathOf(input) !== '/v1/coverage/vantages') return fallback(input, init)
          return jsonResponse({
            items: [
              {
                test_id: 'localized-test',
                test_name: 'edge-dns',
                region: 'eu-west',
                site: 'dub-1',
                agent_readiness: 'ready',
                agent_count: 1,
                ready_agent_count: 1,
                probe_family: 'dns',
                target: '1.1.1.1',
                independent_vantage_count: 1,
                stale_after_seconds: 300,
                status: 'non_redundant',
                execution_cadence: {
                  state: 'gaps_observed',
                  reason: 'missed_rounds',
                  attribution: 'exact_test_id',
                  configured_interval_seconds: 60,
                  window_seconds: 360,
                  expected_rounds: 6,
                  observed_rounds: 4,
                  missed_rounds: 2,
                  max_gap_seconds: 180,
                  observed_agent_count: 1,
                  history_complete: true,
                  current_assignment_verified: false,
                },
                next_action: {
                  kind: 'author_test',
                  label: 'Author another test',
                  href: '/targets?create=test',
                },
              },
            ],
            as_of: '2026-07-26T12:00:00Z',
            evidence_running: true,
            candidate_limit: 5000,
            truncated: false,
          })
        }),
      )

      renderApp('/targets', { locale })
      await screen.findAllByText(stateLabel)
      const receipt = document.querySelector<HTMLElement>('[data-cadence-receipt]')
      expect(receipt).not.toBeNull()
      expect(receipt).toHaveTextContent(reasonLabel)
      expect(receipt).toHaveTextContent(
        messages[locale as Locale]['coverage.cadence.assignmentCaveat'],
      )
      expect(
        within(receipt!).getByRole('button', {
          name: messages[locale as Locale]['coverage.cadence.inspectTest']
            .replace('{name}', 'edge-dns')
            .replace('{id}', 'localized-test'),
        }),
      ).toBeInTheDocument()

      if (locale === 'ar') expect(document.documentElement).toHaveAttribute('dir', 'rtl')
      if (locale === 'en-xa') {
        expect(receipt).not.toHaveTextContent('Gaps observed')
        expect(receipt).not.toHaveTextContent('One or more configured rounds')
        expect(receipt).not.toHaveTextContent('largest gap')
        expect(receipt).not.toHaveTextContent('complete history')
        expect(receipt).not.toHaveTextContent('Current local assignment')
        expect(receipt).not.toHaveTextContent('Inspect test')
      }
    },
  )

  test('lists, creates, and deletes tests through the UI', async () => {
    const user = userEvent.setup()
    let tests = [
      {
        id: 't1',
        name: 'edge-dns',
        type: 'dns',
        target: '1.1.1.1',
        interval_seconds: 30,
        timeout_seconds: 3,
        params: {},
        enabled: true,
        created_at: '',
        updated_at: '',
      },
    ]
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      const method = init?.method ?? 'GET'
      if (path === '/v1/tests' && method === 'GET') return jsonResponse({ items: tests })
      if (path === '/v1/tests' && method === 'POST') {
        const body = JSON.parse(String(init?.body))
        const created = {
          ...body,
          id: 'new',
          params: body.params ?? {},
          created_at: '',
          updated_at: '',
        }
        tests = [created, ...tests]
        return jsonResponse(created, 201)
      }
      if (/\/v1\/tests\/.+/.test(path) && method === 'DELETE') {
        const id = path.split('/').pop()
        tests = tests.filter((t) => t.id !== id)
        return new Response(null, { status: 204 })
      }
      return jsonResponse({ error: { code: 'x', message: 'no route' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderApp('/targets')
    await screen.findByText('edge-dns')
    const testsHeading = screen.getByRole('heading', { name: /^tests$/i })
    const authoringHeading = screen.getByRole('heading', { name: /author with ai/i })
    expect(
      testsHeading.compareDocumentPosition(authoringHeading) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0)
    expect(screen.queryByText('Demo data')).not.toBeInTheDocument()
    expect(screen.queryByText(/Avg RTT \(24h\)/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/Packet loss \(24h\)/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/^sample$/i)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /new test/i }))
    const dialog = await screen.findByRole('dialog', { name: /create test/i })
    await user.type(within(dialog).getByLabelText('Name'), 'my-test')
    expect(
      within(dialog).getByRole('option', { name: 'HTTP transaction (no rendering)' }),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByRole('option', { name: 'Rendered browser (Playwright)' }),
    ).toBeInTheDocument()
    await user.selectOptions(within(dialog).getByLabelText('Type'), 'browser-rendered')
    await user.type(within(dialog).getByLabelText('Target'), 'https://shop.example/login')
    await user.click(within(dialog).getByRole('button', { name: /^create$/i }))

    // The new row appears (list invalidated + refetched). Assert via its delete
    // action, which is unique to the row (the success toast also says "my-test").
    await screen.findByRole('button', { name: /delete my-test/i })

    const postCall = fetchMock.mock.calls.find(
      ([url, init]) => pathOf(url) === '/v1/tests' && init?.method === 'POST',
    )
    expect(postCall).toBeTruthy()
    const posted = JSON.parse(String((postCall![1] as RequestInit).body))
    expect(posted.name).toBe('my-test')
    expect(posted.type).toBe('browser')
    expect(posted.target).toBe('https://shop.example/login')
    expect(posted.timeout_seconds).toBe(60)
    expect(posted.params.browser_driver).toBe('browser')
    const script = JSON.parse(posted.params.script)
    expect(script.start_url).toBe('https://shop.example/login')
    expect(script.steps.map((step: { action: string }) => step.action)).toEqual([
      'goto',
      'assert_status',
    ])

    await user.click(screen.getByRole('button', { name: /delete my-test/i }))
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /delete my-test/i })).not.toBeInTheDocument(),
    )
  })

  test('loads additional backend cursor pages', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://t.invalid')
      const method = init?.method ?? 'GET'
      if (url.pathname === '/v1/tests' && method === 'GET') {
        const after = url.searchParams.get('after')
        if (!after) {
          return jsonResponse({
            items: [
              {
                id: 't1',
                name: 'first-page',
                type: 'dns',
                target: '1.1.1.1',
                interval_seconds: 30,
                timeout_seconds: 3,
                params: {},
                enabled: true,
                created_at: '',
                updated_at: '',
              },
            ],
            next_cursor: 'cursor-2',
          })
        }
        if (after === 'cursor-2') {
          return jsonResponse({
            items: [
              {
                id: 't2',
                name: 'second-page',
                type: 'icmp',
                target: '9.9.9.9',
                interval_seconds: 60,
                timeout_seconds: 3,
                params: {},
                enabled: true,
                created_at: '',
                updated_at: '',
              },
            ],
          })
        }
      }
      return jsonResponse({ error: { code: 'x', message: 'no route' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderApp('/targets')
    await screen.findByText('first-page')
    expect(screen.queryByText('second-page')).toBeNull()

    await user.click(screen.getByRole('button', { name: /load more tests/i }))

    expect(await screen.findByText('second-page')).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(([input]) => {
        const url = new URL(String(input), 'http://t.invalid')
        return url.pathname === '/v1/tests' && url.searchParams.get('after') === 'cursor-2'
      }),
    ).toBe(true)
  })

  test('shows an error state when the API fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ error: { code: 'internal', message: 'boom' } }, 500)),
    )
    renderApp('/targets')
    expect(await screen.findByText(/boom/i, {}, { timeout: 4000 })).toBeInTheDocument()
  })
})
