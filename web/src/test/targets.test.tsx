// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, pathOf } from './fetchStub'

describe('Targets & Tests (live /v1/tests CRUD)', () => {
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
        next_action: {
          kind: 'enroll_vantage',
          label: 'Enroll or restore a vantage',
          href: '/admin',
        },
      },
    ]
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const path = pathOf(input)
        if (path === '/v1/tests') return jsonResponse({ items: tests })
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
    expect(within(matrix).getByText('Never')).toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Coverage state'), 'uncovered')
    expect(within(matrix).getByText('apac-api')).toBeInTheDocument()
    expect(within(matrix).queryByText('edge-dns')).not.toBeInTheDocument()

    await user.selectOptions(screen.getByLabelText('Coverage state'), 'all')
    await user.click(screen.getByRole('button', { name: 'Author another test' }))
    expect(await screen.findByRole('dialog', { name: /create test/i })).toBeInTheDocument()
  })

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
