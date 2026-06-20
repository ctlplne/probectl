import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, pathOf } from './fetchStub'

describe('Targets & Tests (live /v1/tests CRUD)', () => {
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
        const created = { ...body, id: 'new', params: body.params ?? {}, created_at: '', updated_at: '' }
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

    await user.click(screen.getByRole('button', { name: /new test/i }))
    const dialog = await screen.findByRole('dialog', { name: /create test/i })
    await user.type(within(dialog).getByLabelText('Name'), 'my-test')
    await user.selectOptions(within(dialog).getByLabelText('Type'), 'browser')
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
