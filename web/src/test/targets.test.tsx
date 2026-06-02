import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

describe('Targets & Tests (live /v1/tests CRUD)', () => {
  test('lists, creates, and deletes tests through the UI', async () => {
    const user = userEvent.setup()
    let tests = [
      {
        id: 't1', name: 'edge-dns', type: 'dns', target: '1.1.1.1',
        interval_seconds: 30, timeout_seconds: 3, params: {}, enabled: true,
        created_at: '', updated_at: '',
      },
    ]
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.endsWith('/v1/tests') && method === 'GET') return jsonResponse({ items: tests })
      if (url.endsWith('/v1/tests') && method === 'POST') {
        const body = JSON.parse(String(init?.body))
        const created = { ...body, id: 'new', params: {}, created_at: '', updated_at: '' }
        tests = [created, ...tests]
        return jsonResponse(created, 201)
      }
      if (/\/v1\/tests\/.+/.test(url) && method === 'DELETE') {
        const id = url.split('/').pop()
        tests = tests.filter((t) => t.id !== id)
        return new Response(null, { status: 204 })
      }
      return jsonResponse({ error: { code: 'x', message: 'no route' } }, 404)
    })
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch)

    renderApp('/targets')
    await screen.findByText('edge-dns')

    await user.click(screen.getByRole('button', { name: /new test/i }))
    const dialog = await screen.findByRole('dialog', { name: /create test/i })
    await user.type(within(dialog).getByLabelText('Name'), 'my-test')
    await user.type(within(dialog).getByLabelText('Target'), '8.8.8.8')
    await user.click(within(dialog).getByRole('button', { name: /^create$/i }))

    // The new row appears (list invalidated + refetched). Assert via its delete
    // action, which is unique to the row (the success toast also says "my-test").
    await screen.findByRole('button', { name: /delete my-test/i })

    const postCall = fetchMock.mock.calls.find(
      ([url, init]) => String(url).endsWith('/v1/tests') && (init as RequestInit | undefined)?.method === 'POST',
    )
    expect(postCall).toBeTruthy()
    expect(String((postCall![1] as RequestInit).body)).toContain('"name":"my-test"')

    await user.click(screen.getByRole('button', { name: /delete my-test/i }))
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /delete my-test/i })).not.toBeInTheDocument(),
    )
  })

  test('shows an error state when the API fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ error: { code: 'internal', message: 'boom' } }, 500)) as unknown as typeof fetch,
    )
    renderApp('/targets')
    expect(await screen.findByText(/boom/i, {}, { timeout: 4000 })).toBeInTheDocument()
  })
})
