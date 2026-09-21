// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi, beforeEach } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const openapiDoc = {
  openapi: '3.1.0',
  info: { title: 'probectl API', version: 'test' },
  paths: {
    '/v1/tests': {
      get: {
        operationId: 'listTests',
        summary: 'List tests',
        tags: ['tests'],
        responses: { '200': { description: 'ok' } },
      },
    },
    '/v1/alerts': {
      post: {
        operationId: 'createAlert',
        summary: 'Create an alert rule',
        tags: ['alerts'],
        requestBody: {
          content: {
            'application/json': { schema: { $ref: '#/components/schemas/AlertRequest' } },
          },
        },
        responses: { '201': { description: 'created' }, '422': { description: 'invalid' } },
      },
    },
  },
  components: {
    schemas: {
      AlertRequest: {
        type: 'object',
        properties: {
          name: { type: 'string', example: 'edge latency burn' },
          severity: { type: 'string', enum: ['warning', 'critical'] },
        },
      },
    },
  },
}

function pathnameOf(input: RequestInfo | URL): string {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  return new URL(raw, 'http://probectl.test').pathname
}

describe('native API docs route', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  test('/docs/api keeps day-0 and day-2 operator guidance findable offline', async () => {
    const requests: string[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const path = pathnameOf(input)
      requests.push(path)
      if (path === '/openapi.json') return jsonResponse(openapiDoc)
      return jsonResponse({ error: { code: 'not_found', message: `unstubbed ${path}` } }, 404)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)

    renderApp('/docs/api')

    expect(await screen.findByRole('heading', { name: 'API docs' })).toBeDefined()
    const topicNav = screen.getByRole('navigation', { name: 'Operator guide topics' })
    for (const topic of [
      'Install',
      'First data',
      'Configuration',
      'Security',
      'Limitations',
      'Backup & restore',
      'Upgrade & rollback',
      'Troubleshooting',
      'Editions',
      'Support',
    ]) {
      expect(within(topicNav).getByRole('link', { name: topic })).toBeDefined()
      expect(screen.getByRole('heading', { name: topic })).toBeDefined()
    }

    await userEvent.type(screen.getByLabelText('Filter operator guidance'), 'postgres outage')
    expect(screen.getByRole('heading', { name: 'Troubleshooting' })).toBeDefined()
    expect(screen.queryByRole('heading', { name: 'Install' })).toBeNull()

    expect(
      requests.every((path) =>
        ['/branding', '/v1/me', '/v1/editions', '/openapi.json'].includes(path),
      ),
    ).toBe(true)
  })

  test('/docs/api renders operations from same-origin /openapi.json without external assets', async () => {
    const requests: string[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const path = pathnameOf(input)
      requests.push(path)
      if (path === '/openapi.json') return jsonResponse(openapiDoc)
      return jsonResponse({ error: { code: 'not_found', message: `unstubbed ${path}` } }, 404)
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)

    renderApp('/docs/api')

    const table = await screen.findByRole('table', { name: 'API operations' })
    expect(within(table).getByText('/v1/tests')).toBeDefined()
    expect(within(table).getByText('List tests')).toBeDefined()
    expect(within(table).getByText('/v1/alerts')).toBeDefined()
    expect(await screen.findByText('operationId: createAlert')).toBeDefined()

    await userEvent.type(screen.getByLabelText('Filter operations'), 'alerts')
    await waitFor(() => {
      expect(
        within(screen.getByRole('table', { name: 'API operations' })).queryByText('/v1/tests'),
      ).toBeNull()
      expect(
        within(screen.getByRole('table', { name: 'API operations' })).getByText('/v1/alerts'),
      ).toBeDefined()
    })

    expect(requests).toContain('/openapi.json')
    // Same-origin shell reads only: identity, theming, the license-state
    // banner (edition lifecycle), and the spec itself.
    expect(
      requests.every((path) =>
        ['/branding', '/v1/me', '/v1/editions', '/openapi.json'].includes(path),
      ),
    ).toBe(true)
  })

  test('/docs/api executes a GET with the same-origin session only', async () => {
    const calls: { path: string; init?: RequestInit }[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathnameOf(input)
      calls.push({ path, init })
      if (path === '/openapi.json') return jsonResponse(openapiDoc)
      if (path === '/v1/tests') return jsonResponse({ items: [{ id: 'test-1', name: 'edge-dns' }] })
      return jsonResponse({ ok: true })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)

    renderApp('/docs/api')

    await screen.findByRole('table', { name: 'API operations' })
    await userEvent.click(screen.getByRole('button', { name: 'Open GET /v1/tests' }))
    await waitFor(() => expect(screen.getByDisplayValue('/v1/tests')).toBeDefined())
    await userEvent.click(screen.getByRole('button', { name: 'Run request' }))

    expect(await screen.findByText(/"edge-dns"/)).toBeDefined()
    const apiCall = calls.find((call) => call.path === '/v1/tests')
    expect(apiCall?.init).toMatchObject({ method: 'GET', credentials: 'same-origin' })
    expect(JSON.stringify(apiCall?.init?.headers ?? {})).not.toMatch(/cookie|authorization|bearer/i)
  })

  test('/docs/api generates secret-free POST examples and blocks mutation without confirmation', async () => {
    const calls: { path: string; init?: RequestInit }[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathnameOf(input)
      calls.push({ path, init })
      if (path === '/openapi.json') return jsonResponse(openapiDoc)
      if (path === '/v1/alerts')
        return jsonResponse({ id: 'alert-1', name: 'edge latency burn' }, 201)
      return jsonResponse({ ok: true })
    }) as unknown as typeof fetch
    vi.stubGlobal('fetch', fetcher)

    renderApp('/docs/api')

    const curl = await screen.findByText(/curl -X POST/)
    expect(curl.textContent).toContain('/v1/alerts')
    expect(curl.textContent).toContain('Content-Type: application/json')
    expect(curl.textContent).not.toMatch(/cookie|authorization|bearer|session/i)
    expect(screen.getByText(/credentials: 'same-origin'/)).toBeDefined()

    await userEvent.click(screen.getByRole('button', { name: 'Run request' }))
    expect(await screen.findByRole('alert')).toBeDefined()
    expect(calls.some((call) => call.path === '/v1/alerts')).toBe(false)

    fireEvent.change(screen.getByLabelText('Request body'), {
      target: { value: '{"name":"edge latency burn","severity":"warning"}' },
    })
    await userEvent.type(screen.getByLabelText('Mutation confirmation'), 'RUN')
    await userEvent.click(screen.getByRole('button', { name: 'Run request' }))

    await screen.findByText('201')
    const apiCall = calls.find((call) => call.path === '/v1/alerts')
    expect(apiCall?.init).toMatchObject({
      method: 'POST',
      credentials: 'same-origin',
      body: '{"name":"edge latency burn","severity":"warning"}',
    })
    expect(JSON.stringify(apiCall?.init?.headers ?? {})).not.toMatch(/cookie|authorization|bearer/i)
  })
})
