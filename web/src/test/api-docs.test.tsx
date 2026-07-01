import { describe, expect, test, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
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
}

function pathnameOf(input: RequestInfo | URL): string {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  return new URL(raw, 'http://probectl.test').pathname
}

describe('native API docs route', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
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
      expect(within(screen.getByRole('table', { name: 'API operations' })).queryByText('/v1/tests')).toBeNull()
      expect(within(screen.getByRole('table', { name: 'API operations' })).getByText('/v1/alerts')).toBeDefined()
    })

    expect(requests).toContain('/openapi.json')
    expect(requests.every((path) => ['/branding', '/v1/me', '/openapi.json'].includes(path))).toBe(true)
  })
})
