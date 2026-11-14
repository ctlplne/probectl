// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { ChangeTimelinePage } from '../routes/ChangeTimelinePage'
import type { ChangeEvent } from '../api/incidents'
import { TenantReaderFrame } from './tenantReaderFrame'

const at = '2026-11-14T01:02:03Z'
const item = (tenant: string, id: string): ChangeEvent => ({
  id: `${tenant}-${id}`,
  source: 'generic',
  title: `${tenant} ${id}`,
  kind: 'config',
  occurred_at: at,
})

test('timeline continues past the first page, opens the exact old pair and clears prior-tenant selection before a late response', async () => {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  let tenant = 'primary'
  let finishPaired: ((response: Response) => void) | undefined
  const response = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'https://example.invalid')
    if (url.pathname !== '/v1/changes') throw new Error(`unexpected request ${url.pathname}`)
    if (tenant === 'paired')
      return new Promise<Response>((resolve) => {
        finishPaired = resolve
      })
    const cursor = url.searchParams.get('cursor')
    const rows: ChangeEvent[] = cursor
      ? [
          {
            ...item(tenant, 'old config'),
            config: {
              current_id: 'original-501',
              previous_id: 'original-500',
              current_version: 501,
              previous_version: 500,
              current_hash: 'original-current-hash',
              previous_hash: 'original-prior-hash',
            },
          },
        ]
      : Array.from({ length: 200 }, (_, index) => item(tenant, `change ${index}`))
    return Promise.resolve(
      response({
        items: rows,
        next_cursor: cursor ? '' : 'continue-original-window',
        truncated: !cursor,
        effective_limit: 200,
        change_ingest_configured: true,
        config_archive_running: true,
      }),
    )
  })
  vi.stubGlobal('fetch', fetcher)
  const view = () => (
    <QueryClientProvider client={client}>
      <MemoryRouter
        initialEntries={[
          '/incidents?view=changes&changes_from=2026-11-01T00%3A00%3A00Z&changes_to=2026-11-15T00%3A00%3A00Z',
        ]}
      >
        <TenantReaderFrame tenant={tenant} permissions={['change.read']}>
          <ChangeTimelinePage />
        </TenantReaderFrame>
      </MemoryRouter>
    </QueryClientProvider>
  )
  const user = userEvent.setup()
  const rendered = render(view())
  try {
    await screen.findByText('primary change 199')
    await user.click(screen.getByRole('button', { name: 'Next page' }))
    await user.click(await screen.findByRole('button', { name: 'primary old config' }))
    const diff = screen.getByRole('link', { name: 'Open exact redacted configuration diff' })
    const target = new URL(diff.getAttribute('href') ?? '', 'https://example.invalid')
    expect(target.searchParams.get('config')).toBe('original-501')
    expect(target.searchParams.get('previous_config')).toBe('original-500')
    expect(target.searchParams.get('ctx_return')).toContain('view=changes')
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled()
    tenant = 'paired'
    rendered.rerender(view())
    expect(screen.queryByText('primary old config')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('link', { name: 'Open exact redacted configuration diff' }),
    ).not.toBeInTheDocument()
    await waitFor(() => expect(finishPaired).toBeTypeOf('function'))
    finishPaired?.(
      response({
        items: [item('paired', 'own change')],
        next_cursor: '',
        truncated: false,
        effective_limit: 200,
        change_ingest_configured: true,
        config_archive_running: true,
      }),
    )
    await screen.findByText('paired own change')
    expect(screen.queryByText('primary change 0')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled()
  } finally {
    rendered.unmount()
    client.clear()
    vi.unstubAllGlobals()
  }
})
