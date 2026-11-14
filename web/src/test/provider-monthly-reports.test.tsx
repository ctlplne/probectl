// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { StrictMode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { MonthlyReportsCard } from '../../../ee/web/provider/MonthlyReportsCard'
import { jsonResponse, pathOf } from './fetchStub'

const tenants = [
  { id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', status: 'active' },
  { id: '22222222-2222-4222-8222-222222222222', name: 'Globex', slug: 'globex', status: 'active' },
  {
    id: '33333333-3333-4333-8333-333333333333',
    name: 'Suspended',
    slug: 'suspended',
    status: 'suspended',
  },
]
function mount(readOnly = false) {
  return render(
    <StrictMode>
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <MonthlyReportsCard readOnly={readOnly} />
      </QueryClientProvider>
    </StrictMode>,
  )
}

test('provider fanout keeps a stable retry nonce and reads counts without requeuing', async () => {
  const seen: Array<{ method: string; tenant: string; request?: string }> = []
  let failed = false
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      if (path === '/provider/v1/tenants') return jsonResponse({ items: tenants })
      const match = path.match(/^\/provider\/v1\/tenants\/([^/]+)\/monthly-reports(?:\/([^/]+))?$/)
      if (!match) throw new Error('Unexpected provider route')
      const method = init?.method ?? 'GET'
      const request =
        method === 'POST' ? (JSON.parse(String(init?.body)).request_id as string) : match[2]
      seen.push({ method, tenant: match[1], request })
      if (match[1] === tenants[1].id && !failed) {
        failed = true
        throw new Error('response lost')
      }
      return jsonResponse(
        {
          tenant_id: match[1],
          eligible: 1,
          queued: 1,
          pending: method === 'POST' ? 1 : 0,
          delivered: method === 'GET' ? 1 : 0,
          inactive: 0,
          replay: method === 'GET',
        },
        method === 'POST' ? 202 : 200,
      )
    }),
  )
  mount()
  const user = userEvent.setup()
  await screen.findByLabelText('Select Acme')
  await user.click(screen.getByRole('button', { name: 'Select all active tenants' }))
  expect(screen.getByRole('status')).toHaveTextContent('2 tenants selected')
  expect(screen.queryByLabelText('Select Suspended')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Queue monthly reports' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Retry same report request' })).toBeEnabled(),
  )
  expect(seen).toHaveLength(2)
  const nonce = seen[0].request
  expect(nonce).toMatch(/^[a-f0-9-]{36}$/)
  expect(seen[1].request).toBe(nonce)
  expect(
    screen.getByRole('list', { name: 'Monthly report operational progress' }),
  ).toHaveTextContent('response lost')
  await user.click(screen.getByRole('button', { name: 'Retry same report request' }))
  await waitFor(() => expect(seen).toHaveLength(4))
  expect(seen.every((item) => item.request === nonce)).toBe(true)
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Refresh report progress' })).toBeEnabled(),
  )
  await user.click(screen.getByRole('button', { name: 'Refresh report progress' }))
  await waitFor(() => expect(seen).toHaveLength(6))
  expect(seen.slice(4).map((item) => item.method)).toEqual(['GET', 'GET'])
  expect(
    screen.getByRole('list', { name: 'Monthly report operational progress' }),
  ).toHaveTextContent('1 delivered')
  expect(screen.queryByRole('link')).toBeNull()
})

test('a foreign-tenant response is refused and read-only mode cannot queue', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) =>
      pathOf(input) === '/provider/v1/tenants'
        ? jsonResponse({ items: tenants })
        : jsonResponse(
            {
              tenant_id: tenants[1].id,
              eligible: 1,
              queued: 1,
              pending: 1,
              delivered: 0,
              inactive: 0,
              replay: false,
            },
            202,
          ),
    ),
  )
  const mounted = mount()
  const user = userEvent.setup()
  await user.click(await screen.findByLabelText('Select Acme'))
  await user.click(screen.getByRole('button', { name: 'Queue monthly reports' }))
  await waitFor(() =>
    expect(
      screen.getByRole('list', { name: 'Monthly report operational progress' }),
    ).toHaveTextContent('scope mismatch'),
  )
  mounted.unmount()
  mount(true)
  await screen.findByLabelText('Select Acme')
  expect(screen.getByRole('button', { name: 'Queue monthly reports' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Select all active tenants' })).toBeDisabled()
})
