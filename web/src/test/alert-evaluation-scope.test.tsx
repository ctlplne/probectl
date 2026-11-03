// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { useAlertEvaluations } from '../api/alerts'
import { jsonResponse } from './fetchStub'

const grants = ['alert.read', 'tags.read', 'test.read', 'metrics.read']
function identity(): AuthContextValue {
  return {
    tenant: { id: 'tenant-a', name: 'A', slug: 'a' },
    user: { id: 'user-a', name: 'A', email: 'a@example.test' },
    tenants: [],
    permissions: grants,
    switchTenant: vi.fn(),
    signOut: vi.fn(),
  }
}
function Probe() {
  const result = useAlertEvaluations('11111111-1111-4111-8111-111111111111', 'eval:owned')
  return <output>{result.data?.items[0]?.tag_selection?.tag_revision ?? 'loading'}</output>
}
const response = (revision: string) =>
  jsonResponse({
    contract_version: 'probectl.alert-evaluations/v1',
    tag_selection_access: 'available',
    items: [
      {
        tag_selection: {
          target_kind: 'test',
          tag_revision: revision,
          as_of: '2026-11-03T00:00:00Z',
        },
      },
    ],
  })

test.each(['tenant', 'actor', 'grants'])(
  'receipt cache cannot cross a current %s change',
  async (mode) => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    let release!: (value: Response) => void
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(response('9007199254740993'))
      .mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            release = resolve
          }),
      )
    vi.stubGlobal('fetch', fetcher)
    const view = (auth: AuthContextValue) => (
      <QueryClientProvider client={client}>
        <AuthContext.Provider value={auth}>
          <Probe />
        </AuthContext.Provider>
      </QueryClientProvider>
    )
    const before = identity(),
      mounted = render(view(before))
    await screen.findByText('9007199254740993')
    const after = { ...before }
    if (mode === 'tenant') after.tenant = { ...before.tenant, id: 'tenant-b' }
    if (mode === 'actor') after.user = { ...before.user, id: 'user-b' }
    if (mode === 'grants') after.permissions = ['alert.read']
    mounted.rerender(view(after))
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('9007199254740993')).toBeNull()
    release(response('9007199254740995'))
    await screen.findByText('9007199254740995')
    mounted.unmount()
    client.clear()
  },
)

test('a late receipt response is aborted and cannot publish after actor changes', async () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const pending: Array<(value: Response) => void> = [],
    signals: Array<AbortSignal> = []
  vi.stubGlobal(
    'fetch',
    vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signals.push(init?.signal as AbortSignal)
      return new Promise<Response>((resolve) => pending.push(resolve))
    }),
  )
  const view = (auth: AuthContextValue) => (
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <Probe />
      </AuthContext.Provider>
    </QueryClientProvider>
  )
  const before = identity(),
    mounted = render(view(before))
  await waitFor(() => expect(pending).toHaveLength(1))
  mounted.rerender(view({ ...before, user: { ...before.user, id: 'user-b' } }))
  await waitFor(() => expect(pending).toHaveLength(2))
  expect(signals[0].aborted).toBe(true)
  pending[0](response('9007199254740993'))
  expect(screen.queryByText('9007199254740993')).toBeNull()
  pending[1](response('9007199254740995'))
  await screen.findByText('9007199254740995')
  expect(screen.queryByText('9007199254740993')).toBeNull()
  mounted.unmount()
  client.clear()
})
