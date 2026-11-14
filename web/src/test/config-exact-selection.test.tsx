// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { expect, test, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useDeviceConfigs } from '../api/planes'

test('exact old archive pairs have distinct cache identities and request both originals', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'https://example.invalid')
    const ids = url.searchParams.getAll('id')
    return new Response(
      JSON.stringify({
        items: ids.map((id) => ({
          id,
          device: 'old-router',
          version: id.endsWith('before') ? 1 : 2,
          content_hash: id,
          archived_at: '2026-11-14T00:00:00Z',
          drifted: true,
        })),
        archive_running: true,
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )
  })
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  try {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    )
    const result = renderHook(
      ({ lane }) => useDeviceConfigs(2, true, [`${lane}-before`, `${lane}-after`]),
      { initialProps: { lane: 'primary' }, wrapper },
    )
    await waitFor(() => expect(result.result.current.data?.items[0].id).toBe('primary-before'))
    result.rerender({ lane: 'paired' })
    expect(
      result.result.current.data?.items.some((item) => item.id.startsWith('primary')),
    ).not.toBe(true)
    await waitFor(() => expect(result.result.current.data?.items[0].id).toBe('paired-before'))
    const requests = fetcher.mock.calls.map(([input]) =>
      new URL(String(input), 'https://example.invalid').searchParams.getAll('id'),
    )
    expect(requests).toEqual([
      ['primary-before', 'primary-after'],
      ['paired-before', 'paired-after'],
    ])
    result.unmount()
  } finally {
    client.clear()
    vi.unstubAllGlobals()
  }
})
