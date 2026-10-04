// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import React from 'react'
import { describe, expect, test, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useIncident } from '../api/incidents'
import { usePath } from '../api/paths'

// WEB-13: URL-param-derived ids must be percent-encoded into a single path
// segment, so a '../' id cannot traverse to an arbitrary same-origin GET.
describe('client-side path traversal is encoded away (WEB-13)', () => {
  function qcWrapper() {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    return ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
  }

  test('useIncident encodes a traversal id into one segment', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    renderHook(() => useIncident('../x'), { wrapper: qcWrapper() })
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = String((fetchMock.mock.calls[0] as unknown as Parameters<typeof fetch>)[0])
    expect(url).toContain('/incidents/..%2Fx')
    expect(url).not.toContain('/incidents/../')
  })

  test('usePath encodes a traversal testId into one segment', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    renderHook(() => usePath('../x'), { wrapper: qcWrapper() })
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = String((fetchMock.mock.calls[0] as unknown as Parameters<typeof fetch>)[0])
    expect(url).toContain('/tests/..%2Fx/path')
    expect(url).not.toContain('/tests/../')
  })
})
