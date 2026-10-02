// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import React from 'react'
import { describe, expect, test, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useDeleteMaintenanceWindow } from '../api/alerts'

// WEB-01: a maintenance-window id with a '../' segment must be percent-encoded
// into a single path segment, so the Delete mutation can never be redirected
// into a cross-route, same-origin DELETE (confused deputy).
describe('maintenance window delete encodes the id (WEB-01)', () => {
  test('a traversal id stays a single encoded segment, not a cross-route path', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    )
    const { result } = renderHook(() => useDeleteMaintenanceWindow(), { wrapper })

    const evil = '../../abac/policies/5cc14ff6'
    result.current.mutate(evil)
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('/alerts/maintenance/')
    // The id is encoded (slashes become %2F), so no /abac/policies route appears.
    expect(url).toContain(encodeURIComponent(evil))
    expect(url).not.toContain('/abac/policies')
  })
})
