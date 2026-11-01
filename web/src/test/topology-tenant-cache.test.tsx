// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import type { PropsWithChildren } from 'react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, renderHook, screen, waitFor } from '@testing-library/react'
import { test, expect, vi } from 'vitest'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { useTopology } from '../api/topology'
import { Providers } from '../App'
import { TopologyPage } from '../routes/TopologyPage'
import { TimeProvider } from '../time/TimeProvider'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

test('topology canonical cache changes with the authenticated tenant', async () => {
  const tenants = ['00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-000000000102']
  const canonicalIDs = [
    '00000000-0000-4000-8000-000000000301',
    '00000000-0000-4000-8000-000000000302',
  ]
  let selected = 0
  const fetcher = vi.fn(async () =>
    jsonResponse({
      topology_running: true,
      nodes: [
        {
          id: 'hop:10.0.0.1',
          kind: 'hop',
          label: '10.0.0.1',
          canonical_status: 'resolved',
          canonical_entity_id: canonicalIDs[selected],
        },
      ],
      edges: [],
    }),
  )
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({
    defaultOptions: { queries: { staleTime: Infinity, retry: false } },
  })
  function wrapper({ children }: PropsWithChildren) {
    const tenant = { id: tenants[selected], name: 'tenant', slug: 'tenant' }
    const auth: AuthContextValue = {
      user: { id: 'user', name: 'operator', email: 'operator@example.test' },
      tenant,
      tenants: [tenant],
      permissions: ['topology.read', 'entities.read'],
      switchTenant: () => {},
      signOut: () => {},
    }
    return (
      <QueryClientProvider client={client}>
        <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>
      </QueryClientProvider>
    )
  }
  const { result, rerender } = renderHook(() => useTopology(undefined, true, tenants[0]), {
    wrapper,
  })
  await waitFor(() =>
    expect(result.current.data?.nodes[0]?.canonical_entity_id).toBe(canonicalIDs[0]),
  )
  selected = 1
  rerender()
  await waitFor(() =>
    expect(result.current.data?.nodes[0]?.canonical_entity_id).toBe(canonicalIDs[1]),
  )
  expect(fetcher).toHaveBeenCalledTimes(2)
  client.clear()
})

test('a live tenant switch drops the previous topology routing context before another lookup', async () => {
  const tenants = ['00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-000000000102']
  const contextID = '00000000-0000-4000-8000-000000000201'
  let selected = 0
  const requests: { tenant: string; path: string }[] = []
  const fallback = defaultFetch()
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    requests.push({ tenant: tenants[selected], path })
    if (pathOf(input) === '/v1/entity-contexts') {
      return jsonResponse({ items: [], scope: { tenant_id: tenants[selected] } })
    }
    if (pathOf(input) === '/v1/topology') {
      return jsonResponse({ topology_running: true, nodes: [], edges: [] })
    }
    return fallback(input, init)
  })
  function LocationProbe() {
    const location = useLocation()
    return <output data-testid="location">{location.search}</output>
  }
  function view() {
    const tenant = { id: tenants[selected], name: 'tenant', slug: 'tenant' }
    const auth: AuthContextValue = {
      user: { id: 'user', name: 'operator', email: 'operator@example.test' },
      tenant,
      tenants: [tenant],
      permissions: ['topology.read', 'entities.read'],
      switchTenant: () => {},
      signOut: () => {},
    }
    return (
      <Providers>
        <MemoryRouter initialEntries={[`/topology?entity_context=${contextID}`]}>
          <AuthContext.Provider value={auth}>
            <TimeProvider>
              <TopologyPage />
              <LocationProbe />
            </TimeProvider>
          </AuthContext.Provider>
        </MemoryRouter>
      </Providers>
    )
  }
  const { rerender } = render(view())
  await waitFor(() =>
    expect(
      requests.some(
        (item) => item.tenant === tenants[0] && item.path.includes(`context_id=${contextID}`),
      ),
    ).toBe(true),
  )
  selected = 1
  rerender(view())
  await waitFor(() =>
    expect(screen.getByTestId('location')).not.toHaveTextContent('entity_context'),
  )
  await waitFor(() =>
    expect(
      requests.some((item) => item.tenant === tenants[1] && pathOf(item.path) === '/v1/topology'),
    ).toBe(true),
  )
  expect(
    requests
      .filter((item) => item.tenant === tenants[1] && pathOf(item.path) === '/v1/topology')
      .every((item) => !item.path.includes('context_id=')),
  ).toBe(true)
  expect(
    requests.some(
      (item) => item.tenant === tenants[1] && item.path.includes(`context_id=${contextID}`),
    ),
  ).toBe(false)
})
