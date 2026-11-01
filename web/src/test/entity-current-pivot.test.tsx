// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { EntityCurrentPivot, observedIPs } from '../routes/EntityCurrentPivot'
import { jsonResponse, pathOf } from './fetchStub'

test('current pivot offers only bounded literal IPs from authorized rows', () => {
  expect(
    observedIPs([
      { source: '10.42.0.1', malformed: '01.2.3.4', port: '1:2' },
      { source: '10.42.0.1', ipv6: '2001:db8::1', text: 'host.example' },
    ]),
  ).toEqual(['10.42.0.1', '2001:db8::1'])
})

test('current Explorer pivot needs explicit context and never reuses another tenant resolution', async () => {
  const tenants = ['00000000-0000-4000-8000-000000000101', '00000000-0000-4000-8000-000000000102']
  const contexts = ['00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000202']
  const entities = ['00000000-0000-4000-8000-000000000301', '00000000-0000-4000-8000-000000000302']
  const requests: string[] = []
  let selected = 0
  let activeIP = '10.42.0.1'
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const raw = String(input)
      requests.push(raw)
      const path = pathOf(input)
      if (path === '/v1/entity-contexts') {
        return jsonResponse({
          items: [
            {
              tenant_id: tenants[selected],
              context_id: contexts[selected],
              site_id: tenants[selected],
              vrf_id: contexts[selected],
              site_label: tenants[selected],
              vrf_label: contexts[selected],
            },
          ],
        })
      }
      if (path === '/v1/entities/resolve') {
        const url = new URL(raw, 'http://localhost')
        expect(url.searchParams.get('context_id')).toBe(contexts[selected])
        expect(url.searchParams.get('kind')).toBe('address')
        expect(url.searchParams.get('value')).toBe('10.42.0.1')
        return jsonResponse({
          status: 'resolved',
          entity_id: entities[selected],
          candidates: [],
          more_candidates: false,
          scope: { tenant_id: tenants[selected], context_id: contexts[selected] },
          alias: { kind: 'address', value: '10.42.0.1' },
        })
      }
      throw new Error(`unexpected request ${raw}`)
    }),
  )
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  function view() {
    const tenant = { id: tenants[selected], name: 'tenant', slug: 'tenant' }
    const auth: AuthContextValue = {
      user: { id: 'operator', name: 'operator', email: 'operator@example.test' },
      tenant,
      tenants: [tenant],
      permissions: ['entities.read'],
      switchTenant: () => {},
      signOut: () => {},
    }
    return (
      <QueryClientProvider client={client}>
        <I18nProvider initialLocale="en">
          <AuthContext.Provider value={auth}>
            <EntityCurrentPivot
              ips={observedIPs([{ exporter_ip: activeIP, count: 50000 }])}
              source="explorer"
            />
          </AuthContext.Provider>
        </I18nProvider>
      </QueryClientProvider>
    )
  }
  const { rerender } = render(view())
  expect(requests.some((path) => path.includes('/entities/resolve'))).toBe(false)
  await screen.findByRole('option', { name: `${tenants[0]} / ${contexts[0]}` })
  fireEvent.change(screen.getByRole('combobox', { name: 'Observed IP' }), {
    target: { value: '10.42.0.1' },
  })
  fireEvent.change(screen.getByRole('combobox', { name: 'Routing context' }), {
    target: { value: contexts[0] },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Resolve current identity' }))
  expect(await screen.findByText(entities[0])).toBeInTheDocument()
  selected = 1
  rerender(view())
  await screen.findByRole('option', { name: `${tenants[1]} / ${contexts[1]}` })
  await waitFor(() => expect(screen.queryByText(entities[0])).not.toBeInTheDocument())
  fireEvent.change(screen.getByRole('combobox', { name: 'Observed IP' }), {
    target: { value: '10.42.0.1' },
  })
  fireEvent.change(screen.getByRole('combobox', { name: 'Routing context' }), {
    target: { value: contexts[1] },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Resolve current identity' }))
  expect(await screen.findByText(entities[1])).toBeInTheDocument()
  expect(requests.filter((path) => path.includes('/entities/resolve'))).toHaveLength(2)
  expect(requests.every((path) => !path.includes('tenant_id='))).toBe(true)
  activeIP = '10.42.0.2'
  rerender(view())
  expect(screen.queryByText(entities[1])).not.toBeInTheDocument()
  expect(requests.filter((path) => path.includes('/entities/resolve'))).toHaveLength(2)
  const pivot = document.querySelector('[data-entity-current-pivot]')
  expect(pivot).not.toBeNull()
  expect(await axe(pivot as HTMLElement)).toHaveNoViolations()
  client.clear()
})

test('current identity pivot sends no context or resolution request without entities.read', () => {
  const fetcher = vi.fn(async () => {
    throw new Error('unauthorized request')
  })
  vi.stubGlobal('fetch', fetcher)
  const tenant = { id: '00000000-0000-4000-8000-000000000101', name: 'tenant', slug: 'tenant' }
  const auth: AuthContextValue = {
    user: { id: 'viewer', name: 'viewer', email: 'viewer@example.test' },
    tenant,
    tenants: [tenant],
    permissions: ['explorer.read'],
    switchTenant: () => {},
    signOut: () => {},
  }
  const client = new QueryClient()
  render(
    <QueryClientProvider client={client}>
      <I18nProvider initialLocale="en">
        <AuthContext.Provider value={auth}>
          <EntityCurrentPivot ips={['10.42.0.1']} source="explorer" />
        </AuthContext.Provider>
      </I18nProvider>
    </QueryClientProvider>,
  )
  expect(document.querySelector('[data-entity-current-pivot]')).toBeNull()
  expect(fetcher).not.toHaveBeenCalled()
  client.clear()
})
