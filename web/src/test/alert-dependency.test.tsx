// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { TimeProvider } from '../time/TimeProvider'
import { AlertDependencyDialog } from '../routes/AlertDependencyDialog'
import { jsonResponse } from './fetchStub'

const ruleID = '11111111-1111-4111-8111-111111111111'
const firstID = '22222222-2222-4222-8222-222222222222'
const nextID = '33333333-3333-4333-8333-333333333333'
const grants = [
  'alert.read',
  'alert.write',
  'entities.read',
  'topology.read',
  'test.read',
  'metrics.read',
]
function identity(tenant = 'tenant-a', permissions = grants): AuthContextValue {
  return {
    tenant: { id: tenant, name: tenant, slug: tenant },
    user: { id: `user-${tenant}`, name: 'Operator', email: 'operator@example.test' },
    tenants: [],
    permissions,
    switchTenant: vi.fn(),
    signOut: vi.fn(),
  }
}
function fixture() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const close = vi.fn()
  const view = (auth: AuthContextValue) => (
    <QueryClientProvider client={client}>
      <I18nProvider initialLocale="en">
        <AuthContext.Provider value={auth}>
          <TimeProvider>
            <AlertDependencyDialog
              rule={{
                id: ruleID,
                tenant_id: auth.tenant.id,
                name: 'Reachability',
                metric: 'probectl_probe_success',
                type: 'threshold',
                severity: 'warning',
                enabled: true,
                created_at: '2026-11-12T00:00:00Z',
                updated_at: '2026-11-12T00:00:00Z',
              }}
              onClose={close}
            />
          </TimeProvider>
        </AuthContext.Provider>
      </I18nProvider>
    </QueryClientProvider>
  )
  const rendered = render(view(identity()))
  return { rerender: (auth: AuthContextValue) => rendered.rerender(view(auth)) }
}
function state(configured = false, seconds = 300) {
  return {
    rule_id: ruleID,
    rule_updated_at: '2026-11-12T00:00:00Z',
    configured,
    ...(configured ? { policy: { context_id: firstID, freshness_seconds: seconds } } : {}),
  }
}
function context(tenant: string, id = firstID) {
  return {
    context_id: id,
    tenant_id: tenant,
    site_id: 'site',
    site_label: `Site ${tenant}`,
    vrf_id: 'vrf',
    vrf_label: 'Production',
  }
}

test('dependency context editor keeps later pages and full duration values with explicit save and clear', async () => {
  const calls: Array<{ tenant: string | null; method: string; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input),
        method = init?.method ?? 'GET',
        tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({ tenant, method, body: init?.body ? JSON.parse(String(init.body)) : undefined })
      if (path.includes('/entity-contexts'))
        return jsonResponse(
          path.includes('cursor=')
            ? { items: [context('tenant-a', nextID)] }
            : { items: [context('tenant-a')], next_cursor: 'next-page' },
        )
      if (method === 'PUT')
        return jsonResponse({
          ...state(),
          configured: true,
          policy: JSON.parse(String(init?.body)),
        })
      return jsonResponse(state())
    }),
  )
  const user = userEvent.setup()
  fixture()
  expect(screen.getByText(/Notification holding is not active/)).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Load current dependency settings' }))
  await screen.findByLabelText('Dependency routing context')
  await user.click(screen.getByRole('button', { name: 'Load more contexts' }))
  await screen.findByRole('option', { name: new RegExp(nextID) })
  await user.selectOptions(screen.getByLabelText('Dependency routing context'), nextID)
  fireEvent.change(screen.getByLabelText('Source freshness in seconds'), {
    target: { value: '5000000000' },
  })
  await user.click(screen.getByRole('button', { name: 'Save dependency settings' }))
  await screen.findByText(/Dependency context configured/)
  expect(screen.getByRole('form', { name: 'Dependency settings' })).toHaveFocus()
  expect(calls.find((call) => call.method === 'PUT')?.body).toEqual({
    context_id: nextID,
    freshness_seconds: 5000000000,
  })
  expect(calls.every((call) => call.tenant === 'tenant-a')).toBe(true)
  await user.click(screen.getByRole('button', { name: 'Clear dependency settings' }))
  expect(calls.some((call) => call.method === 'DELETE')).toBe(false)
  await user.click(screen.getByRole('button', { name: 'Clear settings' }))
  await screen.findByText('Dependency settings cleared. Detection keeps running.')
  expect(calls.find((call) => call.method === 'DELETE')?.body).toBeUndefined()
})

test('dependency context response from a previous tenant is discarded and write-only removal reads no old policy', async () => {
  let resolveOld: ((value: Response) => void) | undefined
  const calls: Array<{ tenant: string | null; method: string }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input),
        method = init?.method ?? 'GET',
        tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({ tenant, method })
      if (path.includes('/entity-contexts')) return jsonResponse({ items: [context(tenant ?? '')] })
      if (method === 'GET' && tenant === 'tenant-a')
        return new Promise<Response>((resolve) => {
          resolveOld = resolve
        })
      return jsonResponse(state(method !== 'DELETE', 800))
    }),
  )
  const user = userEvent.setup(),
    view = fixture()
  await user.click(screen.getByRole('button', { name: 'Load current dependency settings' }))
  await waitFor(() => expect(resolveOld).toBeDefined())
  view.rerender(identity('tenant-b'))
  await user.click(screen.getByRole('button', { name: 'Load current dependency settings' }))
  expect(await screen.findByLabelText('Source freshness in seconds')).toHaveValue(800)
  resolveOld?.(jsonResponse(state(true, 1234)))
  await waitFor(() => expect(screen.getByLabelText('Source freshness in seconds')).toHaveValue(800))
  expect(calls.filter((call) => call.tenant === 'tenant-a')).toHaveLength(1)
  view.rerender(identity('tenant-b', ['alert.write']))
  expect(screen.queryByLabelText('Source freshness in seconds')).toBeNull()
  const before = calls.length
  await user.click(screen.getByRole('button', { name: 'Clear dependency settings' }))
  await user.click(screen.getByRole('button', { name: 'Clear settings' }))
  await screen.findByText('Dependency settings cleared. Detection keeps running.')
  expect(calls.slice(before)).toEqual([{ tenant: 'tenant-b', method: 'DELETE' }])
})

test('dependency context editor refuses a foreign context page without publishing partial choices', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) =>
      jsonResponse(
        String(input).includes('/entity-contexts')
          ? { items: [context('tenant-a'), context('tenant-b', nextID)] }
          : state(),
      ),
    ),
  )
  const user = userEvent.setup()
  fixture()
  await user.click(screen.getByRole('button', { name: 'Load current dependency settings' }))
  await screen.findByText(
    'Dependency settings are unavailable. Refresh or check your current source permissions.',
  )
  expect(screen.queryByLabelText('Dependency routing context')).toBeNull()
  expect(screen.queryByText(/Site tenant-b/)).toBeNull()
})
