// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { TimeProvider } from '../time/TimeProvider'
import { pathHealthAlertMetric, type AlertRule } from '../api/alerts'
import { AlertPathHealthSourceDialog } from '../routes/AlertPathHealthSourceDialog'
import { jsonResponse } from './fetchStub'

const id = '11111111-1111-4111-8111-111111111111'
const interfaceID = '22222222-2222-4222-8222-222222222222'
const grants = ['alert.read', 'alert.write', 'test.read', 'entities.read', 'metrics.read']
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
function source(tenant: string) {
  return {
    test_id: tenant === 'tenant-a' ? id : '33333333-3333-4333-8333-333333333333',
    interface_id: interfaceID,
    metric: 'probectl.device.if.in.fcs.errors' as const,
    lookback_seconds: 86400,
    poll_gap_seconds: 300,
  }
}
function fixture(creating = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const close = vi.fn()
  const view = (auth: AuthContextValue) => {
    const rule: AlertRule = {
      id,
      tenant_id: auth.tenant.id,
      name: 'Owned FCS',
      enabled: true,
      metric: pathHealthAlertMetric,
      type: 'threshold',
      comparison: 'gte',
      threshold: 1,
      severity: 'warning',
      created_at: '2026-11-14T00:00:00Z',
      updated_at: '2026-11-14T00:00:00Z',
    }
    return (
      <QueryClientProvider client={client}>
        <I18nProvider initialLocale="en">
          <AuthContext.Provider value={auth}>
            <TimeProvider>
              <AlertPathHealthSourceDialog
                rule={creating ? undefined : rule}
                initialSource={creating ? source(auth.tenant.id) : undefined}
                onClose={close}
              />
            </TimeProvider>
          </AuthContext.Provider>
        </I18nProvider>
      </QueryClientProvider>
    )
  }
  const rendered = render(view(identity()))
  return { close, rerender: (auth: AuthContextValue) => rendered.rerender(view(auth)) }
}

test('path-error alert creation keeps the selected original counter and canonical parents', async () => {
  const user = userEvent.setup()
  const calls: Array<{ tenant: string | null; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({ tenant, body: JSON.parse(String(init?.body)) })
      return jsonResponse({ id, tenant_id: tenant })
    }),
  )
  const view = fixture(true)
  await user.type(screen.getByLabelText('Rule name'), 'Original FCS climb')
  await user.click(screen.getByRole('button', { name: 'Create path-error alert' }))
  await waitFor(() => expect(view.close).toHaveBeenCalledOnce())
  expect(calls).toEqual([
    {
      tenant: 'tenant-a',
      body: { name: 'Original FCS climb', path_health_source: source('tenant-a') },
    },
  ])
})

test('source editor discards a late tenant result and allows write-only confirmed clearing', async () => {
  const user = userEvent.setup()
  const pending: { release?: (value: Response) => void; signal?: AbortSignal | null } = {}
  const calls: Array<{ method: string; tenant: string | null }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? 'GET',
        tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({ method, tenant })
      if (method === 'GET' && tenant === 'tenant-a') {
        pending.signal = init?.signal
        return new Promise<Response>((resolve) => {
          pending.release = resolve
        })
      }
      return jsonResponse({
        rule_id: id,
        rule_updated_at: '2026-11-14T00:00:00Z',
        configured: method !== 'DELETE',
        ...(method !== 'DELETE' ? { source: source(tenant!) } : {}),
      })
    }),
  )
  const view = fixture()
  await user.click(screen.getByRole('button', { name: 'Read current path source' }))
  view.rerender(identity('tenant-b'))
  expect(pending.signal?.aborted).toBe(true)
  pending.release?.(jsonResponse({ rule_id: id, configured: true, source: source('tenant-a') }))
  await user.click(screen.getByRole('button', { name: 'Read current path source' }))
  expect(await screen.findByLabelText('Owned path test ID')).toHaveValue(source('tenant-b').test_id)
  expect(screen.queryByDisplayValue(source('tenant-a').test_id)).toBeNull()
  view.rerender(identity('tenant-b', ['alert.write']))
  expect(screen.queryByLabelText('Owned path test ID')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Clear source and disable rule' }))
  await user.click(screen.getByRole('button', { name: 'Clear and disable' }))
  expect(await screen.findByRole('status')).toHaveTextContent('Source cleared and rule disabled')
  expect(calls).toEqual([
    { method: 'GET', tenant: 'tenant-a' },
    { method: 'GET', tenant: 'tenant-b' },
    { method: 'DELETE', tenant: 'tenant-b' },
  ])
})
