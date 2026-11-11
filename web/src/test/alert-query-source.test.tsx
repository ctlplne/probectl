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
import { savedQueryAlertMetric, type AlertRule } from '../api/alerts'
import { AlertQuerySourceDialog } from '../routes/AlertQuerySourceDialog'
import { jsonResponse } from './fetchStub'

const ruleID = '11111111-1111-4111-8111-111111111111'
const viewID = '22222222-2222-4222-8222-222222222222'
const grants = ['alert.read', 'alert.write', 'ai.query', 'flow.read']
const revision = '9007199254740993'
const exact = '18446744073709551617'
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
function fixture(creating = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const close = vi.fn()
  const view = (auth: AuthContextValue) => {
    const rule: AlertRule = {
      id: ruleID,
      tenant_id: auth.tenant.id,
      name: 'Source AS',
      enabled: true,
      metric: savedQueryAlertMetric,
      type: 'threshold',
      comparison: 'gte',
      threshold: 1,
      severity: 'warning',
      created_at: '2026-11-12T00:00:00Z',
      updated_at: '2026-11-12T00:00:00Z',
    }
    return (
      <QueryClientProvider client={client}>
        <I18nProvider initialLocale="en">
          <AuthContext.Provider value={auth}>
            <TimeProvider>
              <AlertQuerySourceDialog rule={creating ? undefined : rule} onClose={close} />
            </TimeProvider>
          </AuthContext.Provider>
        </I18nProvider>
      </QueryClientProvider>
    )
  }
  const rendered = render(view(identity()))
  return { close, rerender: (auth: AuthContextValue) => rendered.rerender(view(auth)) }
}
function backend() {
  const calls: Array<{ path: string; method: string; tenant: string | null; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input),
        method = init?.method ?? 'GET',
        tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({
        path,
        method,
        tenant,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      })
      if (path.includes('/explorer/flow-views'))
        return jsonResponse({
          items: [
            {
              id: viewID,
              version: revision,
              owner_id: 'owner',
              definition: {
                name: 'Source AS query',
                plan: { metrics: [{ measure: 'bytes', calculation: 'total', role: 'primary' }] },
              },
            },
          ],
        })
      if (method === 'POST') return jsonResponse({ id: ruleID, name: 'Query alert' }, 201)
      if (method === 'DELETE')
        return jsonResponse({
          rule_id: ruleID,
          configured: false,
          stale_revision: false,
          rule_updated_at: '2026-11-12T00:00:00Z',
        })
      return jsonResponse({
        rule_id: ruleID,
        configured: true,
        stale_revision: false,
        rule_updated_at: '2026-11-12T00:00:00Z',
        source: {
          view_id: viewID,
          view_version: revision,
          every_seconds: 60,
          condition: {
            mode: 'threshold',
            metric: 'bytes:total',
            comparison: 'gt',
            threshold: tenant === 'tenant-b' ? '900' : exact,
          },
        },
      })
    }),
  )
  return calls
}

test('saved-query alert creation preserves exact source revision and decimal threshold', async () => {
  const calls = backend(),
    user = userEvent.setup(),
    view = fixture(true)
  await user.type(screen.getByLabelText('Rule name'), 'Query alert')
  await screen.findByRole('option', { name: `Source AS query · revision ${revision}` })
  await user.selectOptions(screen.getByLabelText('Saved query'), viewID)
  await user.selectOptions(screen.getByLabelText('Condition'), 'threshold')
  fireEvent.change(screen.getByLabelText('Exact decimal threshold'), { target: { value: exact } })
  await user.click(screen.getByRole('button', { name: 'Create query alert' }))
  await waitFor(() => expect(view.close).toHaveBeenCalledOnce())
  const saved = calls.find((call) => call.method === 'POST')
  expect(saved?.tenant).toBe('tenant-a')
  expect(saved?.body).toEqual({
    name: 'Query alert',
    query_source: {
      view_id: viewID,
      view_version: revision,
      every_seconds: 60,
      condition: { mode: 'threshold', metric: 'bytes:total', comparison: 'gt', threshold: exact },
    },
  })
})

test('saved-query editor clears old tenant criteria and retains write-only explicit removal', async () => {
  const calls = backend(),
    user = userEvent.setup(),
    view = fixture()
  await user.click(screen.getByRole('button', { name: 'Load current source' }))
  expect(await screen.findByLabelText('Exact decimal threshold')).toHaveValue(exact)
  view.rerender(identity('tenant-b'))
  expect(screen.queryByLabelText('Exact decimal threshold')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Load current source' }))
  expect(await screen.findByLabelText('Exact decimal threshold')).toHaveValue('900')
  expect(
    calls
      .filter((call) => call.path.endsWith('/query-source') && call.method === 'GET')
      .map((call) => call.tenant),
  ).toEqual(['tenant-a', 'tenant-b'])
  view.rerender(identity('tenant-b', ['alert.write']))
  expect(screen.queryByLabelText('Exact decimal threshold')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Clear source and disable rule' }))
  await user.click(screen.getByRole('button', { name: 'Clear and disable' }))
  await screen.findByText('Source and baseline cleared. The rule is disabled.')
  expect(calls.find((call) => call.method === 'DELETE')?.tenant).toBe('tenant-b')
})
