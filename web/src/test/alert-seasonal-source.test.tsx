// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import type { AlertRule } from '../api/alerts'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { AlertSeasonalSourceDialog } from '../routes/AlertSeasonalSourceDialog'
import { jsonResponse } from './fetchStub'

const ruleID = '11111111-1111-4111-8111-111111111111'
const testID = '22222222-2222-4222-8222-222222222222'
const grants = ['alert.read', 'alert.write', 'metrics.read', 'test.read']

function fixture(configured = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const onClose = vi.fn()
  const view = (tenant: string, permissions: string[]) => {
    const auth: AuthContextValue = {
      tenant: { id: tenant, name: tenant, slug: tenant },
      user: { id: `user-${tenant}`, name: 'Operator', email: 'operator@example.test' },
      tenants: [],
      permissions,
      switchTenant: vi.fn(),
      signOut: vi.fn(),
    }
    const rule: AlertRule = {
      id: ruleID,
      tenant_id: tenant,
      name: 'Circuit throughput',
      enabled: true,
      metric: 'throughput_bps',
      type: 'baseline',
      comparison: 'gte',
      threshold: 1,
      severity: 'warning',
      created_at: '2026-11-14T00:00:00Z',
      updated_at: '2026-11-14T00:00:00Z',
      has_seasonal_source: configured,
    }
    return (
      <QueryClientProvider client={client}>
        <AuthContext.Provider value={auth}>
          <AlertSeasonalSourceDialog
            key={JSON.stringify([tenant, auth.user.id, permissions.slice().sort()])}
            rule={rule}
            onClose={onClose}
          />
        </AuthContext.Provider>
      </QueryClientProvider>
    )
  }
  const rendered = render(view('tenant-a', grants))
  return {
    onClose,
    rerender: (tenant: string, grants: string[]) => rendered.rerender(view(tenant, grants)),
  }
}

test('the weekly editor saves its configured civil time, holiday dates, floor and owned test', async () => {
  const user = userEvent.setup()
  const edits: unknown[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('X-Probectl-Tenant')).toBe('tenant-a')
      if (init?.method === 'PUT') {
        edits.push(JSON.parse(String(init.body)))
        return jsonResponse({ rule_id: ruleID, configured: true, enabled: true })
      }
      return jsonResponse({ rule_id: ruleID, configured: false, enabled: true })
    }),
  )
  const view = fixture()
  const timezone = await screen.findByRole('textbox', { name: 'Timezone' })
  await user.clear(timezone)
  await user.type(timezone, 'America/New_York')
  await user.type(screen.getByRole('spinbutton', { name: 'Minimum change' }), '2000.5')
  await user.type(
    screen.getByRole('textbox', { name: 'Holiday dates' }),
    '2026-11-26{enter}2026-12-25',
  )
  await user.type(screen.getByRole('textbox', { name: 'Test ID' }), testID)
  await user.tab()
  expect(screen.getByRole('button', { name: 'Save weekly baseline' })).toHaveFocus()
  await user.keyboard('{Enter}')
  await waitFor(() => expect(view.onClose).toHaveBeenCalledOnce())
  expect(edits).toEqual([
    {
      timezone: 'America/New_York',
      minimum_change: 2000.5,
      holidays: ['2026-11-26', '2026-12-25'],
      test_id: testID,
    },
  ])
})

test('a late sibling load is dropped and a write-only user can confirm clearing', async () => {
  const user = userEvent.setup()
  const pending: { release?: (value: Response) => void; signal?: AbortSignal | null } = {}
  const calls: Array<{ method: string; tenant: string | null }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      const tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({ method, tenant })
      if (method === 'GET' && tenant === 'tenant-a') {
        pending.signal = init?.signal
        return new Promise<Response>((resolve) => {
          pending.release = resolve
        })
      }
      return jsonResponse({
        rule_id: ruleID,
        configured: method === 'GET',
        enabled: method === 'GET',
        source: method === 'GET' ? { timezone: 'Europe/London', minimum_change: 1 } : null,
      })
    }),
  )
  const view = fixture(true)
  await waitFor(() => expect(pending.signal).toBeDefined())
  view.rerender('tenant-b', grants)
  expect(pending.signal?.aborted).toBe(true)
  pending.release?.(
    jsonResponse({
      rule_id: ruleID,
      configured: true,
      source: { timezone: 'Asia/Kolkata', minimum_change: 9 },
    }),
  )
  expect(await screen.findByRole('textbox', { name: 'Timezone' })).toHaveValue('Europe/London')
  expect(screen.queryByDisplayValue('Asia/Kolkata')).toBeNull()
  view.rerender('tenant-b', ['alert.write'])
  expect(screen.queryByRole('textbox', { name: 'Timezone' })).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Clear weekly baseline' }))
  expect(calls).toHaveLength(2)
  await user.click(screen.getByRole('button', { name: 'Clear and disable' }))
  await waitFor(() => expect(view.onClose).toHaveBeenCalledOnce())
  expect(calls).toEqual([
    { method: 'GET', tenant: 'tenant-a' },
    { method: 'GET', tenant: 'tenant-b' },
    { method: 'DELETE', tenant: 'tenant-b' },
  ])
})
