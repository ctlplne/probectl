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

function fixture(configured = false, createFlow = false) {
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
            rule={createFlow ? undefined : rule}
            onClose={onClose}
          />
        </AuthContext.Provider>
      </QueryClientProvider>
    )
  }
  const rendered = render(
    view('tenant-a', createFlow ? [...grants, 'flow.read', 'ai.query'] : grants),
  )
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
  expect(screen.getByRole('button', { name: 'Save seasonal baseline' })).toHaveFocus()
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
  await user.click(screen.getByRole('button', { name: 'Clear seasonal baseline' }))
  expect(calls).toHaveLength(2)
  await user.click(screen.getByRole('button', { name: 'Clear and disable' }))
  await waitFor(() => expect(view.onClose).toHaveBeenCalledOnce())
  expect(calls).toEqual([
    { method: 'GET', tenant: 'tenant-a' },
    { method: 'GET', tenant: 'tenant-b' },
    { method: 'DELETE', tenant: 'tenant-b' },
  ])
})

test('the saved flow editor binds one moving view and preserves its exact revision', async () => {
  const user = userEvent.setup()
  const edits: unknown[] = []
  const view = {
    id: '33333333-3333-4333-8333-333333333333',
    version: '9007199254740993',
    definition: {
      name: 'Owned throughput',
      time: { mode: 'lookback', lookback_seconds: 600 },
      plan: { metrics: [{ measure: 'bytes', calculation: 'total' }] },
    },
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST') {
        expect(new Headers(init.headers).get('X-Probectl-Tenant')).toBe('tenant-a')
        edits.push(JSON.parse(String(init.body)))
        return jsonResponse({ id: ruleID, tenant_id: 'tenant-a', has_seasonal_source: true })
      }
      if (String(input).includes(view.id)) return jsonResponse(view)
      return jsonResponse({
        items: [
          view,
          {
            id: testID,
            version: '1',
            definition: { name: 'Fixed event window', time: { mode: 'absolute' } },
          },
        ],
      })
    }),
  )
  const rendered = fixture(false, true)
  await screen.findByRole('option', { name: 'Owned throughput' })
  expect(screen.queryByRole('option', { name: 'Fixed event window' })).not.toBeInTheDocument()
  await user.selectOptions(screen.getByRole('combobox', { name: 'Saved flow view' }), view.id)
  await user.selectOptions(screen.getByRole('combobox', { name: 'Flow measure' }), 'bytes:total')
  expect(
    screen.queryByRole('option', { name: 'Hourly (same local minute)' }),
  ).not.toBeInTheDocument()
  await user.selectOptions(screen.getByRole('combobox', { name: 'Learning cadence' }), 'daily')
  await user.selectOptions(screen.getByRole('combobox', { name: 'Alert when values go' }), 'above')
  await user.type(screen.getByRole('textbox', { name: 'Name' }), 'Weekly circuit volume')
  await user.type(screen.getByRole('spinbutton', { name: 'Minimum change' }), '1')
  await user.click(screen.getByRole('button', { name: 'Create seasonal flow alert' }))
  await waitFor(() => expect(rendered.onClose).toHaveBeenCalledOnce())
  expect(edits).toEqual([
    {
      name: 'Weekly circuit volume',
      seasonal_source: {
        cadence: 'daily',
        direction: 'above',
        timezone: 'UTC',
        minimum_change: 1,
        holidays: [],
        flow: { view_id: view.id, view_version: view.version, measure: 'bytes:total' },
      },
    },
  ])
})
