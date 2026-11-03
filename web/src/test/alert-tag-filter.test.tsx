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
import type { AlertRule, AlertTagFilterState } from '../api/alerts'
import type { FlowQueryFilterGroup } from '../api/flowExplorer'
import { AlertTagFilterDialog } from '../routes/AlertTagFilterDialog'
import { jsonResponse } from './fetchStub'

const ruleID = '11111111-1111-4111-8111-111111111111'
const tagID = '22222222-2222-4222-8222-222222222222'
const revision = '9007199254740993'
const wide = '🌐'.repeat(24000)
const grants = ['alert.read', 'alert.write', 'tags.read', 'test.read', 'metrics.read']

function identity(tenantID = 'tenant-a', permissions = grants): AuthContextValue {
  return {
    tenant: { id: tenantID, name: tenantID, slug: tenantID },
    user: { id: `user-${tenantID}`, name: 'Operator', email: 'operator@example.test' },
    tenants: [],
    permissions,
    switchTenant: vi.fn(),
    signOut: vi.fn(),
  }
}

function fixture(tenant: string, filter: FlowQueryFilterGroup): AlertTagFilterState {
  return {
    rule_id: ruleID,
    has_tag_filter: true,
    tag_filter: {
      version: 1,
      target_kind: 'test',
      owner_user_id: `user-${tenant}`,
      tag_revision: revision,
      as_of: '2026-11-03T00:00:00Z',
      tag_ids: { 'tag.customer': tagID },
      filter,
    },
    editor: {
      tag_revision: revision,
      as_of: '2026-11-03T01:00:00Z',
      fields: [
        {
          name: 'tag.customer',
          tag_id: tagID,
          type: 'text',
          operators: ['eq', 'ne', 'regex', 'not_regex'],
        },
      ],
      limits: {
        max_group_entries: 250,
        max_expanded_conditions: 1000,
        max_filter_depth: 5,
        max_regex_bytes: 1024,
        max_values_per_predicate: 1000,
        max_value_bytes: 65536,
        grammar_bytes: 2 << 20,
      },
    },
  }
}

const nested: FlowQueryFilterGroup = {
  match: 'all',
  groups: [
    { conditions: [{ field: 'tag.customer', op: 'eq', values: [wide] }] },
    {
      mode: 'exclude',
      conditions: [{ field: 'tag.customer', op: 'regex', values: ['excluded$'] }],
    },
  ],
}

function editor(initial = identity()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const rule = (tenant: string): AlertRule => ({
    id: ruleID,
    tenant_id: tenant,
    name: 'Latency',
    enabled: true,
    metric: 'probectl_probe_duration_seconds',
    type: 'threshold',
    severity: 'warning',
    has_tag_filter: true,
    created_at: '2026-11-03T00:00:00Z',
    updated_at: '2026-11-03T00:00:00Z',
  })
  const view = (auth: AuthContextValue) => (
    <QueryClientProvider client={client}>
      <I18nProvider initialLocale="en">
        <AuthContext.Provider value={auth}>
          <TimeProvider>
            <AlertTagFilterDialog rule={rule(auth.tenant.id)} onClose={vi.fn()} />
          </TimeProvider>
        </AuthContext.Provider>
      </I18nProvider>
    </QueryClientProvider>
  )
  const rendered = render(view(initial))
  return (auth: AuthContextValue) => rendered.rerender(view(auth))
}

function backend() {
  const state = { refuse: false, filter: nested, empty: false }
  const calls: Array<{ method: string; tenant: string | null; body: unknown }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toMatch(new RegExp(`/v1/alerts/rules/${ruleID}/tag-filter$`))
      const method = init?.method ?? 'GET'
      const tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      calls.push({ method, tenant, body: init?.body ? JSON.parse(String(init.body)) : undefined })
      if (state.refuse)
        return jsonResponse({ error: { code: 'forbidden', message: 'current read refused' } }, 403)
      if (method === 'DELETE') return new Response(null, { status: 204 })
      if (method === 'PUT') state.filter = JSON.parse(String(init?.body)).filter
      const value = fixture(tenant ?? '', state.filter)
      if (state.empty && value.editor) value.editor.fields = []
      return jsonResponse(value)
    }),
  )
  return { state, calls }
}

test('alert editor preserves complete nested Unicode criteria and exact clocks, then clears on refusal', async () => {
  const { state, calls } = backend()
  const user = userEvent.setup()
  editor()
  await user.click(screen.getByRole('button', { name: 'Load current criteria' }))
  const value = await screen.findByLabelText('Condition 1.1.1 value 1')
  expect(value).toHaveValue(wide)
  expect((value as HTMLInputElement).maxLength).toBeGreaterThanOrEqual(wide.length)
  expect(screen.getAllByText(revision).length).toBe(2)
  expect(screen.queryByRole('button', { name: /Add saved filter/ })).toBeNull()
  expect(screen.getByLabelText('Group 1.2 inclusion')).toHaveValue('exclude')
  fireEvent.change(screen.getByLabelText('Condition 1.2.1 value 1'), {
    target: { value: 'changed$' },
  })
  await user.click(screen.getByRole('button', { name: 'Save current criteria' }))
  await screen.findByLabelText('Condition 1.1.1 value 1')
  const saved = calls.find((call) => call.method === 'PUT')
  expect(saved?.tenant).toBe('tenant-a')
  expect(saved?.body).toEqual({
    target_kind: 'test',
    filter: {
      ...nested,
      groups: [
        nested.groups![0],
        {
          mode: 'exclude',
          conditions: [{ field: 'tag.customer', op: 'regex', values: ['changed$'] }],
        },
      ],
    },
  })
  state.refuse = true
  await user.click(screen.getByRole('button', { name: 'Refresh current criteria' }))
  await screen.findByText(/Previous criteria have been cleared/)
  expect(screen.queryByDisplayValue(wide)).toBeNull()
  expect(screen.queryByText(revision)).toBeNull()
  expect(screen.queryByRole('button', { name: 'Save current criteria' })).toBeNull()
})

test('a writer without metadata reads can explicitly clear without requesting previous criteria', async () => {
  const { calls } = backend()
  const user = userEvent.setup()
  editor(identity('tenant-a', ['alert.read', 'alert.write']))
  expect(screen.queryByRole('button', { name: 'Load current criteria' })).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Clear tag filter' }))
  expect(calls).toHaveLength(0)
  await user.click(screen.getByRole('button', { name: 'Clear criteria' }))
  await screen.findByText(/Tag filter cleared/)
  expect(calls).toEqual([{ method: 'DELETE', tenant: 'tenant-a', body: undefined }])
  expect(screen.queryByDisplayValue(wide)).toBeNull()
})

test('read-only and empty-vocabulary states cannot submit mutations or invent a field', async () => {
  const { state, calls } = backend()
  const user = userEvent.setup()
  const change = editor(
    identity(
      'tenant-a',
      grants.filter((key) => key !== 'alert.write'),
    ),
  )
  await user.click(screen.getByRole('button', { name: 'Load current criteria' }))
  await screen.findByLabelText('Condition 1.1.1 value 1')
  expect(screen.getByRole('button', { name: 'Save current criteria' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Clear tag filter' })).toBeDisabled()
  expect(
    screen.getByLabelText('Condition 1.1.1 value 1').closest('fieldset[disabled]'),
  ).not.toBeNull()
  expect(calls.every((call) => call.method === 'GET')).toBe(true)
  state.empty = true
  change(identity())
  await user.click(screen.getByRole('button', { name: 'Load current criteria' }))
  await screen.findByText('No test tag keys')
  expect(screen.getByRole('button', { name: 'Add condition to group 1' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Save current criteria' })).toBeDisabled()
})

test('a late response cannot cross tenant, actor or current permission changes', async () => {
  let finish!: (response: Response) => void
  const pending = new Promise<Response>((resolve) => {
    finish = resolve
  })
  vi.stubGlobal(
    'fetch',
    vi.fn(() => pending),
  )
  const user = userEvent.setup()
  const change = editor()
  await user.click(screen.getByRole('button', { name: 'Load current criteria' }))
  change(identity('tenant-b'))
  finish(jsonResponse(fixture('tenant-a', nested)))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Load current criteria' })).toBeEnabled(),
  )
  expect(screen.queryByDisplayValue(wide)).toBeNull()
  const { calls } = backend()
  await user.click(screen.getByRole('button', { name: 'Load current criteria' }))
  await screen.findByLabelText('Condition 1.1.1 value 1')
  expect(calls[0].tenant).toBe('tenant-b')
  change({
    ...identity('tenant-b'),
    user: { id: 'new-actor', name: 'New actor', email: 'new@example.test' },
  })
  expect(screen.queryByDisplayValue(wide)).toBeNull()
  change(identity('tenant-b', ['alert.read', 'alert.write']))
  expect(screen.queryByRole('button', { name: 'Load current criteria' })).toBeNull()
  expect(screen.queryByDisplayValue(wide)).toBeNull()
})
