// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { Providers } from '../App'
import type { ExplorerResult } from '../api/explorer'
import type { FlowQueryPlan } from '../api/flowExplorer'
import { AuthContext } from '../auth/AuthProvider'
import { NativeFlowPage } from '../routes/NativeFlowPage'
import { flowRoleResultReadable } from '../routes/FlowRoleSources'
import flowSchema from './flowExplorerSchema.json'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const grants = ['entities.read', 'metrics.read', 'events.read']
const plan: FlowQueryPlan = {
  from: '2026-11-06T00:00:00Z',
  to: '2026-11-06T01:00:00Z',
  group_by: ['in_if_role', 'out_if_role'],
  view: 'table',
  metrics: [{ measure: 'bytes', calculation: 'total', role: 'primary' }],
}

function roleResult(tenant: string): ExplorerResult {
  return {
    query: {
      source: 'flow',
      flow: plan,
      question: '',
      from: plan.from!,
      to: plan.to!,
      dimensions: [],
      groupings: plan.group_by!,
      measures: ['bytes:total'],
      filters: {},
      visualization: 'table',
      limit: 100,
    },
    preview: '',
    columns: [],
    rows: [],
    suggestions: {},
    evidence_path: '/planes/flow',
    truncated: false,
    flow: {
      query: plan,
      source: 'raw',
      resolution_seconds: 60,
      total_groups: 1,
      detail_limited: false,
      role_digest: 'a'.repeat(64),
      role_tenant_id: tenant,
      role_sources: Array.from({ length: 21 }, (_, i) => ({
        tenant_id: tenant,
        context_id: `${tenant}-context`,
        router_id: `${tenant}-router`,
        interface_id: `${tenant}-interface-${i}`,
        exporter: '192.0.2.1',
        protocol: 'ipfix',
        obs_domain: 4294967295,
        if_index: i + 1,
        role: tenant === 'red' ? 'transit' : 'backbone',
        reason: 'current_evidence',
        sources: [
          `${tenant}-origin-${i}/9007199254740993`,
          `${tenant}-policy-${i}/9007199254740994`,
        ],
        valid_until: '2026-11-06T02:00:00Z',
      })),
      rows: [
        {
          group: { in_if_role: tenant === 'red' ? 'transit' : 'backbone', out_if_role: 'other' },
          other: false,
          metrics: { 'bytes:total': '9007199254740993' },
        },
      ],
      totals: { 'bytes:total': '9007199254740993' },
      series: [],
      other_series: [],
      matrix: [],
    },
  }
}

function Harness({
  tenant = 'red',
  permissions = grants,
}: {
  tenant?: string
  permissions?: string[]
}) {
  return (
    <Providers>
      <MemoryRouter initialEntries={['/explore?native_flow=1']}>
        <AuthContext.Provider
          value={{
            tenant: { id: tenant, name: tenant, slug: tenant },
            tenants: [],
            user: { id: 'operator', name: 'Operator', email: 'roles@local.test' },
            permissions: [
              'flow.read',
              'ai.query',
              'flow.views.write',
              'flow.filters.write',
              ...permissions,
            ],
            switchTenant: () => {},
            signOut: () => {},
          }}
        >
          <NativeFlowPage />
        </AuthContext.Provider>
      </MemoryRouter>
    </Providers>
  )
}

function backend(current: () => string) {
  const base = defaultFetch()
  let denied = false
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/explorer/schema')
      return jsonResponse({ flow: flowSchema, templates: [], visualizations: [], max_rows: 50000 })
    if (path === '/v1/explorer/flow-views' || path === '/v1/explorer/flow-filters')
      return jsonResponse({ items: [] })
    if (path === '/v1/explorer/query')
      return denied
        ? jsonResponse({ error: { message: 'Current role source withdrawn' } }, 403)
        : jsonResponse(roleResult(current()))
    return base(input, init)
  })
  return () => {
    denied = true
  }
}

for (const theme of ['light', 'dark']) {
  test(`complete paired role provenance and source refusal in ${theme}`, async () => {
    const original = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: true,
      value: { getItem: () => theme, setItem: vi.fn() },
    })
    try {
      let tenant = 'red'
      const deny = backend(() => tenant)
      const view = render(<Harness />)
      await userEvent.click(await screen.findByRole('button', { name: 'Run flow query' }))
      await screen.findByRole('heading', { name: 'Frozen flow results' })
      expect(document.documentElement).toHaveAttribute('data-theme', theme)
      fireEvent.click(screen.getByText('Interface role sources (21)'))
      expect(screen.getByText('red-origin-0/9007199254740993')).toBeInTheDocument()
      expect(screen.queryByText('red-origin-20/9007199254740993')).not.toBeInTheDocument()
      await userEvent.click(screen.getByRole('button', { name: 'Next role sources' }))
      expect(screen.getByText('red-origin-20/9007199254740993')).toBeInTheDocument()
      expect(screen.getByText('red-policy-20/9007199254740994')).toBeInTheDocument()
      expect(screen.getByText('Sources 21–21 of 21')).toBeInTheDocument()
      expect(await axe(view.container)).toHaveNoViolations()
      tenant = 'blue'
      view.rerender(<Harness tenant="blue" />)
      expect(screen.queryByRole('heading', { name: 'Frozen flow results' })).not.toBeInTheDocument()
      expect(screen.queryByText(/red-origin-/)).not.toBeInTheDocument()
      await userEvent.click(await screen.findByRole('button', { name: 'Run flow query' }))
      await screen.findByRole('heading', { name: 'Frozen flow results' })
      fireEvent.click(screen.getByText('Interface role sources (21)'))
      expect(screen.getByText('blue-origin-0/9007199254740993')).toBeInTheDocument()
      expect(screen.queryByText(/red-origin-/)).not.toBeInTheDocument()
      expect(await axe(view.container)).toHaveNoViolations()
      deny()
      await userEvent.click(screen.getByRole('button', { name: 'Run flow query' }))
      await screen.findByText(/Current role source withdrawn/)
      expect(screen.queryByRole('heading', { name: 'Frozen flow results' })).not.toBeInTheDocument()
      expect(screen.queryByText(/blue-origin-/)).not.toBeInTheDocument()
    } finally {
      cleanup()
      if (original) Object.defineProperty(window, 'localStorage', original)
    }
  })
}

test.each(grants)(
  'retained role groups disappear immediately when %s is withdrawn',
  async (permission) => {
    backend(() => 'red')
    const view = render(<Harness />)
    await userEvent.click(await screen.findByRole('button', { name: 'Run flow query' }))
    await screen.findByRole('heading', { name: 'Frozen flow results' })
    view.rerender(<Harness permissions={grants.filter((grant) => grant !== permission)} />)
    expect(screen.queryByRole('heading', { name: 'Frozen flow results' })).not.toBeInTheDocument()
    expect(screen.queryByText(/red-origin-/)).not.toBeInTheDocument()
    await waitFor(() =>
      expect(
        screen.getByText(/Interface role access changed; run a fresh query/),
      ).toBeInTheDocument(),
    )
    view.rerender(<Harness />)
    expect(screen.queryByRole('heading', { name: 'Frozen flow results' })).not.toBeInTheDocument()
  },
)

test('foreign or unbound role result is refused as a whole, with no partial sources', () => {
  const own = roleResult('red').flow!
  expect(flowRoleResultReadable(own, 'red', grants)).toBe(true)
  expect(flowRoleResultReadable(own, 'blue', grants)).toBe(false)
  expect(flowRoleResultReadable({ ...own, role_digest: undefined }, 'red', grants)).toBe(false)
  const sources = [...own.role_sources!]
  sources[20] = { ...sources[20], tenant_id: 'blue' }
  expect(flowRoleResultReadable({ ...own, role_sources: sources }, 'red', grants)).toBe(false)
  expect(
    flowRoleResultReadable(
      {
        ...own,
        query: { ...own.query, group_by: ['protocol'] },
        role_digest: undefined,
        role_sources: undefined,
        role_tenant_id: undefined,
      },
      'red',
      [],
    ),
  ).toBe(true)
})
