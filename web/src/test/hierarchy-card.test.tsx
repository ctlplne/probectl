// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { flattenHierarchy } from '../routes/admin/hierarchyTree'
import type { Hierarchy } from '../api/hierarchy'

const TENANT = '00000000-0000-0000-0000-000000000001'

const tree: Hierarchy = {
  items: [
    {
      id: 'org-1',
      tenant_id: TENANT,
      slug: 'acme-platform',
      name: 'Platform Engineering',
      created_at: '2026-05-02T09:00:00Z',
      updated_at: '2026-06-01T10:15:00Z',
      teams: [
        {
          id: 'team-1',
          tenant_id: TENANT,
          org_id: 'org-1',
          slug: 'network-observability',
          name: 'Network Observability',
          created_at: '2026-05-02T09:05:00Z',
          updated_at: '2026-06-01T10:15:00Z',
          projects: [
            {
              id: 'project-1',
              tenant_id: TENANT,
              team_id: 'team-1',
              slug: 'checkout-slo',
              name: 'Checkout SLO',
              created_at: '2026-05-02T09:10:00Z',
              updated_at: '2026-06-01T10:15:00Z',
            },
          ],
        },
      ],
    },
  ],
}

/** A stateful hierarchy backend: GET serves the tree, POST appends to it. */
function hierarchyFetch(options: { empty?: boolean; createStatus?: number; wire?: unknown } = {}) {
  const base = defaultFetch()
  let state: Hierarchy = options.empty ? { items: [] } : structuredClone(tree)
  const calls: Array<{ path: string; body: unknown }> = []
  const stub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/hierarchy' && method === 'GET') {
      return jsonResponse(options.wire ?? state)
    }
    if (path.startsWith('/v1/hierarchy/') && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as { slug: string; name: string }
      calls.push({ path, body })
      if (options.createStatus) {
        return new Response(
          JSON.stringify({ error: { message: 'organization slug already exists' } }),
          { status: options.createStatus, headers: { 'Content-Type': 'application/json' } },
        )
      }
      if (path === '/v1/hierarchy/orgs') {
        const org = {
          id: `org-${state.items.length + 2}`,
          tenant_id: TENANT,
          slug: body.slug,
          name: body.name,
          created_at: '2026-06-02T09:00:00Z',
          updated_at: '2026-06-02T09:00:00Z',
          teams: [],
        }
        state = { items: [...state.items, org] }
        return jsonResponse(org, 201)
      }
      const team = {
        id: 'team-2',
        tenant_id: TENANT,
        org_id: 'org-1',
        slug: body.slug,
        name: body.name,
        created_at: '2026-06-02T09:00:00Z',
        updated_at: '2026-06-02T09:00:00Z',
        projects: [],
      }
      state = {
        items: state.items.map((org) =>
          org.id === 'org-1' ? { ...org, teams: [...org.teams, team] } : org,
        ),
      }
      return jsonResponse(team, 201)
    }
    return base(input, init)
  })
  return { stub, calls }
}

/**
 * DPR-254 (F24): the hierarchy API and CLI existed with no screen, so a tenant
 * administrator could only see and change the structure their roles and ABAC
 * rules are written against from a terminal.
 */
describe('tenant hierarchy card', () => {
  test('flattens every level in tree order so the table is one scan', () => {
    expect(flattenHierarchy(tree).map((row) => `${row.level}:${row.slug}`)).toEqual([
      'organization:acme-platform',
      'team:network-observability',
      'project:checkout-slo',
    ])
  })

  test('renders organizations, teams and projects with what each sits within', async () => {
    const { stub } = hierarchyFetch()
    vi.stubGlobal('fetch', stub)
    renderApp('/admin', { me: { permissions: ['org.read'] } })

    const table = await screen.findByRole('table', {
      name: /Tenant organization, team and project hierarchy/i,
    })
    expect(table).toHaveTextContent('Platform Engineering')
    expect(table).toHaveTextContent('Network Observability')
    expect(table).toHaveTextContent('Checkout SLO')
    // A project names its team, a team names its organization, an org names the tenant.
    expect(within(table).getByText('the tenant')).toBeInTheDocument()
  })

  test('creates an organization and shows it without a manual reload', async () => {
    const { stub, calls } = hierarchyFetch()
    vi.stubGlobal('fetch', stub)
    const user = userEvent.setup()
    renderApp('/admin', { me: { permissions: ['org.read', 'org.write'] } })

    await screen.findByRole('table', { name: /Tenant organization, team and project/i })
    await user.type(screen.getByLabelText('Name'), 'Security Engineering')
    await user.type(screen.getByLabelText('Slug'), 'sec-eng')
    await user.click(screen.getByRole('button', { name: /Create organization/i }))

    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0]).toEqual({
      path: '/v1/hierarchy/orgs',
      body: { name: 'Security Engineering', slug: 'sec-eng' },
    })
    await waitFor(() => expect(screen.getByText('Security Engineering')).toBeInTheDocument())
  })

  test('a team needs its organization chosen, and says so instead of guessing one', async () => {
    const { stub, calls } = hierarchyFetch()
    vi.stubGlobal('fetch', stub)
    const user = userEvent.setup()
    renderApp('/admin', { me: { permissions: ['org.read', 'org.write'] } })

    await screen.findByRole('table', { name: /Tenant organization, team and project/i })
    await user.selectOptions(screen.getByLabelText('Level'), 'team')
    await user.type(screen.getByLabelText('Name'), 'Threat Detection')
    await user.type(screen.getByLabelText('Slug'), 'threat-det')
    await user.click(screen.getByRole('button', { name: /Create team/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /Choose the organization this team belongs to/i,
    )
    expect(calls, 'no request may be sent without a parent').toHaveLength(0)

    await user.selectOptions(screen.getByLabelText('Within organization'), 'org-1')
    await user.click(screen.getByRole('button', { name: /Create team/i }))
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0].path).toBe('/v1/hierarchy/orgs/org-1/teams')
  })

  test("the server's own refusal is shown, not a generic failure", async () => {
    const { stub } = hierarchyFetch({ createStatus: 409 })
    vi.stubGlobal('fetch', stub)
    const user = userEvent.setup()
    renderApp('/admin', { me: { permissions: ['org.read', 'org.write'] } })

    await screen.findByRole('table', { name: /Tenant organization, team and project/i })
    await user.type(screen.getByLabelText('Name'), 'Platform Engineering')
    await user.type(screen.getByLabelText('Slug'), 'acme-platform')
    await user.click(screen.getByRole('button', { name: /Create organization/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/organization slug already exists/i)
  })

  test('an empty tree says ABAC may be withholding branches, not that the tenant is flat', async () => {
    const { stub } = hierarchyFetch({ empty: true })
    vi.stubGlobal('fetch', stub)
    renderApp('/admin', { me: { permissions: ['org.read'] } })

    expect(await screen.findByText('No organizations yet')).toBeInTheDocument()
    expect(screen.getByText(/ABAC withholds every branch/i)).toBeInTheDocument()
    expect(screen.getByText(/never the whole tenant/i)).toBeInTheDocument()
  })

  test('a server that omits empty arrays does not drop a level from the tree', async () => {
    // The wire form may send an organization with no `teams` key at all; the
    // organization must still appear rather than vanishing from the table.
    const { stub } = hierarchyFetch({
      wire: {
        items: [
          {
            id: 'org-9',
            tenant_id: TENANT,
            slug: 'lean-org',
            name: 'Lean Org',
            created_at: '2026-05-02T09:00:00Z',
            updated_at: '2026-06-01T10:15:00Z',
          },
        ],
      },
    })
    vi.stubGlobal('fetch', stub)
    renderApp('/admin', { me: { permissions: ['org.read'] } })

    const table = await screen.findByRole('table', {
      name: /Tenant organization, team and project hierarchy/i,
    })
    expect(table).toHaveTextContent('Lean Org')
  })
})
