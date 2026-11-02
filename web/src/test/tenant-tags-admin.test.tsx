// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

const tenantID = '00000000-0000-0000-0000-000000000001'
const contextID = '00000000-0000-0000-0000-000000000072'

interface TagCapture {
  bodies: unknown[]
  deleted: string[]
  ruleBodies?: unknown[]
  deletedRules?: string[]
  assignmentBodies?: unknown[]
  deletedAssignments?: string[]
}

function tagFetch(capture: TagCapture) {
  const base = defaultFetch()
  let tags = [{ id: 'tag-1', tenant_id: tenantID, key: 'customer' }]
  let rules = [
    {
      id: 'rule-1',
      tenant_id: tenantID,
      context_id: contextID,
      tag_id: 'tag-1',
      target_kind: 'exporter',
      match_kind: 'cidr',
      address_side: 'exporter',
      cidr: '192.0.2.0/24',
      value: 'blue',
      priority: 0,
    },
  ]
  let assignments = [
    {
      id: 'assignment-1',
      tenant_id: tenantID,
      context_id: contextID,
      tag_id: 'tag-1',
      target_kind: 'device',
      target_id: 'device-1',
      value: 'gold',
      source: 'manual',
    },
  ]
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/tags' && method === 'GET') return jsonResponse({ items: tags })
    if (path === '/v1/tags' && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as { key: string }
      capture.bodies.push(body)
      const item = { id: 'tag-2', tenant_id: tenantID, key: body.key }
      tags = [...tags, item]
      return jsonResponse(item, 201)
    }
    if (path === '/v1/tags/tag-1' && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as { key: string }
      capture.bodies.push(body)
      const item = { ...tags[0], key: body.key }
      tags = [item, ...tags.slice(1)]
      return jsonResponse(item)
    }
    if (path === '/v1/tags/tag-1' && method === 'DELETE') {
      capture.deleted.push('tag-1')
      tags = tags.filter((tag) => tag.id !== 'tag-1')
      return jsonResponse(undefined, 204)
    }
    if (path === '/v1/entity-contexts' && method === 'GET')
      return jsonResponse({
        items: [{ context_id: contextID, site_label: 'iad1', vrf_label: 'default' }],
      })
    if (path === `/v1/entity-contexts/${contextID}/tag-rules` && method === 'GET')
      return jsonResponse({ items: rules })
    if (path === `/v1/entity-contexts/${contextID}/tag-rules` && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      capture.ruleBodies?.push(body)
      const item = { id: 'rule-2', tenant_id: tenantID, context_id: contextID, ...body }
      rules = [...rules, item as (typeof rules)[number]]
      return jsonResponse(item, 201)
    }
    if (path === `/v1/entity-contexts/${contextID}/tag-rules/rule-1` && method === 'PUT') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      capture.ruleBodies?.push(body)
      const item = { id: 'rule-1', tenant_id: tenantID, context_id: contextID, ...body }
      rules = [item as (typeof rules)[number], ...rules.slice(1)]
      return jsonResponse(item)
    }
    if (path === `/v1/entity-contexts/${contextID}/tag-rules/rule-1` && method === 'DELETE') {
      capture.deletedRules?.push('rule-1')
      rules = rules.filter((rule) => rule.id !== 'rule-1')
      return jsonResponse(undefined, 204)
    }
    if (path === `/v1/entity-contexts/${contextID}/tag-assignments` && method === 'GET')
      return jsonResponse({ items: assignments })
    if (path === `/v1/entity-contexts/${contextID}/tag-assignments` && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      capture.assignmentBodies?.push(body)
      const item = {
        id: 'assignment-2',
        tenant_id: tenantID,
        context_id: contextID,
        source: 'manual',
        ...body,
      }
      assignments = [...assignments, item as (typeof assignments)[number]]
      return jsonResponse(item, 201)
    }
    if (
      path === `/v1/entity-contexts/${contextID}/tag-assignments/assignment-1` &&
      method === 'PUT'
    ) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>
      capture.assignmentBodies?.push(body)
      const item = {
        id: 'assignment-1',
        tenant_id: tenantID,
        context_id: contextID,
        source: 'manual',
        ...body,
      }
      assignments = [item as (typeof assignments)[number], ...assignments.slice(1)]
      return jsonResponse(item)
    }
    if (
      path === `/v1/entity-contexts/${contextID}/tag-assignments/assignment-1` &&
      method === 'DELETE'
    ) {
      capture.deletedAssignments?.push('assignment-1')
      assignments = assignments.filter((item) => item.id !== 'assignment-1')
      return jsonResponse(undefined, 204)
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('Tenant tag definitions in Admin', () => {
  test('writes only through the authenticated tenant API and confirms destructive deletion', async () => {
    const capture: { bodies: unknown[]; deleted: string[] } = { bodies: [], deleted: [] }
    vi.stubGlobal('fetch', tagFetch(capture))
    const app = renderApp('/admin', { me: { permissions: ['tags.read', 'tags.write'] } })
    const card = (await screen.findByRole('table', { name: 'Tenant tag definitions' })).closest(
      '[data-tenant-tags]',
    ) as HTMLElement
    const table = within(card).getByRole('table', { name: 'Tenant tag definitions' })
    expect(within(table).getByText('customer')).toBeInTheDocument()

    const user = userEvent.setup()
    await user.type(within(card).getByRole('textbox', { name: 'Key' }), 'site')
    await user.click(within(card).getByRole('button', { name: 'Create key' }))
    await waitFor(() => expect(within(table).getByText('site')).toBeInTheDocument())
    expect(capture.bodies).toEqual([{ key: 'site' }])

    await user.click(within(table).getByRole('button', { name: 'Rename tag customer' }))
    await user.clear(within(card).getByRole('textbox', { name: 'New key' }))
    await user.type(within(card).getByRole('textbox', { name: 'New key' }), 'contract')
    await user.click(within(card).getByRole('button', { name: 'Save name' }))
    await waitFor(() => expect(within(table).getByText('contract')).toBeInTheDocument())
    expect(capture.bodies).toEqual([{ key: 'site' }, { key: 'contract' }])

    await user.click(within(table).getByRole('button', { name: 'Delete tag contract' }))
    const dialog = screen.getByRole('dialog', { name: 'Delete tag contract?' })
    expect(capture.deleted).toEqual([])
    await user.click(within(dialog).getByRole('button', { name: 'Delete key and assignments' }))
    await waitFor(() => expect(within(table).queryByText('contract')).not.toBeInTheDocument())
    expect(capture.deleted).toEqual(['tag-1'])
    app.unmount()
  })

  test('read-only tenant has no mutation controls; tenant without tags.read sees no card', async () => {
    vi.stubGlobal('fetch', tagFetch({ bodies: [], deleted: [] }))
    const first = renderApp('/admin', { me: { permissions: ['tags.read'] } })
    const table = await screen.findByRole('table', { name: 'Tenant tag definitions' })
    expect(within(table).getByText('customer')).toBeInTheDocument()
    const card = table.closest('[data-tenant-tags]') as HTMLElement
    expect(within(card).queryByRole('button', { name: 'Create key' })).not.toBeInTheDocument()
    const rules = await screen.findByRole('table', {
      name: 'Tag rules in selected routing context',
    })
    expect(within(rules).getByText('blue')).toBeInTheDocument()
    expect(
      within(rules).queryByRole('button', { name: 'Edit rule rule-1' }),
    ).not.toBeInTheDocument()
    const assignments = await screen.findByRole('table', {
      name: 'Tag assignments in selected routing context',
    })
    expect(within(assignments).getByText('gold')).toBeInTheDocument()
    expect(
      within(assignments).queryByRole('button', { name: 'Edit assignment assignment-1' }),
    ).not.toBeInTheDocument()
    first.unmount()
    renderApp('/admin', { me: { permissions: [] } })
    expect(screen.queryByRole('table', { name: 'Tenant tag definitions' })).not.toBeInTheDocument()
    expect(
      screen.queryByRole('table', { name: 'Tag rules in selected routing context' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('table', { name: 'Tag assignments in selected routing context' }),
    ).not.toBeInTheDocument()
  })

  test('creates, edits and confirms deletion of a context-scoped rule', async () => {
    const capture: TagCapture = { bodies: [], deleted: [], ruleBodies: [], deletedRules: [] }
    vi.stubGlobal('fetch', tagFetch(capture))
    renderApp('/admin', { me: { permissions: ['tags.read', 'tags.write'] } })
    const table = await screen.findByRole('table', {
      name: 'Tag rules in selected routing context',
    })
    const card = table.closest('[data-tenant-tag-rules]') as HTMLElement
    const user = userEvent.setup()
    expect(within(table).getByText('blue')).toBeInTheDocument()

    await user.type(
      await within(card).findByRole('textbox', { name: 'Canonical CIDR' }),
      '198.51.100.0/24',
    )
    await user.type(within(card).getByRole('textbox', { name: 'Tag value' }), 'premium')
    await user.click(within(card).getByRole('button', { name: 'Create rule' }))
    await waitFor(() => expect(within(table).getByText('premium')).toBeInTheDocument())
    expect(capture.ruleBodies?.[0]).toEqual({
      tag_id: 'tag-1',
      target_kind: 'exporter',
      match_kind: 'cidr',
      address_side: 'exporter',
      cidr: '198.51.100.0/24',
      value: 'premium',
      priority: 0,
    })

    await user.click(within(table).getByRole('button', { name: 'Edit rule rule-1' }))
    await user.clear(within(card).getByRole('textbox', { name: 'Tag value' }))
    await user.type(within(card).getByRole('textbox', { name: 'Tag value' }), 'green')
    await user.click(within(card).getByRole('button', { name: 'Save rule' }))
    await waitFor(() => expect(within(table).getByText('green')).toBeInTheDocument())
    expect((capture.ruleBodies?.[1] as { value: string }).value).toBe('green')

    await user.click(within(table).getByRole('button', { name: 'Delete rule rule-1' }))
    expect(capture.deletedRules).toEqual([])
    await user.click(
      within(screen.getByRole('dialog', { name: 'Delete tag rule?' })).getByRole('button', {
        name: 'Delete rule',
      }),
    )
    await waitFor(() => expect(within(table).queryByText('green')).not.toBeInTheDocument())
    expect(capture.deletedRules).toEqual(['rule-1'])
  })

  test('creates, edits and confirms deletion of a tenant-owned manual assignment', async () => {
    const capture: TagCapture = {
      bodies: [],
      deleted: [],
      assignmentBodies: [],
      deletedAssignments: [],
    }
    vi.stubGlobal('fetch', tagFetch(capture))
    renderApp('/admin', { me: { permissions: ['tags.read', 'tags.write'] } })
    const table = await screen.findByRole('table', {
      name: 'Tag assignments in selected routing context',
    })
    const card = table.closest('[data-tenant-tag-assignments]') as HTMLElement
    const user = userEvent.setup()
    expect(within(table).getByText('gold')).toBeInTheDocument()

    await user.type(
      await within(card).findByRole('textbox', { name: 'Owned target ID' }),
      'device-2',
    )
    await user.type(within(card).getByRole('textbox', { name: 'Assignment value' }), 'silver')
    await user.click(within(card).getByRole('button', { name: 'Create assignment' }))
    await waitFor(() => expect(within(table).getByText('silver')).toBeInTheDocument())
    expect(capture.assignmentBodies?.[0]).toEqual({
      tag_id: 'tag-1',
      target_kind: 'device',
      target_id: 'device-2',
      value: 'silver',
    })

    await user.click(within(table).getByRole('button', { name: 'Edit assignment assignment-1' }))
    await user.clear(within(card).getByRole('textbox', { name: 'Assignment value' }))
    await user.type(within(card).getByRole('textbox', { name: 'Assignment value' }), 'platinum')
    await user.click(within(card).getByRole('button', { name: 'Save assignment' }))
    await waitFor(() => expect(within(table).getByText('platinum')).toBeInTheDocument())
    expect((capture.assignmentBodies?.[1] as { value: string }).value).toBe('platinum')

    await user.click(within(table).getByRole('button', { name: 'Delete assignment assignment-1' }))
    expect(capture.deletedAssignments).toEqual([])
    await user.click(
      within(screen.getByRole('dialog', { name: 'Delete manual assignment?' })).getByRole(
        'button',
        { name: 'Delete assignment' },
      ),
    )
    await waitFor(() => expect(within(table).queryByText('platinum')).not.toBeInTheDocument())
    expect(capture.deletedAssignments).toEqual(['assignment-1'])
  })
})
