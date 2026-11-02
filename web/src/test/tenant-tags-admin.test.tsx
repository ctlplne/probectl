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

function tagFetch(capture: { bodies: unknown[]; deleted: string[] }) {
  const base = defaultFetch()
  let tags = [{ id: 'tag-1', tenant_id: tenantID, key: 'customer' }]
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
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('Tenant tag definitions in Admin', () => {
  test('writes only through the authenticated tenant API and confirms destructive deletion', async () => {
    const capture: { bodies: unknown[]; deleted: string[] } = { bodies: [], deleted: [] }
    vi.stubGlobal('fetch', tagFetch(capture))
    const app = renderApp('/admin', { me: { permissions: ['tags.read', 'tags.write'] } })
    const card = (await screen.findByRole('table', { name: 'Tenant tag definitions' })).closest('[data-tenant-tags]')!
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
    const card = table.closest('[data-tenant-tags]')!
    expect(within(card).queryByRole('button', { name: 'Create key' })).not.toBeInTheDocument()
    first.unmount()
    renderApp('/admin', { me: { permissions: [] } })
    expect(screen.queryByRole('table', { name: 'Tenant tag definitions' })).not.toBeInTheDocument()
  })
})
