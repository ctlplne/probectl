// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const contextID = '00000000-0000-4000-8000-000000000201'
const otherContext = '00000000-0000-4000-8000-000000000202'
const entityID = '00000000-0000-4000-8000-000000000301'

function prefixRegistry(tenant: string) {
  const rest = defaultFetch()
  const updates: Record<string, unknown>[] = []
  const creates: Record<string, unknown>[] = []
  let network = '10.2.0.0/24'
  let refuse = false
  const row = () => ({
    id: entityID,
    kind: 'prefix',
    label: `Prefix ${tenant}`,
    scope: { tenant_id: tenant, context_id: contextID },
    network_prefix: network,
    created_at: '2026-11-03T00:00:00Z',
    updated_at: '2026-11-03T00:00:00Z',
  })
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [contextID, otherContext].map((id) => ({
          tenant_id: tenant,
          context_id: id,
          site_id: id,
          vrf_id: id,
          site_label: 'West DC',
          vrf_label: id === contextID ? 'Private' : 'Other',
        })),
      })
    if (path === `/v1/entities/${entityID}/network-prefix` && init?.method === 'PUT') {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      updates.push(body)
      if (refuse) return jsonResponse({ error: { message: 'Network change denied' } }, 403)
      network = String(body.network_prefix)
      return jsonResponse(row())
    }
    if (path === '/v1/entities' && init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      creates.push(body)
      return jsonResponse({ ...row(), id: '00000000-0000-4000-8000-000000000302', ...body }, 201)
    }
    if (path === '/v1/entities') {
      const chosen = new URL(String(input), 'http://localhost').searchParams.get('context_id')
      return jsonResponse({
        scope: { tenant_id: tenant, context_id: chosen },
        items: chosen === contextID ? [row()] : [],
      })
    }
    if (path === `/v1/entities/${entityID}`) return jsonResponse(row())
    if (path === `/v1/entities/${entityID}/evidence` || path === `/v1/entities/${entityID}/links`)
      return jsonResponse({
        scope: { tenant_id: tenant, context_id: contextID },
        entity_id: entityID,
        items: [],
      })
    return rest(input, init)
  })
  return {
    updates,
    creates,
    deny: () => {
      refuse = true
    },
  }
}

for (const theme of ['light', 'dark'] as const) {
  for (const tenant of [
    '00000000-0000-4000-8000-000000000101',
    '00000000-0000-4000-8000-000000000102',
  ]) {
    test(`prefix network editor preserves owned identity and clears old context state: ${theme} ${tenant}`, async () => {
      const storage = Object.getOwnPropertyDescriptor(window, 'localStorage')
      Object.defineProperty(window, 'localStorage', {
        configurable: true,
        enumerable: true,
        value: { getItem: () => theme, setItem: vi.fn() },
      })
      try {
        const state = prefixRegistry(tenant)
        const view = renderApp('/admin', {
          me: { tenant_id: tenant, permissions: ['entities.read', 'agent.write'] },
        })
        const inspect = await view.findByRole('button', { name: `Inspect prefix Prefix ${tenant}` })
        const cardElement = inspect.closest('[data-entity-registry]') as HTMLElement
        const card = within(cardElement)
        fireEvent.click(inspect)
        let editor = await card.findByRole('textbox', {
          name: 'Network range (CIDR, empty clears)',
        })
        await waitFor(() => expect(editor).toHaveValue('10.2.0.0/24'))
        expect(document.documentElement).toHaveAttribute('data-theme', theme)
        fireEvent.change(editor, { target: { value: '2001:db8::/32' } })
        fireEvent.click(card.getByRole('button', { name: 'Save network range' }))
        await card.findByText('Network range saved.')
        expect(state.updates).toEqual([{ context_id: contextID, network_prefix: '2001:db8::/32' }])
        fireEvent.change(editor, { target: { value: '' } })
        fireEvent.click(card.getByRole('button', { name: 'Save network range' }))
        await waitFor(() => expect(state.updates).toHaveLength(2))
        await waitFor(() =>
          expect(card.getByRole('button', { name: 'Save network range' })).toBeEnabled(),
        )
        expect(state.updates[1]).toEqual({ context_id: contextID, network_prefix: '' })
        fireEvent.change(card.getByRole('combobox', { name: 'Kind' }), {
          target: { value: 'prefix' },
        })
        fireEvent.change(card.getByRole('textbox', { name: 'Label' }), {
          target: { value: 'New explicit prefix' },
        })
        fireEvent.change(card.getByRole('textbox', { name: 'Network range (CIDR, optional)' }), {
          target: { value: '192.0.2.0/24' },
        })
        fireEvent.click(card.getByRole('button', { name: 'Create entity' }))
        await waitFor(() => expect(state.creates).toHaveLength(1))
        expect(state.creates[0]).toEqual({
          context_id: contextID,
          kind: 'prefix',
          label: 'New explicit prefix',
          network_prefix: '192.0.2.0/24',
        })
        await waitFor(() =>
          expect(card.getByRole('textbox', { name: 'Network range (CIDR, optional)' })).toHaveValue(
            '',
          ),
        )
        fireEvent.click(
          await card.findByRole('button', { name: `Inspect prefix Prefix ${tenant}` }),
        )
        editor = await card.findByRole('textbox', {
          name: 'Network range (CIDR, empty clears)',
        })
        state.deny()
        fireEvent.change(editor, { target: { value: '203.0.113.0/24' } })
        fireEvent.click(card.getByRole('button', { name: 'Save network range' }))
        await card.findByText('Network change denied')
        fireEvent.change(card.getByRole('combobox', { name: 'Routing context' }), {
          target: { value: otherContext },
        })
        await waitFor(() =>
          expect(card.queryByText('Network change denied')).not.toBeInTheDocument(),
        )
        expect(card.queryByText('Network range saved.')).not.toBeInTheDocument()
        expect(
          card.queryByRole('textbox', { name: 'Network range (CIDR, empty clears)' }),
        ).not.toBeInTheDocument()
        fireEvent.change(card.getByRole('combobox', { name: 'Routing context' }), {
          target: { value: contextID },
        })
        fireEvent.click(
          await card.findByRole('button', { name: `Inspect prefix Prefix ${tenant}` }),
        )
        await waitFor(() =>
          expect(
            card.getByRole('textbox', { name: 'Network range (CIDR, empty clears)' }),
          ).toHaveValue(''),
        )
        expect(cardElement).toBeInTheDocument()
        expect(await axe(cardElement)).toHaveNoViolations()
      } finally {
        cleanup()
        if (storage) Object.defineProperty(window, 'localStorage', storage)
        else Reflect.deleteProperty(window, 'localStorage')
      }
    })
  }
}

test('prefix network reader sees the range and has no mutation controls', async () => {
  const tenant = '00000000-0000-4000-8000-000000000101'
  const state = prefixRegistry(tenant)
  const view = renderApp('/admin', { me: { tenant_id: tenant, permissions: ['entities.read'] } })
  fireEvent.click(await view.findByRole('button', { name: `Inspect prefix Prefix ${tenant}` }))
  expect(await view.findByText('10.2.0.0/24')).toBeInTheDocument()
  expect(view.queryByRole('button', { name: 'Save network range' })).not.toBeInTheDocument()
  expect(state.updates).toEqual([])
})
