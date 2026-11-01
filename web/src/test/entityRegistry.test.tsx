// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { axe } from 'jest-axe'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const red = '00000000-0000-4000-8000-000000000101'
const blue = '00000000-0000-4000-8000-000000000102'
const redContext = '00000000-0000-4000-8000-000000000201'
const blueContext = '00000000-0000-4000-8000-000000000202'
const site = '00000000-0000-4000-8000-000000000301'
const vrf = '00000000-0000-4000-8000-000000000302'

function stubRegistry(tenant: string, contextID: string, entityID: string, label: string) {
  const rest = defaultFetch()
  const requests: string[] = []
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    requests.push(String(input))
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            tenant_id: tenant,
            context_id: contextID,
            site_id: site,
            vrf_id: vrf,
            site_label: 'West DC',
            vrf_label: 'Customer A',
          },
        ],
      })
    if (path === '/v1/entities') {
      const url = new URL(String(input), 'http://localhost')
      if (url.searchParams.get('context_id') !== contextID)
        return jsonResponse({ error: { message: 'wrong context' } }, 404)
      return jsonResponse({
        scope: { tenant_id: tenant, context_id: contextID },
        items: [
          {
            id: entityID,
            scope: { tenant_id: tenant, context_id: contextID },
            kind: 'device',
            label,
            created_at: '2026-11-01T00:00:00Z',
            updated_at: '2026-11-01T00:00:00Z',
          },
        ],
      })
    }
    if (path === `/v1/entities/${entityID}`)
      return jsonResponse({
        id: entityID,
        scope: { tenant_id: tenant, context_id: contextID },
        kind: 'device',
        label,
        created_at: '2026-11-01T00:00:00Z',
        updated_at: '2026-11-01T00:00:00Z',
      })
    if (path === `/v1/entities/${entityID}/evidence`)
      return jsonResponse({
        scope: { tenant_id: tenant, context_id: contextID },
        entity_id: entityID,
        items: [
          {
            id: '00000000-0000-4000-8000-000000000401',
            observation_id: '00000000-0000-4000-8000-000000000402',
            alias: { kind: 'address', value: '10.42.0.1' },
            source: 'snmp',
            source_ref: 'snmp:router',
            source_key: {
              agent_id: entityID,
              source_kind: 'device_target',
              source_ref: '10.42.0.1',
            },
            observed_at: '2026-11-01T00:00:00Z',
            current: true,
          },
        ],
      })
    if (path === `/v1/entities/${entityID}/links`)
      return jsonResponse({
        scope: { tenant_id: tenant, context_id: contextID },
        entity_id: entityID,
        items: [],
      })
    return rest(input, init)
  })
  return requests
}

test('Admin entity registry keeps paired tenants in their own context and has named controls', async () => {
  const redRequests = stubRegistry(red, redContext, red, 'Router red')
  const redView = renderApp('/admin', { me: { tenant_id: red, permissions: ['entities.read'] } })
  const redCard = await redView.findByText('Router red')
  expect(redCard).toBeInTheDocument()
  expect(redRequests.some((request) => request.includes('tenant_id='))).toBe(false)
  cleanup()

  const blueRequests = stubRegistry(blue, blueContext, blue, 'Router blue')
  const blueView = renderApp('/admin', { me: { tenant_id: blue, permissions: ['entities.read'] } })
  const card = (await blueView.findByText('Router blue')).closest('[data-entity-registry]')
  expect(card).not.toBeNull()
  expect(within(card as HTMLElement).queryByText('Router red')).not.toBeInTheDocument()
  expect(
    within(card as HTMLElement).getByRole('combobox', { name: 'Routing context' }),
  ).toHaveValue(blueContext)
  expect(
    within(
      within(card as HTMLElement).getByRole('combobox', { name: 'Identifier kind' }),
    ).getByRole('option', { name: 'physical_neighbor_id' }),
  ).toBeInTheDocument()
  expect(blueRequests.some((request) => request.includes('tenant_id='))).toBe(false)
  fireEvent.click(
    within(card as HTMLElement).getByRole('button', { name: 'Inspect device Router blue' }),
  )
  expect(await within(card as HTMLElement).findByText('snmp:router')).toBeInTheDocument()
  expect(within(card as HTMLElement).getByText(/Current/)).toBeInTheDocument()
  expect(blueRequests.some((request) => request.includes('tenant_id='))).toBe(false)
  expect(await axe(card as HTMLElement)).toHaveNoViolations()
})

test('Admin source assignment sends only the chosen context and source, with no tenant hint', async () => {
  const rest = defaultFetch()
  let assigned: Record<string, unknown> | undefined
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            tenant_id: red,
            context_id: redContext,
            site_id: site,
            vrf_id: vrf,
            site_label: 'West DC',
            vrf_label: 'Customer A',
          },
        ],
      })
    if (path === '/v1/entities')
      return jsonResponse({ scope: { tenant_id: red, context_id: redContext }, items: [] })
    if (path === '/v1/entity-source-contexts' && init?.method === 'PUT') {
      assigned = JSON.parse(String(init.body)) as Record<string, unknown>
      return jsonResponse(assigned)
    }
    return rest(input, init)
  })
  const view = renderApp('/admin', {
    me: { tenant_id: red, permissions: ['entities.read', 'agent.write'] },
  })
  const card = (await view.findByText('Canonical entity registry')).closest(
    '[data-entity-registry]',
  ) as HTMLElement
  await waitFor(() =>
    expect(within(card).getByRole('combobox', { name: 'Routing context' })).toHaveValue(redContext),
  )
  fireEvent.change(within(card).getByRole('textbox', { name: 'Registered agent UUID' }), {
    target: { value: red },
  })
  fireEvent.change(within(card).getByRole('textbox', { name: 'Configured source reference' }), {
    target: { value: '10.42.0.1' },
  })
  fireEvent.click(within(card).getByRole('button', { name: 'Assign source' }))
  await waitFor(() =>
    expect(assigned).toEqual({
      agent_id: red,
      source_kind: 'device_target',
      source_ref: '10.42.0.1',
      context_id: redContext,
    }),
  )
})
