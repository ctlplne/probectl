// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { act, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'
import type { BGPRoutingBindingConfiguration } from '../api/bgpRoutingBindings'

const contextID = '00000000-0000-4000-8000-000000000501'
const routerID = '00000000-0000-4000-8000-000000000502'
const endpoint = `/v1/entity-contexts/${contextID}/bgp-routing-bindings`
function configuration(source = 'origin-a'): BGPRoutingBindingConfiguration {
  return {
    collector_agent_id: 'collector',
    source_ref: source,
    context_id: contextID,
    router_id: routerID,
    manifest: {
      epoch: routerID,
      assigned_at: '2026-11-06T00:00:00Z',
      bindings: [
        {
          id: routerID,
          context_id: contextID,
          router_id: routerID,
          distinguisher: 'ffffffffffffffff',
          bgp_identifier: '0.0.0.0',
          families: [1, 2],
          source_format: 'frr_loc_rib_v1',
        },
      ],
    },
  }
}
function install(tenant: string, pending?: Promise<Response>) {
  const rest = defaultFetch()
  const writes: Record<string, unknown>[] = []
  let current = configuration()
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            tenant_id: tenant,
            context_id: contextID,
            site_id: contextID,
            vrf_id: contextID,
            site_label: tenant,
            vrf_label: 'private',
          },
        ],
      })
    if (path === endpoint) {
      if (init?.method === 'PUT') {
        const body = JSON.parse(String(init.body))
        writes.push(body)
        current = {
          ...current,
          manifest: {
            epoch: `00000000-0000-4000-8000-${String(600 + writes.length).padStart(12, '0')}`,
            assigned_at: '2026-11-06T00:00:01Z',
            bindings: body.bindings,
          },
        }
        return jsonResponse(current)
      }
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
        window.location.href,
      )
      if (pending && url.searchParams.get('source_ref') === 'origin-a') return pending
      return jsonResponse({ ...current, source_ref: url.searchParams.get('source_ref') ?? '' })
    }
    return rest(input, init)
  })
  return writes
}
async function choose(view: ReturnType<typeof renderApp>, tenant: string) {
  const selector = await view.findByRole('combobox', { name: 'Routing binding base context' })
  const card = within(selector.closest('[data-bgp-routing-bindings]') as HTMLElement)
  await card.findByRole('option', { name: `${tenant} / private` })
  fireEvent.change(selector, { target: { value: contextID } })
  fireEvent.change(card.getByRole('textbox', { name: 'Routing collector identity' }), {
    target: { value: 'collector' },
  })
  fireEvent.change(card.getByRole('textbox', { name: 'Routing origin identity' }), {
    target: { value: 'origin-a' },
  })
  return card
}

for (const theme of ['light', 'dark']) {
  for (const tenant of [
    '00000000-0000-4000-8000-000000000701',
    '00000000-0000-4000-8000-000000000702',
  ]) {
    test(`routing bindings preserve complete replacement and confirmed withdrawal ${theme} ${tenant}`, async () => {
      const storage = Object.getOwnPropertyDescriptor(window, 'localStorage')
      Object.defineProperty(window, 'localStorage', {
        configurable: true,
        value: { getItem: () => theme, setItem: vi.fn() },
      })
      try {
        const writes = install(tenant)
        const view = renderApp('/admin', {
          me: { tenant_id: tenant, permissions: ['entities.read', 'agent.write'] },
        })
        const card = await choose(view, tenant)
        fireEvent.click(card.getByRole('button', { name: 'Read current routing bindings' }))
        const editor = await card.findByRole('textbox', { name: 'Complete routing binding array' })
        expect(document.documentElement).toHaveAttribute('data-theme', theme)
        const bindings = configuration().manifest!.bindings
        fireEvent.change(editor, {
          target: {
            value: JSON.stringify([
              ...bindings,
              {
                ...bindings[0],
                id: undefined,
                distinguisher: '0000000000000000',
                bgp_identifier: '192.0.2.1',
              },
            ]),
          },
        })
        fireEvent.click(card.getByRole('button', { name: 'Replace complete routing bindings' }))
        await waitFor(() => expect(writes).toHaveLength(1))
        expect(writes[0]).toMatchObject({
          collector_agent_id: 'collector',
          source_ref: 'origin-a',
          expected_epoch: routerID,
        })
        expect(writes[0].bindings).toHaveLength(2)
        await waitFor(() => expect(editor).not.toHaveAttribute('readonly'))
        expect(await axe(selectorElement(card))).toHaveNoViolations()
        fireEvent.change(editor, { target: { value: '[]' } })
        fireEvent.click(card.getByRole('button', { name: 'Replace complete routing bindings' }))
        const dialog = await view.findByRole('dialog', { name: 'Withdraw all routing bindings?' })
        fireEvent.click(within(dialog).getByRole('button', { name: 'Keep current bindings' }))
        expect(writes).toHaveLength(1)
        fireEvent.click(card.getByRole('button', { name: 'Replace complete routing bindings' }))
        fireEvent.click(
          within(
            await view.findByRole('dialog', { name: 'Withdraw all routing bindings?' }),
          ).getByRole('button', { name: 'Withdraw all routing bindings' }),
        )
        await waitFor(() => expect(writes).toHaveLength(2))
        expect(writes[1].bindings).toEqual([])
      } finally {
        cleanup()
        vi.unstubAllGlobals()
        if (storage) Object.defineProperty(window, 'localStorage', storage)
      }
    })
  }
}
function selectorElement(card: ReturnType<typeof within>) {
  return card
    .getByRole('combobox', { name: 'Routing binding base context' })
    .closest('[data-bgp-routing-bindings]') as HTMLElement
}

test('routing source change rejects a late former-source reply', async () => {
  let resolve!: (response: Response) => void
  const pending = new Promise<Response>((done) => {
    resolve = done
  })
  const tenant = '00000000-0000-4000-8000-000000000703'
  try {
    install(tenant, pending)
    const view = renderApp('/admin', {
      me: { tenant_id: tenant, permissions: ['entities.read', 'agent.write'] },
    })
    const card = await choose(view, tenant)
    fireEvent.click(card.getByRole('button', { name: 'Read current routing bindings' }))
    fireEvent.change(card.getByRole('textbox', { name: 'Routing origin identity' }), {
      target: { value: 'origin-b' },
    })
    fireEvent.click(card.getByRole('button', { name: 'Read current routing bindings' }))
    await card.findByRole('textbox', { name: 'Complete routing binding array' })
    const old = configuration('origin-a')
    old.manifest!.bindings[0].distinguisher = 'aaaaaaaaaaaaaaaa'
    await act(async () => {
      resolve(jsonResponse(old))
      await pending
    })
    expect(
      (card.getByRole('textbox', { name: 'Complete routing binding array' }) as HTMLTextAreaElement)
        .value,
    ).not.toContain('aaaaaaaaaaaaaaaa')
    expect(card.getByRole('textbox', { name: 'Routing origin identity' })).toHaveValue('origin-b')
  } finally {
    cleanup()
    vi.unstubAllGlobals()
  }
})

test('routing configuration readers have no replacement control', async () => {
  const tenant = '00000000-0000-4000-8000-000000000704'
  try {
    const writes = install(tenant)
    const view = renderApp('/admin', { me: { tenant_id: tenant, permissions: ['entities.read'] } })
    const card = await choose(view, tenant)
    fireEvent.click(card.getByRole('button', { name: 'Read current routing bindings' }))
    const editor = await card.findByRole('textbox', { name: 'Complete routing binding array' })
    expect(editor).toHaveAttribute('readonly')
    expect(
      card.queryByRole('button', { name: 'Replace complete routing bindings' }),
    ).not.toBeInTheDocument()
    fireEvent.submit(editor.closest('form')!)
    expect(writes).toHaveLength(0)
  } finally {
    cleanup()
    vi.unstubAllGlobals()
  }
})
