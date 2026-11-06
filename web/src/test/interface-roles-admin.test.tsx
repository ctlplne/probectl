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

const contextID = '00000000-0000-4000-8000-000000000401'
const interfaceID = '00000000-0000-4000-8000-000000000402'

function roleFixture(tenant: string) {
  const rest = defaultFetch()
  const writes: Record<string, unknown>[] = []
  const resets: Record<string, unknown>[] = []
  const explanationReads: string[] = []
  let explanationStatus = 200
  const policy = {
    tenant_id: tenant,
    context_id: contextID,
    id: `${tenant}-policy`,
    revision: '9007199254740993',
    updated_at: '2026-11-05T00:00:00Z',
    definition: {
      provider_asns: [64500],
      customer_asns: [64501],
      description_rules: Array.from({ length: 31 }, (_, i) => ({
        id: `${tenant}-rule-${i}`,
        pattern: `^${tenant}-uplink-${i}$`,
        role: 'backbone',
      })),
    },
  }
  let override = {
    tenant_id: tenant,
    context_id: contextID,
    interface_id: interfaceID,
    id: `${tenant}-override`,
    revision: '9007199254740993',
    role: 'customer',
    updated_at: '2026-11-05T00:00:00Z',
  }
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
    if (path === '/v1/entities')
      return jsonResponse({
        scope: { tenant_id: tenant, context_id: contextID },
        items: [
          {
            id: interfaceID,
            kind: 'interface',
            label: `${tenant} port`,
            scope: { tenant_id: tenant, context_id: contextID },
          },
        ],
      })
    if (path === `/v1/entity-contexts/${contextID}/interface-role-policy`) {
      if (init?.method === 'PUT') {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>
        writes.push(body)
        return jsonResponse({
          ...policy,
          revision: '9007199254740994',
          definition: body.definition,
        })
      }
      return jsonResponse(policy)
    }
    if (path === `/v1/entity-contexts/${contextID}/interfaces/${interfaceID}/role`) {
      explanationReads.push(tenant)
      if (explanationStatus !== 200)
        return jsonResponse(
          { error: { message: 'Role source access withdrawn' } },
          explanationStatus,
        )
      return jsonResponse({
        tenant_id: tenant,
        context_id: contextID,
        interface_id: interfaceID,
        role: override.role || 'transit',
        reason: override.role ? 'operator_override' : 'current_evidence',
        sources: [`${tenant}/${override.role ? 'override' : 'source'}/${override.revision}`],
        as_of: '2026-11-05T23:00:00Z',
        snmp_current: true,
        prefix_current: true,
      })
    }
    if (path === `/v1/entity-contexts/${contextID}/interfaces/${interfaceID}/role-override`) {
      if (init?.method === 'PUT') {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>
        writes.push(body)
        override = { ...override, role: String(body.role), revision: '9007199254740994' }
        return jsonResponse(override)
      }
      if (init?.method === 'DELETE') {
        resets.push(JSON.parse(String(init.body)) as Record<string, unknown>)
        override = { ...override, id: '', revision: '0', role: '' }
        return new Response(null, { status: 204 })
      }
      return jsonResponse(override)
    }
    return rest(input, init)
  })
  return {
    writes,
    resets,
    policy,
    explanationReads,
    revokeExplanation: () => {
      explanationStatus = 403
    },
  }
}

for (const theme of ['light', 'dark']) {
  test(`complete role configuration retains tenant, order and exact revisions in ${theme}`, async () => {
    for (const tenant of ['tenant-role-a', 'tenant-role-b']) {
      const previous = Object.getOwnPropertyDescriptor(window, 'localStorage')
      Object.defineProperty(window, 'localStorage', {
        configurable: true,
        enumerable: true,
        value: { getItem: () => theme, setItem: vi.fn() },
      })
      try {
        const fixture = roleFixture(tenant)
        const view = renderApp('/admin', {
          me: {
            tenant_id: tenant,
            permissions: ['entities.read', 'agent.write', 'metrics.read', 'events.read'],
          },
        })
        const context = await view.findByRole('combobox', {
          name: 'Interface role routing context',
        })
        const element = context.closest('[data-interface-roles]') as HTMLElement
        const card = within(element)
        await card.findByRole('option', { name: `${tenant} / private` })
        fireEvent.change(context, { target: { value: contextID } })
        const providers = await card.findByRole('textbox', { name: 'Provider ASNs' })
        expect(document.documentElement).toHaveAttribute('data-theme', theme)
        fireEvent.change(providers, { target: { value: '4294967295, 64500' } })
        fireEvent.click(card.getByRole('button', { name: 'Next role rules' }))
        const last = card.getByRole('textbox', { name: 'Description pattern 31' })
        expect(last).toHaveValue(`^${tenant}-uplink-30$`)
        fireEvent.change(last, { target: { value: `^${tenant}-changed$` } })
        fireEvent.click(card.getByRole('button', { name: 'Save complete role policy' }))
        await card.findByText('Complete role policy saved.')
        const saved = fixture.writes[0]
        expect(saved.expected_id).toBe(`${tenant}-policy`)
        expect(saved.expected_revision).toBe('9007199254740993')
        const definition = saved.definition as typeof fixture.policy.definition
        expect(definition.provider_asns).toEqual([4294967295, 64500])
        expect(definition.description_rules).toHaveLength(31)
        expect(definition.description_rules[0]).toEqual(
          fixture.policy.definition.description_rules[0],
        )
        expect(definition.description_rules[30]).toEqual({
          ...fixture.policy.definition.description_rules[30],
          pattern: `^${tenant}-changed$`,
        })
        const choose = card.getByRole('combobox', {
          name: 'Interface for role explanation and override',
        })
        await card.findByRole('option', { name: `${tenant} port (${interfaceID})` })
        fireEvent.change(choose, { target: { value: interfaceID } })
        const explanation = await card.findByRole('region', { name: 'Current interface role' })
        await within(explanation).findByText(`${tenant}/override/9007199254740993`)
        expect(fixture.explanationReads.every((value) => value === tenant)).toBe(true)
        expect(element.textContent).not.toContain(
          tenant === 'tenant-role-a' ? 'tenant-role-b' : 'tenant-role-a',
        )
        const role = await card.findByRole('combobox', { name: 'Manual interface role' })
        fireEvent.change(role, { target: { value: 'transit' } })
        fireEvent.click(card.getByRole('button', { name: 'Save manual role override' }))
        await card.findByText('Manual role override saved.')
        expect(fixture.writes[1]).toEqual({
          expected_id: `${tenant}-override`,
          expected_revision: '9007199254740993',
          role: 'transit',
        })
        fireEvent.click(card.getByRole('button', { name: 'Reset manual role override' }))
        expect(fixture.resets).toHaveLength(0)
        fireEvent.click(await view.findByRole('button', { name: 'Confirm role reset' }))
        await waitFor(() =>
          expect(fixture.resets).toEqual([
            {
              expected_id: `${tenant}-override`,
              expected_revision: '9007199254740994',
              confirmed: true,
            },
          ]),
        )
        await waitFor(() =>
          expect(
            view.queryByRole('dialog', { name: 'Reset manual interface role?' }),
          ).not.toBeInTheDocument(),
        )
        await within(explanation).findByText(`${tenant}/source/0`)
        expect(await axe(element)).toHaveNoViolations()
        fixture.revokeExplanation()
        fireEvent.click(
          within(explanation).getByRole('button', { name: 'Refresh role explanation' }),
        )
        await within(explanation).findByText('Cannot explain the current role')
        expect(within(explanation).queryByText(`${tenant}/source/0`)).not.toBeInTheDocument()
        expect(JSON.stringify(fixture.writes)).not.toContain(
          tenant === 'tenant-role-a' ? 'tenant-role-b' : 'tenant-role-a',
        )
      } finally {
        cleanup()
        vi.unstubAllGlobals()
        if (previous) Object.defineProperty(window, 'localStorage', previous)
      }
    }
  }, 60_000)
}

test('read-only role configuration exposes no mutation controls', async () => {
  const fixture = roleFixture('tenant-reader')
  const view = renderApp('/admin', {
    me: { tenant_id: 'tenant-reader', permissions: ['entities.read'] },
  })
  const context = await view.findByRole('combobox', { name: 'Interface role routing context' })
  const card = within(context.closest('[data-interface-roles]') as HTMLElement)
  await card.findByRole('option', { name: 'tenant-reader / private' })
  fireEvent.change(context, { target: { value: contextID } })
  expect(await card.findByRole('textbox', { name: 'Provider ASNs' })).toHaveAttribute('readonly')
  expect(card.queryByRole('button', { name: 'Save complete role policy' })).not.toBeInTheDocument()
  expect(card.queryByRole('button', { name: 'Add description rule' })).not.toBeInTheDocument()
  const choose = card.getByRole('combobox', { name: 'Interface for role explanation and override' })
  await card.findByRole('option', { name: `tenant-reader port (${interfaceID})` })
  fireEvent.change(choose, { target: { value: interfaceID } })
  await card.findByText('Current role explanations require metrics and events read access.')
  expect(fixture.explanationReads).toEqual([])
  expect(card.queryByRole('button', { name: 'Save manual role override' })).not.toBeInTheDocument()
})
