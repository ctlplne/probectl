// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch } from './fetchStub'
import { renderApp } from './renderApp'

/** DPR-027: a tenant administrator manages people and roles in Admin → Identity
 * without SCIM: add a teammate with a role, grant another, revoke one, and be
 * refused when removing the last administrator. */
describe('people & roles', () => {
  test('lists people with their roles and adds a teammate with a role', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin', {
      me: { permissions: ['directory.read', 'directory.write', 'audit.read'] },
    })
    const table = await screen.findByRole('table', { name: 'People & roles' })
    expect(within(table).getByText('operator@probectl.test')).toBeInTheDocument()
    expect(within(table).getByText('viewer@probectl.test')).toBeInTheDocument()

    const form = screen.getByRole('form', { name: 'Grant a role' })
    await userEvent.type(within(form).getByLabelText('Teammate email'), 'ada@example.com')
    await userEvent.selectOptions(within(form).getByLabelText('Role'), 'editor')
    await userEvent.click(within(form).getByRole('button', { name: 'Grant' }))
    const row = await within(table).findByText('ada@example.com')
    expect(row.closest('tr')).toHaveTextContent('editor')
  })

  test('grants and revokes a role, and refuses to remove the last administrator', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin', {
      me: { permissions: ['directory.read', 'directory.write', 'audit.read'] },
    })
    const table = await screen.findByRole('table', { name: 'People & roles' })
    const form = screen.getByRole('form', { name: 'Grant a role' })
    await userEvent.type(within(form).getByLabelText('Teammate email'), 'viewer@probectl.test')
    await userEvent.selectOptions(within(form).getByLabelText('Role'), 'editor')
    await userEvent.click(within(form).getByRole('button', { name: 'Grant' }))
    await waitFor(() =>
      expect(
        within(table).getByRole('button', { name: 'Remove editor from viewer@probectl.test' }),
      ).toBeInTheDocument(),
    )
    await userEvent.click(
      within(table).getByRole('button', { name: 'Remove editor from viewer@probectl.test' }),
    )
    // WEB-21/G8: removing a role is gated — confirm in the dialog.
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: /remove role/i }),
    )
    await waitFor(() =>
      expect(
        within(table).queryByRole('button', { name: 'Remove editor from viewer@probectl.test' }),
      ).toBeNull(),
    )
    await userEvent.click(
      within(table).getByRole('button', { name: 'Remove admin from operator@probectl.test' }),
    )
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: /remove role/i }),
    )
    expect(await screen.findByRole('alert')).toHaveTextContent(/last administrator/i)
  })

  test('delegates a role to one org and removes the delegation', async () => {
    const fetchMock = vi.fn(defaultFetch())
    vi.stubGlobal('fetch', fetchMock)
    renderApp('/admin', {
      me: { permissions: ['directory.read', 'directory.write', 'org.read', 'audit.read'] },
    })
    const table = await screen.findByRole('table', { name: 'People & roles' })
    const form = screen.getByRole('form', { name: 'Grant a role' })
    const scope = within(form).getByLabelText('Scope')
    // The hierarchy's branches are offered alongside the whole tenant.
    await waitFor(() =>
      expect(
        within(scope).getByRole('option', { name: 'Org Platform Engineering' }),
      ).toBeInTheDocument(),
    )
    await userEvent.type(within(form).getByLabelText('Teammate email'), 'dana@example.com')
    await userEvent.selectOptions(within(form).getByLabelText('Role'), 'admin')
    await userEvent.selectOptions(scope, 'org:org-fixture-1')
    await userEvent.click(within(form).getByRole('button', { name: 'Grant' }))

    // A new person is created without a tenant-wide role, then delegated the org.
    const remove = await within(table).findByRole('button', {
      name: 'Remove admin on org Platform Engineering from dana@example.com',
    })
    const row = remove.closest('tr')
    expect(row).toHaveTextContent('admin · Org Platform Engineering')
    expect(row).not.toHaveTextContent('No role yet')
    const bind = fetchMock.mock.calls.find(
      ([url, init]) => String(url).endsWith('/roles') && init?.method === 'POST',
    )
    expect(JSON.parse(String(bind?.[1]?.body))).toEqual({
      role: 'admin',
      scope_type: 'org',
      scope_id: 'org-fixture-1',
    })

    await userEvent.click(remove)
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: /remove role/i }),
    )
    await waitFor(() =>
      expect(
        within(table).queryByRole('button', {
          name: 'Remove admin on org Platform Engineering from dana@example.com',
        }),
      ).toBeNull(),
    )
    const unbind = fetchMock.mock.calls.find(
      ([url, init]) => init?.method === 'DELETE' && String(url).includes('/roles/admin'),
    )
    expect(String(unbind?.[0])).toContain('scope_type=org&scope_id=org-fixture-1')
  })
})
