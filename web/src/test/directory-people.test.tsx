// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    await waitFor(() =>
      expect(
        within(table).queryByRole('button', { name: 'Remove editor from viewer@probectl.test' }),
      ).toBeNull(),
    )
    await userEvent.click(
      within(table).getByRole('button', { name: 'Remove admin from operator@probectl.test' }),
    )
    expect(await screen.findByRole('alert')).toHaveTextContent(/last administrator/i)
  })
})
