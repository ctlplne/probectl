// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch, providerFetch } from './fetchStub'
import { renderApp } from './renderApp'

const admin = { me: { permissions: ['directory.read', 'directory.write', 'audit.read'] } }

/** DPR-038: the tenant decides break-glass. A tenant administrator sees the
 * operator's pending request in Admin, approves or denies it there, and a
 * deployment without the provider plane shows no such card at all. */
describe('break-glass consent', () => {
  test('shows the pending request with who, why, and until when, and approves it', async () => {
    vi.stubGlobal('fetch', providerFetch())
    const { container } = renderApp('/admin', admin)
    const table = await screen.findByRole('table', { name: 'Pending break-glass requests' })
    const row = within(table).getByText('operator@provider.probectl.test').closest('tr')
    expect(row).toHaveTextContent('INC-4821: cross-plane RCA for the checkout latency incident')
    expect(row).toHaveTextContent('read')
    expect(await axe(container)).toHaveNoViolations()

    await userEvent.click(
      within(table).getByRole('button', { name: 'Approve operator@provider.probectl.test' }),
    )
    await waitFor(() =>
      expect(within(table).queryByText('operator@provider.probectl.test')).toBeNull(),
    )
    expect(screen.getByText(/Approved: operator@provider.probectl.test/)).toHaveAttribute(
      'role',
      'status',
    )
    expect(screen.getByText('No pending requests')).toBeInTheDocument()
  })

  test('denies a request and records the decision', async () => {
    vi.stubGlobal('fetch', providerFetch())
    renderApp('/admin', admin)
    const table = await screen.findByRole('table', { name: 'Pending break-glass requests' })
    await userEvent.click(
      within(table).getByRole('button', { name: 'Deny operator@provider.probectl.test' }),
    )
    await waitFor(() =>
      expect(within(table).queryByText('operator@provider.probectl.test')).toBeNull(),
    )
    expect(screen.getByText(/Denied: operator@provider.probectl.test/)).toHaveAttribute(
      'role',
      'status',
    )
  })

  test('is absent when the deployment has no provider plane', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin', admin)
    await screen.findByRole('table', { name: 'People & roles' })
    await waitFor(() => expect(screen.queryByText('Break-glass requests')).toBeNull())
  })
})
