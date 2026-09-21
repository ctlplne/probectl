// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'

describe('authenticated account menu', () => {
  test('exposes identity, tenant, and secure sign out with Escape recovery', async () => {
    const user = userEvent.setup()
    renderApp('/targets')

    const trigger = await screen.findByRole('button', {
      name: 'Open account menu for Test Operator',
    })
    await user.click(trigger)

    const menu = screen.getByRole('menu', { name: 'Account' })
    expect(menu).toHaveTextContent('Test Operator')
    expect(menu).toHaveTextContent('operator@probectl.test')
    expect(menu).toHaveTextContent('Tenant · Acme Industries')
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toHaveFocus()

    await user.keyboard('{Escape}')
    expect(screen.queryByRole('menu', { name: 'Account' })).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })
})
