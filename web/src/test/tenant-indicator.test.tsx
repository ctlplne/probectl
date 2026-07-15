// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { AuthContext, type AuthContextValue, type Tenant } from '../auth/AuthProvider'
import { TenantIndicator } from '../shell/TenantIndicator'

const alpha: Tenant = { id: 'tenant-a', name: 'Alpha', slug: 'alpha' }
const beta: Tenant = { id: 'tenant-b', name: 'Beta', slug: 'beta' }

function authValue(tenants: Tenant[], switchTenant = vi.fn()): AuthContextValue {
  return {
    user: { id: 'user-a', name: 'Operator', email: 'operator@example.test' },
    tenant: alpha,
    tenants,
    permissions: [],
    switchTenant,
    signOut: vi.fn(),
  }
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>
}

function renderIndicator(
  value: AuthContextValue,
  initialEntry = '/incidents?incident=stale&task=incident-share&ctx_selected_id=stale',
) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AuthContext.Provider value={value}>
        <TenantIndicator />
        <LocationProbe />
      </AuthContext.Provider>
    </MemoryRouter>,
  )
}

describe('tenant indicator', () => {
  test('stays visible but non-interactive for a single-tenant session', () => {
    renderIndicator(authValue([alpha]))

    expect(screen.getByLabelText('Current tenant: Alpha')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /switch tenant/i })).not.toBeInTheDocument()
  })

  test('becomes a working switcher when the session has multiple tenants', async () => {
    const user = userEvent.setup()
    const switchTenant = vi.fn()
    renderIndicator(authValue([alpha, beta], switchTenant))

    await user.click(screen.getByRole('button', { name: /switch tenant/i }))
    await user.click(screen.getByRole('menuitemradio', { name: 'Beta' }))

    expect(switchTenant).toHaveBeenCalledWith('tenant-b')
    expect(screen.getByTestId('location')).toHaveTextContent('/onboarding')
    expect(screen.getByTestId('location')).not.toHaveTextContent(/incident|task|ctx_/i)
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
