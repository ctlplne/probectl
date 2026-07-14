import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
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

describe('tenant indicator', () => {
  test('stays visible but non-interactive for a single-tenant session', () => {
    render(
      <AuthContext.Provider value={authValue([alpha])}>
        <TenantIndicator />
      </AuthContext.Provider>,
    )

    expect(screen.getByLabelText('Current tenant: Alpha')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /switch tenant/i })).not.toBeInTheDocument()
  })

  test('becomes a working switcher when the session has multiple tenants', async () => {
    const user = userEvent.setup()
    const switchTenant = vi.fn()
    render(
      <AuthContext.Provider value={authValue([alpha, beta], switchTenant)}>
        <TenantIndicator />
      </AuthContext.Provider>,
    )

    await user.click(screen.getByRole('button', { name: /switch tenant/i }))
    await user.click(screen.getByRole('menuitemradio', { name: 'Beta' }))

    expect(switchTenant).toHaveBeenCalledWith('tenant-b')
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
