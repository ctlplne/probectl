import { createContext, useCallback, useMemo, useState, type ReactNode } from 'react'

/**
 * STUB AUTH (S8a). This resolves a signed-in user and a single active tenant so
 * the shell is tenant-correct and routes render before real identity exists.
 * It is replaced wholesale by SSO/SCIM + the per-tenant IdP in S18 — every
 * consumer reads the same {@link useAuth} contract, so that swap is internal.
 */
export interface Tenant {
  id: string
  name: string
  slug: string
}

export interface User {
  id: string
  name: string
  email: string
}

export interface AuthContextValue {
  user: User
  tenant: Tenant
  tenants: Tenant[]
  switchTenant: (id: string) => void
  signOut: () => void
}

// eslint-disable-next-line react-refresh/only-export-components
export const AuthContext = createContext<AuthContextValue | null>(null)

const DEMO_USER: User = { id: 'u_demo', name: 'Demo Operator', email: 'demo@probectl.local' }

// In dev the default tenant is resolved (single-tenant install is the one-tenant
// case); a second tenant exists only to exercise the always-visible indicator.
const DEMO_TENANTS: Tenant[] = [
  { id: 't_default', name: 'Default Tenant', slug: 'default' },
  { id: 't_acme', name: 'Acme Networks', slug: 'acme' },
]

export function AuthProvider({ children }: { children: ReactNode }) {
  const [tenantId, setTenantId] = useState<string>(DEMO_TENANTS[0].id)

  const tenant = useMemo(
    () => DEMO_TENANTS.find((t) => t.id === tenantId) ?? DEMO_TENANTS[0],
    [tenantId],
  )

  const switchTenant = useCallback((id: string) => setTenantId(id), [])
  const signOut = useCallback(() => {
    /* stub: real sign-out arrives with S18 sessions */
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({ user: DEMO_USER, tenant, tenants: DEMO_TENANTS, switchTenant, signOut }),
    [tenant, switchTenant, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
