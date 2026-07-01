import { createContext, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { apiFetch, publicFetch, redirectToLogin } from '../api/client'

/**
 * AuthProvider resolves the REAL signed-in identity from the session (SEC-001):
 * it fetches `/v1/me` — the server resolves the tenant from the session cookie,
 * never the browser — and exposes it through {@link useAuth}. `signOut` hits the
 * real logout endpoint. There is NO demo/stub identity: an unauthenticated
 * caller is sent to the SSO login, and the backend enforces every `/v1` call
 * regardless of what the UI shows.
 */
export interface Tenant {
  id: string
  name: string
  slug: string
  time_zone?: string | null
  locale?: string | null
}

export interface User {
  id: string
  name: string
  email: string
  time_zone?: string | null
  locale?: string | null
}

export interface AuthContextValue {
  user: User
  tenant: Tenant
  tenants: Tenant[]
  permissions: string[]
  switchTenant: (id: string) => void
  signOut: () => void
}

// eslint-disable-next-line react-refresh/only-export-components
export const AuthContext = createContext<AuthContextValue | null>(null)

/** The `/v1/me` response (the server's authenticated view of the caller). */
interface Me {
  tenant_id: string
  user_id: string
  email: string
  display_name: string
  permissions?: string[]
  tenant_time_zone?: string | null
  tenant_locale?: string | null
  time_zone?: string | null
  locale?: string | null
}

const LOGOUT_PATH = '/auth/logout'

// UX-005/UX-006: the SSO redirect is the shared client.redirectToLogin so the
// global query onError and this bootstrap take the SAME path.
const toLogin = redirectToLogin

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [status, setStatus] = useState<'loading' | 'ready' | 'unauthenticated'>('loading')

  useEffect(() => {
    let alive = true
    apiFetch<Me>('/me')
      .then((m) => {
        if (alive) {
          setMe(m)
          setStatus('ready')
        }
      })
      .catch(() => {
        if (alive) setStatus('unauthenticated')
      })
    return () => {
      alive = false
    }
  }, [])

  const signOut = useCallback(() => {
    // POST the real logout (revokes the session + clears the cookie), then send
    // the browser to the SSO login regardless of the result. /auth/logout is
    // outside the /v1 API base, so it's a direct same-origin fetch.
    void publicFetch(LOGOUT_PATH, { method: 'POST' }).finally(toLogin)
  }, [])

  const value = useMemo<AuthContextValue | null>(() => {
    if (!me) return null
    // A tenant user belongs to exactly ONE tenant; the server resolves it from
    // the session. Cross-tenant switching is a provider-plane operator feature,
    // not exposed in the tenant UI — so the list holds the single tenant and
    // switchTenant is a no-op (the always-visible indicator stays correct).
    const tenant: Tenant = {
      id: me.tenant_id,
      name: me.tenant_id,
      slug: me.tenant_id,
      time_zone: me.tenant_time_zone,
      locale: me.tenant_locale,
    }
    const user: User = {
      id: me.user_id,
      name: me.display_name || me.email,
      email: me.email,
      time_zone: me.time_zone,
      locale: me.locale,
    }
    return {
      user,
      tenant,
      tenants: [tenant],
      permissions: me.permissions ?? [],
      switchTenant: () => {},
      signOut,
    }
  }, [me, signOut])

  if (status === 'loading') {
    return <div role="status" aria-live="polite" aria-busy="true" />
  }
  if (status === 'unauthenticated' || !value) {
    toLogin()
    return null
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
