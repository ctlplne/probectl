import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { AuthProvider } from '../auth/AuthProvider'
import { useAuth } from '../auth/useAuth'
import { jsonResponse } from './fetchStub'

function Identity() {
  const { user, tenant } = useAuth()
  return (
    <div>
      {user.email} @ {tenant.id}
    </div>
  )
}

function SignOutButton() {
  const { signOut } = useAuth()
  return (
    <button type="button" onClick={signOut}>
      sign out
    </button>
  )
}

describe('AuthProvider — real session identity (SEC-001)', () => {
  beforeEach(() => vi.restoreAllMocks())
  afterEach(() => vi.unstubAllGlobals())

  test('resolves the signed-in identity from /v1/me and renders children', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).endsWith('/v1/me')) {
          return jsonResponse({ tenant_id: 't-real', user_id: 'u9', email: 'ops@acme.example', display_name: 'Ops' })
        }
        return jsonResponse({ error: { message: 'unstubbed' } }, 404)
      }) as unknown as typeof fetch,
    )
    render(
      <AuthProvider>
        <Identity />
      </AuthProvider>,
    )
    expect(await screen.findByText('ops@acme.example @ t-real')).toBeDefined()
  })

  test('unauthenticated → redirect to SSO login, NO demo identity rendered', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: '', pathname: '/' } as unknown as Location)
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ error: { message: 'authentication required' } }, 401)) as unknown as typeof fetch,
    )
    render(
      <AuthProvider>
        <Identity />
      </AuthProvider>,
    )
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/auth/login'))
    expect(screen.queryByText(/@/)).toBeNull() // no fallback identity ever shown
  })

  test('signOut posts /auth/logout then redirects to login', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: '', pathname: '/' } as unknown as Location)
    const calls: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        calls.push(`${init?.method ?? 'GET'} ${url}`)
        if (url.endsWith('/v1/me')) return jsonResponse({ tenant_id: 't', user_id: 'u', email: 'e@x', display_name: 'E' })
        if (url.endsWith('/auth/logout')) return new Response(null, { status: 204 })
        return jsonResponse({}, 404)
      }) as unknown as typeof fetch,
    )
    render(
      <AuthProvider>
        <SignOutButton />
      </AuthProvider>,
    )
    ;(await screen.findByRole('button', { name: 'sign out' })).click()
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/auth/login'))
    expect(calls.some((c) => c === 'POST /auth/logout')).toBe(true)
  })
})
