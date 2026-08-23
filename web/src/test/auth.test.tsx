// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthProvider } from '../auth/AuthProvider'
import { useAuth } from '../auth/useAuth'
import { I18nProvider } from '../i18n/I18nProvider'
import { jsonResponse } from './fetchStub'

// AuthProvider's boot screen is translated, so the provider now sits under
// I18nProvider exactly as it does in App.tsx.
function Providers({ children }: { children: ReactNode }) {
  return <I18nProvider initialLocale="en">{children}</I18nProvider>
}

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
          return jsonResponse({
            tenant_id: 't-real',
            user_id: 'u9',
            email: 'ops@acme.example',
            display_name: 'Ops',
          })
        }
        return jsonResponse({ error: { message: 'unstubbed' } }, 404)
      }),
    )
    render(
      <Providers>
        <AuthProvider>
          <Identity />
        </AuthProvider>
      </Providers>,
    )
    expect(await screen.findByText('ops@acme.example @ t-real')).toBeDefined()
  })

  test('the session probe is a visible, announced boot status — never a blank page', async () => {
    // A fetch that never settles freezes the provider in its loading state.
    vi.stubGlobal(
      'fetch',
      vi.fn(() => new Promise<Response>(() => {})),
    )
    render(
      <Providers>
        <AuthProvider>
          <Identity />
        </AuthProvider>
      </Providers>,
    )
    const boot = screen.getByRole('status')
    expect(boot).toHaveTextContent(/probectl/i)
    expect(boot).toHaveTextContent(/signing you in/i)
  })

  test('unauthenticated → redirect to SSO login, NO demo identity rendered', async () => {
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, href: '', pathname: '/' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse({ error: { message: 'authentication required' } }, 401)),
    )
    render(
      <Providers>
        <AuthProvider>
          <Identity />
        </AuthProvider>
      </Providers>,
    )
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/auth/login'))
    expect(screen.queryByText(/@/)).toBeNull() // no fallback identity ever shown
    // The moment of redirect is announced, not blank.
    expect(screen.getByRole('status')).toHaveTextContent(/redirecting to sign-in/i)
  })

  test('signOut posts /auth/logout then redirects to login', async () => {
    const assign = vi.fn()
    const replace = vi.fn()
    vi.stubGlobal('location', { assign, replace, reload: vi.fn(), href: '', pathname: '/' })
    const calls: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        calls.push(`${init?.method ?? 'GET'} ${url}`)
        if (url.endsWith('/v1/me'))
          return jsonResponse({ tenant_id: 't', user_id: 'u', email: 'e@x', display_name: 'E' })
        if (url.endsWith('/auth/logout')) return new Response(null, { status: 204 })
        return jsonResponse({}, 404)
      }),
    )
    render(
      <Providers>
        <AuthProvider>
          <SignOutButton />
        </AuthProvider>
      </Providers>,
    )
    ;(await screen.findByRole('button', { name: 'sign out' })).click()
    // Protected children disappear synchronously while the real logout is in
    // flight, so a BFCache snapshot cannot retain tenant/user content.
    expect(await screen.findByRole('status')).toHaveTextContent(/redirecting to sign-in/i)
    expect(screen.queryByRole('button', { name: 'sign out' })).toBeNull()
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/auth/login'))
    expect(assign).not.toHaveBeenCalled()
    expect(calls.some((c) => c === 'POST /auth/logout')).toBe(true)
  })

  test('a BFCache restore reloads before trusting an in-memory identity', async () => {
    const reload = vi.fn()
    vi.stubGlobal('location', {
      assign: vi.fn(),
      replace: vi.fn(),
      reload,
      href: '',
      pathname: '/',
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({ tenant_id: 't', user_id: 'u', email: 'e@x', display_name: 'E' }),
      ),
    )
    render(
      <Providers>
        <AuthProvider>
          <Identity />
        </AuthProvider>
      </Providers>,
    )
    expect(await screen.findByText('e@x @ t')).toBeDefined()

    const restored = new Event('pageshow')
    Object.defineProperty(restored, 'persisted', { value: true })
    window.dispatchEvent(restored)
    expect(reload).toHaveBeenCalledOnce()
  })
})
