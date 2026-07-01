import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { Providers } from '../App'
import { AppRoutes } from '../routes/AppRoutes'
import { jsonResponse } from './fetchStub'

/** The default authenticated identity for screen tests (SEC-001). The app now
 *  resolves the signed-in user from /v1/me; renderApp serves this so tests
 *  render as a signed-in operator. */
interface MeFixture {
  tenant_id: string
  user_id: string
  email: string
  display_name: string
  mfa_satisfied: boolean
  permissions: string[]
  tenant_time_zone?: string
  tenant_locale?: string
  time_zone?: string
  locale?: string
}

const DEFAULT_ME: MeFixture = {
  tenant_id: '00000000-0000-0000-0000-000000000001',
  user_id: 'u_test',
  email: 'operator@probectl.test',
  display_name: 'Test Operator',
  mfa_satisfied: true,
  permissions: [],
}

/** Renders the full app (shell + routes) at a path, with a MemoryRouter.
 *
 *  The app authenticates via /v1/me (SEC-001), so renderApp serves a default
 *  authenticated session and DELEGATES every other request to whatever fetch
 *  the test already stubbed — existing per-test backends are unchanged, and a
 *  test that wants to exercise the real auth path can render <AuthProvider>
 *  directly with its own /v1/me stub (see auth.test.tsx). */
export function renderApp(
  path = '/targets',
  options: { locale?: string; me?: Partial<MeFixture> } = {},
) {
  const inner = globalThis.fetch
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const u = requestURL(input)
    // Serve the TENANT identity (/v1/me) only — NOT the provider console's
    // /provider/v1/me, which the test's own stub answers with an operator shape.
    if (u.endsWith('/v1/me') && !u.includes('/provider/'))
      return Promise.resolve(jsonResponse({ ...DEFAULT_ME, ...options.me }))
    return inner(input, init)
  })
  return render(
    <Providers initialLocale={options.locale}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </Providers>,
  )
}

function requestURL(input: RequestInfo | URL) {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}
