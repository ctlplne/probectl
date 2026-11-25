// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { afterEach, describe, expect, test, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Providers } from '../App'
import { AppRoutes } from '../routes/AppRoutes'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse } from './fetchStub'
import {
  applyBrand,
  DEFAULT_BRAND,
  fetchBrand,
  sanitizeTokenOverrides,
  tokenOverridesPassContrast,
} from '../api/brand'
import { MAX_RESPONSE_BODY_BYTES } from '../api/response'

const northTenant = '00000000-0000-0000-0000-000000000001'
const northLogo =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGPwTGoHAAIqATNiOKEkAAAAAElFTkSuQmCC'
const southLogo =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNot/AEAAJSAQngtvKYAAAAAElFTkSuQmCC'

function sessionBrand(body: unknown, tenant: string) {
  const response = jsonResponse(body)
  response.headers.set('X-Probectl-Brand-Tenant', tenant)
  return response
}

function brandingStub(response: unknown, tenant?: string) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/branding'))
      return tenant ? sessionBrand(response, tenant) : jsonResponse(response)
    return defaultFetch()(input, init)
  }) as unknown as typeof fetch
}

afterEach(() => {
  applyBrand(DEFAULT_BRAND)
  document.title = ''
})

test.each(['/targets', '/incidents', '/dashboards'])(
  'customer console %s keeps the fixed attribution with its brand',
  async (route) => {
    vi.stubGlobal(
      'fetch',
      brandingStub(
        {
          product_name: 'probectl',
          customer: { name: 'Northstar', logo_data_uri: northLogo },
          token_overrides: { '--font-sans': 'Example', '--powered-by-opacity': '0' },
          powered_by: false,
        },
        northTenant,
      ),
    )
    renderApp(route)
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(await within(nav).findByText('Northstar')).toBeInTheDocument()
    const badge = within(nav).getByRole('link', { name: 'Powered by probectl' })
    expect(badge).toHaveAttribute('href', 'https://probectl.com')
    expect(badge.querySelector('svg')).toBeInTheDocument()
    expect(nav.querySelector('img')).toHaveAttribute('src', northLogo)
    const header = within(screen.getByRole('banner'))
    expect(header.getByText('Northstar')).toBeInTheDocument()
    expect(header.getByText('Powered by probectl')).toHaveAttribute('href', 'https://probectl.com')
    expect(document.documentElement.style.getPropertyValue('--powered-by-opacity')).toBe('')
    expect(document.title).toContain('Powered by probectl')
  },
)

test('a session change rejects another tenant’s name, logo and palette', async () => {
  const southTenant = '00000000-0000-0000-0000-000000000002'
  const fallback = defaultFetch()
  let lookups = 0
  let finishSession!: (response: Response) => void
  let finishCurrentBrand!: (response: Response) => void
  const session = new Promise<Response>((resolve) => {
    finishSession = resolve
  })
  const pending = new Promise<Response>((resolve) => {
    finishCurrentBrand = resolve
  })
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith('/v1/me')) return session
    if (!String(input).endsWith('/branding')) return fallback(input, init)
    lookups++
    if (lookups > 1) return pending
    return sessionBrand(
      {
        product_name: 'probectl',
        customer: { name: 'Northstar', logo_data_uri: northLogo },
        token_overrides: { '--font-sans': 'Northstar Type' },
      },
      northTenant,
    )
  })
  render(
    <Providers>
      <MemoryRouter initialEntries={['/targets']}>
        <AppRoutes />
      </MemoryRouter>
    </Providers>,
  )
  await waitFor(() => expect(lookups).toBe(1))
  await act(async () => {
    finishSession(
      jsonResponse({
        tenant_id: southTenant,
        tenant_name: 'South customer',
        user_id: 'u',
        email: 'user@example.test',
      }),
    )
  })

  const nav = await screen.findByRole('navigation', { name: 'Primary' })
  const header = within(screen.getByRole('banner'))
  await waitFor(() => expect(lookups).toBe(2))
  expect(within(nav).getByText('probectl')).toBeInTheDocument()
  expect(header.getByText('probectl')).toBeInTheDocument()
  expect(screen.queryByText('Northstar')).not.toBeInTheDocument()
  expect(nav.querySelector('img')).toBeNull()
  expect(document.documentElement.style.getPropertyValue('--font-sans')).toBe('')
  expect(document.title).toBe('probectl')

  finishCurrentBrand(
    sessionBrand(
      {
        product_name: 'probectl',
        customer: { name: 'Southwind', logo_data_uri: southLogo },
        token_overrides: { '--font-sans': 'Southwind Type' },
      },
      southTenant,
    ),
  )
  expect(await within(nav).findByText('Southwind')).toBeInTheDocument()
  expect(header.getByText('Southwind')).toBeInTheDocument()
  expect(header.getByText('Powered by probectl')).toHaveAttribute('href', 'https://probectl.com')
  expect(nav.querySelector('img')).toHaveAttribute('src', southLogo)
  expect(within(nav).getByRole('link', { name: 'Powered by probectl' })).toHaveAttribute(
    'href',
    'https://probectl.com',
  )
  expect(document.documentElement.style.getPropertyValue('--font-sans')).toBe('Southwind Type')
})

test.each([true, false])(
  'a mapped customer sign-in uses the host even when the bookmark names another tenant (brand visible: %s)',
  async (hasCustomer) => {
    const foreignTenant = '00000000-0000-0000-0000-000000000002'
    const search = `?login_tenant=${foreignTenant}`
    const assign = vi.fn()
    vi.stubGlobal('location', { assign, search })
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        if (path.endsWith('/branding')) {
          return jsonResponse({
            product_name: 'probectl',
            customer_domain: true,
            ...(hasCustomer ? { customer: { name: 'Northstar' } } : {}),
          })
        }
        if (path.endsWith('/me')) return new Response('', { status: 401 })
        if (path.endsWith('/readyz')) return jsonResponse({ status: 'ready' })
        return defaultFetch()(input, init)
      }),
    )
    render(
      <Providers>
        <MemoryRouter initialEntries={[`/targets${search}`]}>
          <AppRoutes />
        </MemoryRouter>
      </Providers>,
    )
    const signIn = await screen.findByRole('button', { name: 'Sign in' })
    expect(assign).not.toHaveBeenCalled()
    if (hasCustomer) {
      expect(screen.getByText('Northstar')).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Powered by probectl' })).toHaveAttribute(
        'href',
        'https://probectl.com',
      )
    } else {
      expect(screen.getByText('probectl')).toBeInTheDocument()
      expect(screen.queryByText('Northstar')).not.toBeInTheDocument()
    }
    expect(screen.queryByRole('navigation', { name: 'Primary' })).not.toBeInTheDocument()
    fireEvent.click(signIn)
    expect(assign).toHaveBeenCalledExactlyOnceWith('/auth/login')
  },
)

describe('deployment-level probectl theming', () => {
  test('applies deployment tokens while keeping the probectl banner and title', async () => {
    vi.stubGlobal(
      'fetch',
      brandingStub({
        product_name: 'probectl',
        token_overrides: {
          '--primary': '28 85% 30%',
          '--primary-foreground': '0 0% 100%',
        },
      }),
    )
    renderApp('/targets')
    // Scoped to the shell's primary nav: the transient auth boot screen also
    // says "probectl", so an unscoped text query races the boot unmount.
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByText('probectl')).toBeInTheDocument()
    const wordmark = within(nav).getByText('probectl').parentElement
    expect(wordmark?.querySelector('svg[aria-hidden="true"]')).toBeInTheDocument()
    expect(within(nav).queryByRole('link', { name: 'Powered by probectl' })).not.toBeInTheDocument()
    await waitFor(() => {
      expect(document.documentElement.style.getPropertyValue('--primary')).toBe('28 85% 30%')
    })
    expect(document.title).toBe('probectl')
  })

  test('rejects a response that attempts to replace the product identity', async () => {
    vi.stubGlobal(
      'fetch',
      brandingStub({
        product_name: 'OtherProduct',
        token_overrides: {
          '--primary': '28 85% 30%',
          '--primary-foreground': '0 0% 100%',
        },
      }),
    )
    renderApp('/targets')
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByText('probectl')).toBeInTheDocument()
    await waitFor(() =>
      expect(document.documentElement.style.getPropertyValue('--primary')).toBe(''),
    )
    expect(screen.queryByText('OtherProduct')).not.toBeInTheDocument()
    expect(document.title).toBe('probectl')
  })

  test('falls back without buffering an oversized branding response', async () => {
    let cancelled = false
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{}'))
      },
      cancel() {
        cancelled = true
      },
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        return new Response(stream, {
          status: 200,
          headers: { 'Content-Length': String(MAX_RESPONSE_BODY_BYTES + 1) },
        })
      }),
    )

    await expect(fetchBrand()).resolves.toEqual(DEFAULT_BRAND)
    expect(cancelled).toBe(true)
  })

  test.each([
    [[], 'Auditor read-only'],
    [['audit.read', 'test.read'], 'Read-only'],
    [['test.read', 'test.write'], 'Operator'],
    [['provider.tenant.provision'], 'Provider plane'],
    [['provider.breakglass.results'], 'Break-glass active'],
    [['license.read_only'], 'Degraded read-only'],
  ])('shell renders authority posture %s from /v1/me permissions', async (permissions, label) => {
    vi.stubGlobal('fetch', brandingStub(DEFAULT_BRAND))
    renderApp('/targets', { me: { permissions } })
    expect(
      await screen.findByRole('status', { name: `Authority posture: ${label}` }),
    ).toBeInTheDocument()
  })

  // One override map is validated against BOTH shipped themes, which is a real
  // constraint worth pinning: a single chip tone cannot clear 4.5:1 against a
  // near-white card AND a near-black one, so tones are overridable only as a
  // colour/foreground pair. Without this test the constraint reads like a bug the
  // next person "fixes" by validating one theme.
  test('an override is only valid if it holds in light AND dark', () => {
    // The shipped light value for a chip tone, which is unreadable on a dark card.
    expect(tokenOverridesPassContrast({ '--status-success': '166 55% 20%' })).toBe(false)
    // The shipped dark value for the same tone, unreadable on a light card.
    expect(tokenOverridesPassContrast({ '--status-success': '158 64% 52%' })).toBe(false)
    // A colour that carries its own foreground holds in both.
    expect(
      tokenOverridesPassContrast({
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
      }),
    ).toBe(true)
  })

  test('reapplying deployment config removes tokens omitted by the next config', () => {
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
        '--radius-panel': '10px',
      },
    })
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--primary': '24 85% 28%',
        '--primary-foreground': '0 0% 100%',
      },
    })
    expect(document.documentElement.style.getPropertyValue('--primary')).toBe('24 85% 28%')
    expect(document.documentElement.style.getPropertyValue('--radius-panel')).toBe('')
    expect(document.title).toBe('probectl')
  })

  test('client defense ignores unsafe tokens and unreadable sets', () => {
    applyBrand({
      product_name: 'probectl',
      token_overrides: {
        '--space-4': '999px', // structural token, never overridable
        '--primary': 'url(https://evil.example)', // no browser fetch
        '--radius-control': '24', // unitless
        '--radius-panel': '10px', // the one legitimate entry
      },
    })
    expect(document.documentElement.style.getPropertyValue('--space-4')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--primary')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--radius-control')).toBe('')
    expect(document.documentElement.style.getPropertyValue('--radius-panel')).toBe('10px')

    // A hex value is a valid CSS colour but NOT a valid token value: the
    // stylesheet reads the token as hsl(var(--primary) / <alpha>), so applying a
    // hex would break every rule that uses it rather than recolour it.
    expect(sanitizeTokenOverrides({ '--primary': '#6a4cf0' })).toEqual({})
    expect(sanitizeTokenOverrides({ '--primary': 'rgb(106 76 240)' })).toEqual({})
    // The retired vocabulary is refused outright rather than applied to nothing.
    expect(sanitizeTokenOverrides({ '--color-accent': '28 85% 30%' })).toEqual({})
    // A token name that ships nowhere, even under an overridable prefix.
    expect(sanitizeTokenOverrides({ '--radius-nope': '10px' })).toEqual({})
    expect(sanitizeTokenOverrides({ '--font-nope': 'Sora' })).toEqual({})

    // Contrast: white body text on warm paper, a white series line on it, and an
    // action colour too light to carry its own white label.
    expect(tokenOverridesPassContrast({ '--foreground': '0 0% 100%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--chart-1': '0 0% 100%' })).toBe(false)
    expect(tokenOverridesPassContrast({ '--primary': '28 100% 85%' })).toBe(false)
    // One bad member poisons the whole set — a partially-applied theme is worse
    // than none, because the operator sees some of their change and trusts it.
    expect(
      sanitizeTokenOverrides({
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
        '--foreground': '0 0% 100%',
      }),
    ).toEqual({})
    // ...and the same set without the unreadable member goes through, so the test
    // above cannot pass merely because sanitize rejects everything.
    expect(
      sanitizeTokenOverrides({
        '--primary': '28 85% 30%',
        '--primary-foreground': '0 0% 100%',
      }),
    ).toEqual({ '--primary': '28 85% 30%', '--primary-foreground': '0 0% 100%' })
  })
})

test.each([{ permissions: [] }, { permissions: ['org.read', 'test.read'] }])(
  'scoped grants produce an honest badge without enabling tenant-wide writes: $permissions',
  async ({ permissions }) => {
    vi.stubGlobal('fetch', brandingStub(DEFAULT_BRAND))
    renderApp('/targets', { me: { permissions, has_scoped_grants: true } })
    expect(
      await screen.findByRole('status', { name: 'Authority posture: Scoped access' }),
    ).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'New test' })).toBeDisabled()
  },
)
