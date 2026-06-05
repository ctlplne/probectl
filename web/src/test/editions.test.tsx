import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'
import type { EditionsInfo } from '../api/editions'

/** S-T0 surface: Admin → Editions — the ONE place tiers appear when
 *  unlicensed (hidden-unlicensed doctrine; no lockware elsewhere). */

function licensedFixture(): EditionsInfo {
  return {
    tier: 'provider',
    state: 'active',
    customer: 'Reseller GmbH',
    license_id: 'lic_msp_1',
    expires_at: '2026-09-03T23:59:59Z',
    read_only_at: '2026-10-03T23:59:59Z',
    tenant_band: 25,
    features: [
      { name: 'fips', tier: 'enterprise', licensed: false, mode: 'off' },
      { name: 'byok', tier: 'enterprise', licensed: false, mode: 'off' },
      { name: 'provider_plane', tier: 'provider', licensed: true, mode: 'enabled' },
      { name: 'white_label', tier: 'provider', licensed: true, mode: 'enabled' },
    ],
  }
}

function stubWith(info: EditionsInfo) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith('/v1/editions')) return jsonResponse(info)
    if (url.endsWith('/v1/agents')) return jsonResponse({ items: [] })
    if (url.endsWith('/v1/secrets/health'))
      return jsonResponse({ resolver_running: true, backends: [] })
    return jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404)
  }) as unknown as typeof fetch
}

describe('editions card (S-T0)', () => {
  test('community truth: COMMUNITY badge, full feature table, everything unlicensed', async () => {
    vi.stubGlobal('fetch', defaultFetch()) // default stub = community shape
    renderApp('/admin')

    expect(await screen.findByText('COMMUNITY')).toBeInTheDocument()
    expect(screen.getByText(/the full core, free forever/i)).toBeInTheDocument()
    const table = (await screen.findByRole('table', { name: /commercial features by tier/i })) as HTMLTableElement
    // The full feature map renders (9 commercial features), all "Not licensed".
    expect(within(table).getByText('provider_plane')).toBeInTheDocument()
    expect(within(table).getByText('fips')).toBeInTheDocument()
    expect(within(table).getAllByText('Not licensed')).toHaveLength(9)
    expect(within(table).queryByText('Enabled')).toBeNull()
  })

  test('licensed truth: tier, customer, expiry, band; grants enabled, rest unlicensed', async () => {
    vi.stubGlobal('fetch', stubWith(licensedFixture()))
    renderApp('/admin')

    expect(await screen.findByText('PROVIDER')).toBeInTheDocument()
    expect(screen.getByText(/licensed to Reseller GmbH/)).toBeInTheDocument()
    expect(screen.getByText(/tenant band 25/)).toBeInTheDocument()
    const table = (await screen.findByRole('table', { name: /commercial features by tier/i })) as HTMLTableElement
    const provRow = within(table).getByText('provider_plane').closest('tr')!
    expect(within(provRow).getByText('Enabled')).toBeInTheDocument()
    const fipsRow = within(table).getByText('fips').closest('tr')!
    expect(within(fipsRow).getByText('Not licensed')).toBeInTheDocument()
  })

  test('expiry ladder renders: read-only state is loud, never silent', async () => {
    vi.stubGlobal('fetch', stubWith({ ...licensedFixture(), state: 'read_only' }))
    renderApp('/admin')

    expect(await screen.findByText(/expired — read-only/i)).toBeInTheDocument()
  })

  test('a11y: the admin page with the editions card has no axe violations', async () => {
    vi.stubGlobal('fetch', stubWith(licensedFixture()))
    const { container } = renderApp('/admin')
    await screen.findByText('PROVIDER')
    expect(await axe(container)).toHaveNoViolations()
  })
})
