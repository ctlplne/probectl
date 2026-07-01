import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import type { SecretsHealthResponse } from '../api/secrets'

/** S41 surface: the Admin page's "Secret backends" card — per-backend
 *  credential-resolution health with zero secret material. */

function healthFixture(): SecretsHealthResponse {
  return {
    resolver_running: true,
    backends: [
      { scheme: 'env', configured: true, resolves: 12, failures: 0, cached_leases: 0 },
      {
        scheme: 'vault',
        configured: true,
        resolves: 41,
        failures: 2,
        cached_leases: 3,
        last_ok: '2026-06-04T11:55:00Z',
        last_error: 'secrets: backend unavailable: dial tcp: refused',
        last_error_at: '2026-06-04T11:40:00Z',
      },
    ],
  }
}

function stubWith(health: SecretsHealthResponse | { resolver_running: false; backends: [] }) {
  const fallback = defaultFetch()
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === '/v1/secrets/health') return Promise.resolve(jsonResponse(health))
    return fallback(input, init)
  }) as unknown as typeof fetch
}

describe('secret backends card (S41)', () => {
  test('lists per-backend health: counters, live leases, redacted last error', async () => {
    vi.stubGlobal('fetch', stubWith(healthFixture()))
    renderApp('/admin')

    const table = await screen.findByRole('table', {
      name: /secret backend health/i,
    })
    const vaultRow = within(table).getByText('vault').closest('tr')!
    expect(within(vaultRow).getByText('41')).toBeInTheDocument()
    expect(within(vaultRow).getByText('2')).toBeInTheDocument()
    expect(within(vaultRow).getByText('3')).toBeInTheDocument() // live leases badge
    expect(within(vaultRow).getByText(/dial tcp: refused/)).toBeInTheDocument()
    // env backend healthy
    const envRow = within(table).getByText('env').closest('tr')!
    expect(within(envRow).getByText('OK')).toBeInTheDocument()
    // No secret-looking material anywhere in the card.
    expect(within(table).queryByText(/#community|password=|Bearer /)).toBeNull()
  })

  test('honesty: an unwired resolver renders as "not wired", not healthy-empty', async () => {
    vi.stubGlobal('fetch', stubWith({ resolver_running: false, backends: [] }))
    renderApp('/admin')

    expect(await screen.findByText(/secrets resolver not wired/i)).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: /secret backend health/i })).toBeNull()
  })
})
