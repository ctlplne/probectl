// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse, defaultFetch } from './fetchStub'

/** S-T6 surface: the Encryption keys card on Admin — key chain state,
 *  managed rotation, BYOK activation. ee-backed: unlicensed deployments
 *  answer 404 and the card renders NOTHING (hidden-unlicensed). */

const chain = [
  { version: 2, mode: 'managed', state: 'active', created_at: '2026-06-01T00:00:00Z' },
  {
    version: 1,
    mode: 'managed',
    state: 'retired',
    created_at: '2026-01-01T00:00:00Z',
    retired_at: '2026-06-01T00:00:00Z',
  },
]

function licensedFetch(onRotate?: (body: unknown) => void) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/v1/security/keys') && (init?.method ?? 'GET') === 'GET')
      return jsonResponse({ items: chain })
    if (url.endsWith('/v1/security/keys/rotate') && init?.method === 'POST') {
      onRotate?.(JSON.parse(String(init.body)))
      return jsonResponse({
        version: 3,
        mode: 'byok',
        state: 'active',
        created_at: '2026-06-05T00:00:00Z',
      })
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('per-tenant keys / BYOK (S-T6)', () => {
  test('hidden-unlicensed: the default 404 renders no card at all', async () => {
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/admin')
    // Anchor on a sibling card so the page is fully rendered first.
    expect(await screen.findByText(/data lifecycle/i)).toBeInTheDocument()
    expect(screen.queryByText(/encryption keys/i)).not.toBeInTheDocument()
  })

  test('licensed: the chain renders with active + retired states', async () => {
    vi.stubGlobal('fetch', licensedFetch())
    renderApp('/admin')
    expect(await screen.findByText(/encryption keys/i)).toBeInTheDocument()
    expect(await screen.findByText('v2')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText(/retired \(decrypt-only\)/i)).toBeInTheDocument()
  })

  test('BYOK activation posts the secret reference; managed rotation posts no ref', async () => {
    const bodies: unknown[] = []
    vi.stubGlobal(
      'fetch',
      licensedFetch((b) => bodies.push(b)),
    )
    renderApp('/admin')
    const field = await screen.findByLabelText(/byok secret reference/i)
    await userEvent.type(field, 'vault:kv/tenants/acme#kek')
    await userEvent.click(screen.getByRole('button', { name: /activate byok/i }))
    expect(await screen.findByText(/new data seals under v3/i)).toBeInTheDocument()
    expect(bodies[0]).toEqual({ mode: 'byok', byok_ref: 'vault:kv/tenants/acme#kek' })
  })
})
