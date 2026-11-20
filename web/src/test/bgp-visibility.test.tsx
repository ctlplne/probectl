// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'
import type { BGPVisibilityMonitor, BGPVisibilityObservation } from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { BGPVisibilityPanel } from '../routes/BGPVisibilityPanel'
import { TimeProvider } from '../time/TimeProvider'
import { jsonResponse, pathOf } from './fetchStub'

const clock = '2026-10-01T00:00:00Z'
const first: BGPVisibilityMonitor = {
  id: '10000000-0000-4000-8000-000000000001',
  prefix: '192.0.2.0/24',
  minimum_visible_basis_points: 9500,
  alert_on_partial: true,
  alert_on_loss: true,
  created_at: clock,
}
const second = { ...first, id: '10000000-0000-4000-8000-000000000002', prefix: '2001:db8::/32' }
const observation: BGPVisibilityObservation = {
  source: 'routeviews',
  collector: 'route-views.eqix',
  observed_at: clock,
  archive_clock: clock,
  baseline_clock: clock,
  baseline_sha256: 'a'.repeat(64),
  archive_sha256: 'a'.repeat(64),
  availability: 'available',
  policy_version: 'routeviews-full-table-v1',
  minimum_peer_routes: 800000,
  counts: {
    eligible_peers: 4,
    visible_peers: 2,
    ambiguous_origin_peers: 0,
    origins: [{ asn: 64496, peers: 2 }],
  },
}

function mount(permissions: string[]) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={cache}>
      <AuthContext.Provider
        value={{
          user: { id: 'user-red', email: 'red@example.test', name: 'Red operator' },
          tenant: { id: 'tenant-red', name: 'Red', slug: 'red' },
          tenants: [],
          permissions,
          signOut: vi.fn(),
          switchTenant: vi.fn(),
        }}
      >
        <I18nProvider initialLocale="en">
          <TimeProvider>
            <BGPVisibilityPanel />
          </TimeProvider>
        </I18nProvider>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

function connect(handler: (path: string, init?: RequestInit) => Response) {
  const api = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    handler(pathOf(input), init),
  )
  vi.stubGlobal('fetch', api)
  return api
}

afterEach(() => vi.unstubAllGlobals())

test('shows no visibility controls or network reads without event access', () => {
  const api = connect(() => jsonResponse({ items: [] }))
  mount(['alert.write'])
  expect(screen.queryByText('Public prefix visibility')).not.toBeInTheDocument()
  expect(api).not.toHaveBeenCalled()
})

test('distinguishes zero observations from missing views and follows the chosen prefix', async () => {
  const user = userEvent.setup()
  const api = connect((path) => {
    if (path === '/v1/bgp/visibility') return jsonResponse({ items: [first, second] })
    if (path.endsWith(first.id))
      return jsonResponse({
        monitor: first,
        items: [
          observation,
          {
            ...observation,
            observed_at: '2026-10-01T00:15:00Z',
            counts: { eligible_peers: 4, visible_peers: 0, ambiguous_origin_peers: 0, origins: [] },
          },
          {
            ...observation,
            observed_at: '2026-10-01T00:30:00Z',
            counts: undefined,
            availability: 'archive_gap',
          },
        ],
      })
    if (path.endsWith(second.id))
      return jsonResponse({
        monitor: second,
        items: [
          { ...observation, counts: undefined, availability: 'empty_cohort' },
          {
            ...observation,
            observed_at: '2026-10-01T00:15:00Z',
            counts: undefined,
            availability: 'session_change',
          },
        ],
      })
    throw new Error(`unexpected fixture path ${path}`)
  })
  mount(['events.read'])
  expect(api).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Open prefix visibility' }))
  const history = await screen.findByRole('table', {
    name: `Collector coverage for ${first.prefix}`,
  })
  expect(within(history).getByText('0 of 4 eligible peers')).toBeInTheDocument()
  expect(within(history).getByText('Archive gap')).toBeInTheDocument()
  expect(within(history).getByText('AS64496 (2)')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Set up monitoring' })).not.toBeInTheDocument()
  await user.selectOptions(screen.getByLabelText('Monitored prefix'), second.id)
  const other = await screen.findByRole('table', {
    name: `Collector coverage for ${second.prefix}`,
  })
  expect(within(other).getByText('No eligible peers')).toBeInTheDocument()
  expect(within(other).getByText('Collector session changed')).toBeInTheDocument()
  expect(within(other).queryByText('0 of 4 eligible peers')).not.toBeInTheDocument()
})

test('sends exact alert policy and waits for explicit confirmation before removing the monitor', async () => {
  const user = userEvent.setup()
  let exists = false
  let saved: unknown
  let deleteRequests = 0
  connect((path, init) => {
    if (path === '/v1/bgp/visibility' && init?.method === 'PUT') {
      if (typeof init.body !== 'string') throw new Error('missing policy JSON')
      saved = JSON.parse(init.body) as unknown
      exists = true
      return jsonResponse(first)
    }
    if (path === '/v1/bgp/visibility') return jsonResponse({ items: exists ? [first] : [] })
    if (init?.method === 'DELETE') {
      deleteRequests++
      exists = false
      return new Response(null, { status: 204 })
    }
    return jsonResponse({ monitor: first, items: [] })
  })
  mount(['events.read', 'alert.write'])
  await user.click(screen.getByRole('button', { name: 'Open prefix visibility' }))
  await user.click(await screen.findByRole('button', { name: 'Set up monitoring' }))
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close dialog' }))
  expect(saved).toBeUndefined()
  await user.click(await screen.findByRole('button', { name: 'Set up monitoring' }))
  await user.type(screen.getByLabelText('Prefix', { exact: true }), first.prefix)
  await user.clear(screen.getByLabelText('Minimum visible peers (%)'))
  await user.type(screen.getByLabelText('Minimum visible peers (%)'), '90.25')
  await user.click(screen.getByLabelText('Alert on partial visibility'))
  await user.click(screen.getByRole('button', { name: 'Save monitor' }))
  await waitFor(() =>
    expect(saved).toEqual({
      prefix: first.prefix,
      minimum_visible_basis_points: 9025,
      alert_on_partial: false,
      alert_on_loss: true,
    }),
  )
  expect(await screen.findByText('Waiting for a complete collector archive.')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Remove monitor' }))
  expect(deleteRequests).toBe(0)
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close dialog' }))
  expect(deleteRequests).toBe(0)
  await user.click(screen.getByRole('button', { name: 'Remove monitor' }))
  const dialog = screen.getByRole('dialog', { name: 'Remove prefix monitor' })
  await user.click(within(dialog).getByRole('button', { name: 'Remove monitor and history' }))
  expect(await screen.findByText('No monitored prefixes yet.')).toBeInTheDocument()
  expect(deleteRequests).toBe(1)
})
