// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, test, vi } from 'vitest'
import type { BGPASPathEvent, BGPASPathHistory as PathHistory } from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { BGPASPathHistory } from '../routes/BGPASPathHistory'
import { TimeProvider } from '../time/TimeProvider'
import { jsonResponse } from './fetchStub'

const at = '2026-10-01T00:00:00Z'
const monitor = {
  id: '10000000-0000-4000-8000-000000000001',
  prefix: '192.0.2.0/24',
  minimum_visible_basis_points: 9500,
  alert_on_partial: true,
  alert_on_loss: true,
  created_at: at,
}
const current = {
  segments: [{ Kind: 2 as const, Values: [64499, 64500, 64500] }],
  facts: {
    selection_length: 3,
    possible_origins: [64500],
    origin_ambiguous: false,
    upstream_asn: 64499,
  },
}
const publicChange: BGPASPathEvent = {
  id: '20000000-0000-4000-8000-000000000001',
  observed_at: at,
  vantage: 'd'.repeat(64),
  sequence: '3',
  operation: 1,
  source_kind: 'public_mrt',
  source_epoch: 'a'.repeat(64),
  kind: 'path_change',
  has_path_id: true,
  path_id: 0,
  previous: {
    segments: [{ Kind: 2, Values: [64496, 64500] }],
    facts: {
      selection_length: 2,
      possible_origins: [64500],
      origin_ambiguous: false,
      upstream_asn: 64496,
    },
  },
  current,
  changes: {
    origin_changed: false,
    origin_evidence_changed: false,
    upstream_changed: true,
    length_changed: true,
    segments_changed: true,
  },
  public_source: {
    source: 'routeviews',
    collector: 'route-views.eqix',
    baseline_clock: at,
    archive_clock: at,
    baseline_sha256: 'a'.repeat(64),
    archive_sha256: 'b'.repeat(64),
    peer_address: '198.51.100.2',
    peer_asn: 64496,
    archive_record: 3,
    operation_index: 1,
    observed_unix_nanos: '1790812800000000000',
  },
  incidents: [{ id: '30000000-0000-4000-8000-000000000001', relation: 'same_public_archive' }],
}
const baseline: BGPASPathEvent = {
  ...publicChange,
  id: '20000000-0000-4000-8000-000000000002',
  kind: 'baseline',
  changes: undefined,
  previous: undefined,
  incidents: undefined,
}

function mount(respond: (url: URL) => Response) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) =>
      respond(new URL(String(input), 'http://probectl.test')),
    ),
  )
  render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <AuthContext.Provider
          value={{
            user: { id: 'user-a', email: 'operator@example.test', name: 'Operator' },
            tenant: { id: 'tenant-a', name: 'Tenant A', slug: 'tenant-a' },
            tenants: [],
            permissions: ['events.read', 'entities.read'],
            signOut: vi.fn(),
            switchTenant: vi.fn(),
          }}
        >
          <I18nProvider initialLocale="en">
            <TimeProvider>
              <BGPASPathHistory tenant="tenant-a" monitorID={monitor.id} prefix={monitor.prefix} />
            </TimeProvider>
          </I18nProvider>
        </AuthContext.Provider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function page(items: BGPASPathEvent[], nextCursor?: string) {
  return jsonResponse({
    monitor,
    items,
    coverage: items.length ? 'retained_points' : 'no_retained_points',
    effective_limit: 100,
    next_cursor: nextCursor,
  } satisfies PathHistory)
}

afterEach(() => vi.unstubAllGlobals())

test('filters the scoped history and renders the original prepend, digest and incident', async () => {
  const user = userEvent.setup()
  const requests: URL[] = []
  mount((url) => {
    requests.push(url)
    expect(url.pathname).toBe(`/v1/bgp/visibility/${monitor.id}/paths`)
    if (url.searchParams.get('cursor')) return page([baseline])
    if (url.searchParams.get('source') === 'router_bmp')
      return page([
        {
          ...publicChange,
          source_kind: 'router_bmp',
          public_source: undefined,
          router_view: 'operator_loc_rib',
          change_event_id: '40000000-0000-4000-8000-000000000001',
          incidents: undefined,
        },
      ])
    if (url.searchParams.get('vantage')) return page([publicChange])
    return page([publicChange], 'same-clock')
  })
  const timeline = await screen.findByRole('table', { name: /AS-path timeline/ })
  expect(within(timeline).getByText(/Upstream changed/)).toBeInTheDocument()
  await user.click(within(timeline).getByRole('button', { name: 'Path change' }))
  const detail = await screen.findByRole('dialog', { name: 'Path change' })
  expect(within(detail).getByText('AS64496 → AS64500')).toBeInTheDocument()
  expect(within(detail).getByText('AS64499 → AS64500 → AS64500')).toBeInTheDocument()
  expect(within(detail).getByText('b'.repeat(64))).toBeInTheDocument()
  expect(within(detail).getByRole('link', { name: /Visibility incident/ })).toHaveAttribute(
    'href',
    '/incidents?incident=30000000-0000-4000-8000-000000000001',
  )
  await user.click(within(detail).getByRole('button', { name: 'Close details' }))
  await user.click(screen.getByRole('button', { name: 'Load earlier AS paths' }))
  expect(await within(timeline).findByRole('button', { name: 'Baseline' })).toBeInTheDocument()
  const continuation = requests.find((url) => url.searchParams.get('cursor') === 'same-clock')
  expect(continuation?.searchParams.has('from')).toBe(false)
  await user.selectOptions(screen.getByLabelText('Path source'), 'public_mrt')
  expect(await screen.findByRole('button', { name: 'Path change' })).toBeInTheDocument()
  await user.selectOptions(screen.getByLabelText('Vantage'), publicChange.vantage)
  await user.selectOptions(screen.getByLabelText('History range'), 'all')
  expect(await screen.findByRole('button', { name: 'Path change' })).toBeInTheDocument()
  expect(requests.at(-1)?.searchParams.get('vantage')).toBe(publicChange.vantage)
  expect(requests.at(-1)?.searchParams.get('source')).toBe('public_mrt')
  expect(requests.at(-1)?.searchParams.get('from')).toBe('1970-01-01T00:00:00.000Z')
  await user.selectOptions(screen.getByLabelText('Path source'), 'router_bmp')
  await user.click(await screen.findByRole('button', { name: 'Path change' }))
  const privateDetail = await screen.findByRole('dialog', { name: 'Path change' })
  const href = within(privateDetail)
    .getByRole('link', { name: 'Open recorded routing change' })
    .getAttribute('href')
  const link = new URL(href ?? '', 'http://probectl.test')
  expect(link.pathname).toBe('/incidents')
  expect(link.searchParams.get('view')).toBe('changes')
  expect(link.searchParams.get('change_id')).toBe('40000000-0000-4000-8000-000000000001')
})

test('reports an empty selection and a refused private source without a route graph', async () => {
  const user = userEvent.setup()
  mount((url) =>
    url.searchParams.get('source') === 'router_bmp'
      ? jsonResponse({ error: 'source unavailable' }, 404)
      : page([]),
  )
  expect(await screen.findByText('No retained AS paths in this selection.')).toBeInTheDocument()
  await user.selectOptions(screen.getByLabelText('Path source'), 'router_bmp')
  expect(
    await screen.findByText('Could not load the authorized AS-path history.'),
  ).toBeInTheDocument()
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
})
