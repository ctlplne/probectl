// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'
import type { BMPSessionHistory as History, BMPSessionPoint } from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { BMPSessionHistory } from '../routes/BMPSessionHistory'
import { TimeProvider } from '../time/TimeProvider'
import { jsonResponse } from './fetchStub'

const at = '2026-11-20T00:00:00Z'
const source = {
  router_id: '10000000-0000-4000-8000-000000000001',
  context_id: '20000000-0000-4000-8000-000000000001',
  collector_agent_id: 'bmp-listener',
  source_ref: 'bmp-router',
}
const peer = {
  peer_address: '192.0.2.2',
  peer_asn: 64497,
  bgp_identifier: '192.0.2.3',
  flags: 0,
  peer_type: 0,
  filtered: false,
  view: 'adj_rib_in_pre_policy' as const,
  original_clock: at,
}
const observation = {
  connection_id: '30000000-0000-4000-8000-000000000001',
  coverage_gap: false,
  evidence_digest: 'b'.repeat(64),
  observed_at: at,
  observed_unix_nanos: '1795132800000000000',
}
const maximum = '18446744073709551615'

function mount(respond: (url: URL) => Response, permissions = ['events.read', 'entities.read']) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const fetch = vi.fn(async (input: RequestInfo | URL) =>
    respond(new URL(String(input), 'http://probectl.test')),
  )
  vi.stubGlobal('fetch', fetch)
  render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider
        value={{
          user: { id: 'user-a', email: 'operator@example.test', name: 'Operator' },
          tenant: { id: 'tenant-a', name: 'Tenant A', slug: 'tenant-a' },
          tenants: [],
          permissions,
          signOut: vi.fn(),
          switchTenant: vi.fn(),
        }}
      >
        <I18nProvider initialLocale="en">
          <TimeProvider>
            <BMPSessionHistory />
          </TimeProvider>
        </I18nProvider>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
  return fetch
}

function page(items: BMPSessionPoint[], nextCursor?: string) {
  return jsonResponse({
    source,
    items,
    next_cursor: nextCursor,
    coverage: items.length ? 'retained_points' : 'no_retained_points',
    effective_limit: 100,
  } satisfies History)
}

afterEach(() => vi.unstubAllGlobals())

test('keeps original counters and uses the selected router identity across pages', async () => {
  const user = userEvent.setup()
  const requests: URL[] = []
  mount((url) => {
    requests.push(url)
    if (url.searchParams.has('cursor'))
      return page([
        { ...observation, coverage_gap: true, kind: 'transport_closed', sequence: '3' },
        {
          ...observation,
          kind: 'termination',
          sequence: '2',
          lifecycle: { reason: 65535, reason_known: false, terminated: true },
        },
        {
          ...observation,
          kind: 'update_churn',
          sequence: '1',
          update_churn: { peer, updates: '17', first_observed_at: at, last_observed_at: at },
        },
      ])
    return page(
      [
        {
          ...observation,
          kind: 'statistics',
          sequence: '5',
          statistics: { peer, samples: [{ type: 9, value: maximum, counter: false }] },
          range_status: 'within_range',
        },
        {
          ...observation,
          kind: 'neighbor',
          sequence: '4',
          neighbor: {
            peer,
            frame_digest: observation.evidence_digest,
            state: 'down',
            down_reason: 3,
            notification_code: 6,
            notification_subcode: 3,
          },
        },
      ],
      'original-clock',
    )
  })

  await user.click(screen.getByRole('button', { name: 'Open session history' }))
  await user.type(screen.getByLabelText('Router ID'), source.router_id)
  await user.type(screen.getByLabelText('Routing context ID'), source.context_id)
  await user.type(screen.getByLabelText('Listener agent ID'), source.collector_agent_id)
  await user.type(screen.getByLabelText('Router source reference'), source.source_ref)
  await user.type(screen.getByLabelText('Neighbor IP address'), peer.peer_address)
  await user.click(screen.getByText('Compare a RIB gauge with an expected range'))
  await user.type(screen.getByLabelText('BMP gauge type'), '9')
  await user.type(screen.getByLabelText('Expected minimum'), '0')
  await user.type(screen.getByLabelText('Expected maximum'), maximum)
  await user.click(screen.getByRole('button', { name: 'Load session history' }))

  const firstPage = await screen.findByRole('table', { name: 'BMP session history' })
  expect(within(firstPage).getByText(maximum)).toBeInTheDocument()
  expect(within(firstPage).getByText('within range')).toBeInTheDocument()
  expect(within(firstPage).getByText('BGP notification 6/3')).toBeInTheDocument()
  expect(requests[0].pathname).toBe(`/v1/bgp/sessions/${source.router_id}`)
  expect(requests[0].searchParams.get('peer')).toBe(peer.peer_address)
  expect(requests[0].searchParams.get('expected_max')).toBe(maximum)

  await user.click(screen.getByRole('button', { name: 'Next page' }))
  expect(await screen.findByText('Peer state is unknown after disconnect')).toBeInTheDocument()
  expect(screen.getByText('Observation gap')).toBeInTheDocument()
  expect(screen.getByText('Unknown termination reason 65535')).toBeInTheDocument()
  expect(screen.getByText('17 UPDATE frames')).toBeInTheDocument()
  expect(Object.fromEntries(requests[1].searchParams)).toEqual({
    context_id: source.context_id,
    collector_agent_id: source.collector_agent_id,
    source_ref: source.source_ref,
    cursor: 'original-clock',
  })

  await user.click(screen.getByRole('button', { name: 'Previous page' }))
  expect(await screen.findByText(maximum)).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Hide session history' }))
  expect(screen.queryByRole('table', { name: 'BMP session history' })).not.toBeInTheDocument()
})

test('hides session history without the inventory permission', () => {
  const fetch = mount(() => page([]), ['events.read'])
  expect(screen.queryByRole('button', { name: 'Open session history' })).not.toBeInTheDocument()
  expect(fetch).not.toHaveBeenCalled()
})
