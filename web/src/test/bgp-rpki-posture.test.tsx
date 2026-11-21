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
import type { BGPRPKICurrentPosture, BGPRPKIVerdict } from '../api/sdk.gen'
import { AuthContext } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { BGPRPKIPosture } from '../routes/BGPRPKIPosture'
import { TimeProvider } from '../time/TimeProvider'
import { jsonResponse } from './fetchStub'

const clock = '2026-11-20T00:00:00Z'
const snapshot = '2026-11-19T23:59:00Z'
const monitor = {
  id: '10000000-0000-4000-8000-000000000001',
  prefix: '192.0.2.0/24',
  minimum_visible_basis_points: 9500,
  alert_on_partial: true,
  alert_on_loss: true,
  created_at: clock,
}
const context = { context_id: 'context-a', site_label: 'Owned site', vrf_label: 'Transit' }
const prefix = {
  id: 'prefix-a',
  kind: 'prefix',
  network_prefix: monitor.prefix,
  label: 'Owned net',
}
const origin = 64498
const invalid: BGPRPKIVerdict = {
  status: 'invalid',
  reason: 'origin_mismatch',
  covering: [{ prefix: monitor.prefix, max_length: 24, asn: 64497 }],
  validator_version: 'a'.repeat(64),
  validator_observed_at: snapshot,
}

afterEach(() => vi.unstubAllGlobals())

test('reaches the exact owned prefix and keeps earlier validation after the live source is lost', async () => {
  const user = userEvent.setup()
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const postureReads: URL[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input), 'http://probectl.test')
      switch (url.pathname) {
        case '/v1/entity-contexts':
          return jsonResponse({ items: [context] })
        case '/v1/entities':
          expect(url.searchParams.get('context_id')).toBe(context.context_id)
          return url.searchParams.has('cursor')
            ? jsonResponse({ items: [prefix] })
            : jsonResponse({ items: [], next_cursor: 'next-inventory-page' })
        case `/v1/bgp/visibility/${monitor.id}/rpki-posture`: {
          postureReads.push(url)
          const live = postureReads.length === 1
          return jsonResponse({
            as_of: clock,
            context_id: context.context_id,
            coverage: 'observed_source_population',
            monitor_id: monitor.id,
            prefix: monitor.prefix,
            prefix_id: prefix.id,
            paths: [
              {
                generation: 'current-generation',
                has_path_id: true,
                origin_asn: origin,
                path_id: 7,
                router_id: 'owned-router',
                view_observed_at: clock,
                vantage: 'first-listener',
                rpki: live
                  ? { ...invalid, suggestion: { prefix: monitor.prefix, origin_asn: origin } }
                  : { status: 'unknown', reason: 'validator_unavailable', covering: [] },
                irr: [
                  {
                    source: 'LAB',
                    status: 'origin_mismatch',
                    observed_at: snapshot,
                    sha256: 'b'.repeat(64),
                    terms: 'https://registry.example/terms',
                    rpki_filtered: true,
                    objects: [
                      {
                        origin_asn: 64497,
                        modified_at: '2024-10-01T00:00:00Z',
                        review: 'past_review_age',
                      },
                      { origin_asn: 64496, review: 'clock_unavailable' },
                    ],
                  },
                  { source: 'SECOND', status: 'unavailable', rpki_filtered: false, objects: [] },
                ],
                related_hijacks: live
                  ? [{ incident_id: 'owned-incident', observed_at: clock }]
                  : [],
              },
            ],
            trend: [
              {
                id: 'original-route',
                observed_at: clock,
                origin_asn: origin,
                vantage: 'first-listener',
                posture: invalid,
              },
            ],
          } satisfies BGPRPKICurrentPosture)
        }
        default:
          throw new Error(`Unexpected request to ${url.pathname}`)
      }
    }),
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
              <BGPRPKIPosture tenant="tenant-a" monitor={monitor} />
            </TimeProvider>
          </I18nProvider>
        </AuthContext.Provider>
      </QueryClientProvider>
    </MemoryRouter>,
  )

  await screen.findByRole('option', { name: 'Owned site / Transit' })
  await user.selectOptions(
    screen.getByRole('combobox', { name: 'Routing context' }),
    context.context_id,
  )
  await user.click(await screen.findByRole('button', { name: 'Search more owned prefixes' }))
  await user.type(await screen.findByLabelText('Intended origin ASN (optional)'), String(origin))
  await user.click(screen.getByRole('button', { name: 'Check RPKI posture' }))

  const current = await screen.findByRole('table', {
    name: `Current RPKI posture for ${monitor.prefix}`,
  })
  const trend = screen.getByRole('table', { name: 'RPKI trend for retained route observations' })
  expect(within(current).getByText(`${monitor.prefix} from AS${origin}`)).toBeInTheDocument()
  await user.click(within(current).getByText('LAB · Different registered origin'))
  expect(within(current).getByText(/Due for review/)).toBeInTheDocument()
  expect(within(current).getByText(/Modification time unavailable/)).toBeInTheDocument()
  expect(within(current).getByText('Registry filtered by RPKI')).toBeInTheDocument()
  expect(within(current).getByText('SECOND · Snapshot unavailable')).toBeInTheDocument()
  expect(within(current).getByRole('link', { name: 'LAB terms' })).toHaveAttribute(
    'href',
    'https://registry.example/terms',
  )
  expect(within(current).getByRole('link', { name: /Possible hijack/ })).toHaveAttribute(
    'href',
    '/incidents?incident=owned-incident',
  )
  expect(within(trend).getByText('Invalid')).toBeInTheDocument()
  expect(Object.fromEntries(postureReads[0].searchParams)).toEqual({
    context_id: context.context_id,
    prefix_id: prefix.id,
    intended_asn: String(origin),
  })

  await user.click(screen.getByRole('button', { name: 'Check RPKI posture' }))
  expect(await within(current).findByText('Unknown')).toBeInTheDocument()
  expect(within(current).queryByText(`${monitor.prefix} from AS${origin}`)).not.toBeInTheDocument()
  expect(within(trend).getByText('Invalid')).toBeInTheDocument()
})
