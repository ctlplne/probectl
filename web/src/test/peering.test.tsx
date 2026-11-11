// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AuthContext } from '../auth/AuthProvider'
import type {
  PeeringEstimateInput,
  PeeringEstimateResponse,
  PeeringRateEstimate,
} from '../api/sdk.gen'
import { PeeringEstimateCard } from '../routes/PeeringEstimateCard'
import { peeringGbps } from '../routes/peeringValues'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const contextID = '22222222-2222-4222-8222-222222222222'
const interfaceID = '33333333-3333-4333-8333-333333333333'
const permissions = ['flow.read', 'ai.query', 'entities.read', 'metrics.read', 'events.read']
const rate: PeeringRateEstimate = {
  selected_interval_bytes: '3787500000000',
  bits_per_second_numerator: '101000000000',
  bits_per_second_denominator: '1',
  intervals: 20,
  rank: 19,
  nonzero_intervals: 20,
}

function response(tenant: string): PeeringEstimateResponse {
  return {
    contract_version: 'probectl.peering-estimate.v1',
    preview: true,
    direction: 'inbound',
    reason: 'partial_routing_evidence',
    from: '2026-11-01T00:00:00.123456789Z',
    to: '2026-11-01T00:05:00.123456790Z',
    bucket_seconds: 300,
    source: 'raw',
    target: {
      context_id: contextID,
      interface_id: interfaceID,
      peer_asn: 4294967295,
      ix_id: '9223372036854775807',
      ix_lan_id: '9007199254740993',
      eligible: true,
      reason: 'current_owned_ix_evidence',
      valid_until: new Date(Date.now() + 60_000).toISOString(),
      prefix_sources: [`${tenant}-prefix`],
      membership_sources: Array.from({ length: 5001 }, (_, i) => `${tenant}-membership-${i}`),
    },
    coverage: {
      observed_intervals: 20,
      expected_intervals: 20,
      complete_observed_inputs: true,
      complete_routing_classification: false,
    },
    bytes: { unavailable_transit: '184467440737095516160000' },
    known_eligible_p95: rate,
    transit: [],
    interpretation: 'Observed routing inputs only. No live-session or guaranteed-savings claim.',
  }
}

function Harness() {
  const [tenant, setTenant] = useState('red')
  const [allowed, setAllowed] = useState(true)
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        tenants: [],
        user: { id: 'reader', name: 'Reader', email: 'reader@local.test' },
        permissions: allowed ? permissions : permissions.filter((p) => p !== 'events.read'),
        switchTenant: () => {},
        signOut: () => {},
      }}
    >
      <main>
        <button onClick={() => setTenant('blue')}>Switch peering tenant</button>
        <button onClick={() => setAllowed(false)}>Withdraw peering source permission</button>
        <PeeringEstimateCard />
      </main>
    </AuthContext.Provider>
  )
}

function fixture(answer: (input: PeeringEstimateInput) => Promise<Response>) {
  const fallback = defaultFetch()
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === '/v1/entity-contexts')
      return Promise.resolve(
        jsonResponse({
          items: [{ context_id: contextID, site_label: 'Owned site', vrf_label: 'private' }],
        }),
      )
    if (pathOf(input) === '/v1/entities')
      return Promise.resolve(
        jsonResponse({
          items: [{ id: interfaceID, kind: 'interface', label: 'Owned IX interface' }],
        }),
      )
    if (pathOf(input) === '/v1/flows/peering-estimate')
      return answer(JSON.parse(String(init?.body)) as PeeringEstimateInput)
    return fallback(input, init)
  })
}

async function fill() {
  const details = screen.getByText('Configure a hypothetical peering').closest('details')!
  if (!details.open) {
    details.open = true
    fireEvent(details, new Event('toggle'))
  }
  const context = await screen.findByRole('combobox', { name: 'Peering routing context' })
  await screen.findByRole('option', { name: 'Owned site / private' })
  fireEvent.change(context, { target: { value: contextID } })
  await screen.findByRole('option', { name: `Owned IX interface · ${interfaceID}` })
  fireEvent.change(screen.getByRole('combobox', { name: 'Owned IX interface' }), {
    target: { value: interfaceID },
  })
  for (const [name, value] of [
    ['Peer ASN', '4294967295'],
    ['IX ID', '9223372036854775807'],
    ['IX LAN ID', '9007199254740993'],
    ['Peering from (RFC3339, optional)', '2026-11-01T00:00:00.123456789Z'],
    ['Peering to (RFC3339, optional)', '2026-11-01T00:05:00.123456790Z'],
  ])
    fireEvent.change(screen.getByRole('textbox', { name }), { target: { value } })
}

for (const theme of ['light', 'dark']) {
  test(`qualified peering keeps exact identities, complete references and accessible controls in ${theme}`, async () => {
    const previous = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: { getItem: () => theme, setItem: vi.fn() },
    })
    try {
      let seen: PeeringEstimateInput | undefined
      fixture(async (input) => {
        seen = input
        return jsonResponse(response('red'))
      })
      const view = render(
        <Providers>
          <Harness />
        </Providers>,
      )
      await fill()
      fireEvent.click(screen.getByRole('button', { name: 'Estimate observed peering traffic' }))
      const result = await screen.findByRole('region', { name: 'Peering estimate result' })
      expect(seen?.ix_id).toBe('9223372036854775807')
      expect(seen?.ix_lan_id).toBe('9007199254740993')
      expect(seen?.from).toBe('2026-11-01T00:00:00.123456789Z')
      expect(seen?.to).toBe('2026-11-01T00:05:00.123456790Z')
      expect(within(result).getByText('101.000 Gbps')).toBeInTheDocument()
      expect(within(result).getByText('184467440737095516160000')).toBeInTheDocument()
      expect(within(result).getByText(/Partial routing evidence/)).toBeInTheDocument()
      const evidence = within(result)
        .getByText('Complete target evidence references')
        .closest('details')!
      evidence.open = true
      fireEvent(evidence, new Event('toggle'))
      const references = within(result).getByRole('textbox', {
        name: 'All membership sources (5001)',
        hidden: true,
      })
      expect(references.value.split('\n')).toHaveLength(5001)
      expect(references.value).toContain('red-membership-5000')
      expect(document.documentElement).toHaveAttribute('data-theme', theme)
      expect(await axe(view.container)).toHaveNoViolations()
      fireEvent.change(screen.getByRole('textbox', { name: 'Peer ASN' }), {
        target: { value: '64500' },
      })
      expect(
        screen.queryByRole('region', { name: 'Peering estimate result' }),
      ).not.toBeInTheDocument()
    } finally {
      if (previous) Object.defineProperty(window, 'localStorage', previous)
    }
  })
}

test('late peering results never cross a tenant or permission change', async () => {
  let resolve: ((value: Response) => void) | undefined
  fixture(
    () =>
      new Promise<Response>((done) => {
        resolve = done
      }),
  )
  render(
    <Providers>
      <Harness />
    </Providers>,
  )
  await fill()
  fireEvent.click(screen.getByRole('button', { name: 'Estimate observed peering traffic' }))
  await waitFor(() => expect(resolve).toBeDefined())
  fireEvent.click(screen.getByRole('button', { name: 'Switch peering tenant' }))
  await act(async () => {
    resolve!(jsonResponse(response('red')))
  })
  expect(screen.queryByRole('region', { name: 'Peering estimate result' })).not.toBeInTheDocument()
  expect(screen.queryByText('184467440737095516160000')).not.toBeInTheDocument()
  expect(screen.getByRole('textbox', { name: 'Peer ASN' })).toHaveValue('')
  fireEvent.click(screen.getByRole('button', { name: 'Withdraw peering source permission' }))
  expect(screen.queryByText('Peering estimate · preview')).not.toBeInTheDocument()
})

test('missing observed intervals stay unavailable and exact display never narrows wide counters', async () => {
  fixture(async () => {
    const out = response('red')
    out.coverage.complete_observed_inputs = false
    out.coverage.observed_intervals = 19
    delete out.known_eligible_p95
    return jsonResponse(out)
  })
  render(
    <Providers>
      <Harness />
    </Providers>,
  )
  await fill()
  fireEvent.click(screen.getByRole('button', { name: 'Estimate observed peering traffic' }))
  await screen.findByText('Missing observed intervals: no p95 is available.')
  expect(screen.queryByText('101.000 Gbps')).not.toBeInTheDocument()
  expect(
    peeringGbps({
      ...rate,
      bits_per_second_numerator:
        '115792089237316195423570985008687907853269984665640564039457584007913129639936',
    }),
  ).toBe('115792089237316195423570985008687907853269984665640564039457584007913.129 Gbps')
})
