// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AuthContext } from '../auth/AuthProvider'
import { IncidentImpactCard } from '../routes/IncidentImpactCard'
import type { Incident } from '../api/incidents'
import type { IncidentImpactResponse } from '../api/sdk.gen'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const id = '11111111-1111-4111-8111-111111111111'
const context = '22222222-2222-4222-8222-222222222222'
const prefix = '33333333-3333-4333-8333-333333333333'
const permissions = [
  'incident.read',
  'flow.read',
  'entities.read',
  'metrics.read',
  'events.read',
  'tags.read',
]
const incident: Incident = {
  id,
  tenant_id: 'red',
  status: 'open',
  severity: 'warning',
  title: 'Owned incident',
  started_at: '2026-11-01T00:00:00Z',
  last_seen_at: '2026-11-01T00:01:00Z',
  signal_count: 1,
}

function response(tenant: string): IncidentImpactResponse {
  const counters = {
    raw_bytes: '18446744073709551615',
    raw_packets: '7',
    scaled_bytes: '55340232221128654845',
    scaled_packets: '21',
  }
  return {
    contract_version: 'probectl.incident-impact.v1',
    preview: true,
    incident_id: id,
    evaluated_at: '2026-11-01T00:02:00Z',
    current: {
      from: incident.started_at,
      to: incident.last_seen_at,
      attested_records: 1,
      unverified_records: 0,
      coverage: 'observed_attested_records',
      observed_totals: counters,
      captures: [],
    },
    previous: {
      from: '2026-10-25T00:00:00Z',
      to: '2026-10-25T00:01:00Z',
      attested_records: 0,
      unverified_records: 0,
      coverage: 'no_observed_records',
      captures: [],
    },
    members: [],
    unresolved_root: false,
    unresolved_signal_ids: [],
    customer_coverage: 'observed_flow_prefixes_only_tests_and_slos_not_evaluated',
    unclassified_records: 0,
    customers: Array.from({ length: 201 }, (_, i) => ({
      tag_key: 'customer',
      value: `${tenant} customer ${String(i).padStart(3, '0')}`,
      context_id: context,
      prefix_ids: [prefix],
      test_ids: [],
      slo_ids: [],
      capture_keys: ['original-capture'],
      current_observed_totals: counters,
    })),
    interpretation: 'Exact observed counters with explicit original-source coverage.',
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
        permissions: allowed ? permissions : ['incident.read'],
        switchTenant: () => {},
        signOut: () => {},
      }}
    >
      <main>
        <button onClick={() => setTenant('blue')}>Switch impact tenant</button>
        <button onClick={() => setAllowed(false)}>Withdraw impact access</button>
        <IncidentImpactCard incident={incident} />
      </main>
    </AuthContext.Provider>
  )
}

for (const theme of ['light', 'dark'])
  test(`incident impact preserves exact values and every customer page in ${theme}`, async () => {
    document.documentElement.dataset.theme = theme
    const fallback = defaultFetch()
    let selected: Record<string, string> | undefined
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === `/v1/incidents/${id}/impact`) {
        selected = JSON.parse(String(init?.body))
        return Promise.resolve(jsonResponse(response('red')))
      }
      return fallback(input, init)
    })
    const view = render(
      <Providers>
        <Harness />
      </Providers>,
    )
    fireEvent.change(screen.getByLabelText('Customer tag key (optional)'), {
      target: { value: 'customer' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Compare incident impact' }))
    await screen.findByRole('region', { name: 'Incident impact result' })
    expect(selected).toMatchObject({
      customer_tag_key: 'customer',
      from: '2026-11-01T00:00:00.000Z',
      to: '2026-11-01T00:01:00.000Z',
    })
    expect(screen.getAllByText('55340232221128654845').length).toBeGreaterThan(0)
    expect(screen.getByText('red customer 000')).toBeInTheDocument()
    expect(screen.queryByText('red customer 200')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next customer page' }))
    expect(screen.getByText('red customer 200')).toBeInTheDocument()
    expect(screen.getByText('Customer page 2 of 2; 201 customers total')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw impact access' }))
    expect(screen.queryByRole('region', { name: 'Incident impact result' })).not.toBeInTheDocument()
    view.unmount()
  })

test('late incident impact completion cannot disclose the previous tenant', async () => {
  const fallback = defaultFetch()
  let resolve: ((value: Response) => void) | undefined
  let pending: AbortSignal | undefined
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === `/v1/incidents/${id}/impact`) {
      pending = init?.signal ?? undefined
      return new Promise<Response>((done) => {
        resolve = done
      })
    }
    return fallback(input, init)
  })
  const view = render(
    <Providers>
      <Harness />
    </Providers>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Compare incident impact' }))
  await waitFor(() => expect(resolve).toBeDefined())
  fireEvent.click(screen.getByRole('button', { name: 'Switch impact tenant' }))
  expect(pending?.aborted).toBe(true)
  await act(async () => {
    resolve?.(jsonResponse(response('red')))
  })
  expect(screen.queryByRole('region', { name: 'Incident impact result' })).not.toBeInTheDocument()
  expect(screen.queryByText('red customer 000')).not.toBeInTheDocument()
  view.unmount()
})
