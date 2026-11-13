// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AuthContext } from '../auth/AuthProvider'
import { IncidentImpactCard } from '../routes/IncidentImpactCard'
import { TimeProvider } from '../time/TimeProvider'
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
    test_coverage: 'not_evaluated',
  }
}

function Harness({
  canExport = false,
  canReadTests = false,
}: {
  canExport?: boolean
  canReadTests?: boolean
}) {
  const [tenant, setTenant] = useState('red')
  const [allowed, setAllowed] = useState(true)
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        tenants: [],
        user: { id: 'reader', name: 'Reader', email: 'reader@local.test' },
        permissions: allowed
          ? [
              ...permissions,
              ...(canExport ? ['ai.query'] : []),
              ...(canReadTests ? ['test.read'] : []),
            ]
          : ['incident.read'],
        switchTenant: () => {},
        signOut: () => {},
      }}
    >
      <TimeProvider>
        <main>
          <button onClick={() => setTenant('blue')}>Switch impact tenant</button>
          <button onClick={() => setAllowed(false)}>Withdraw impact access</button>
          <IncidentImpactCard incident={incident} />
        </main>
      </TimeProvider>
    </AuthContext.Provider>
  )
}

test('configured outcome selection keeps every original citation and unknown coverage', async () => {
  const fallback = defaultFetch()
  let selected: Record<string, unknown> | undefined
  const value = response('red')
  value.test_coverage = 'current_explicit_sources_original_observations'
  const observations = Array.from({ length: 201 }, (_, index) => ({
    evidence_id: `40000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`,
    digest: 'a'.repeat(64),
    observed_at: incident.started_at,
    status: 'failed' as const,
    reason: 'original_attested_test_observation',
  }))
  value.tests = [
    {
      context_id: context,
      entity_id: prefix,
      test_id: id,
      agent_id: 'owned-agent',
      name: 'Owned application',
      type: 'http',
      definition_digest: 'b'.repeat(64),
      current: {
        from: incident.started_at,
        to: incident.last_seen_at,
        coverage: 'observed_attested_test_outcomes',
        successful: 0,
        failed: 201,
        unknown: 0,
        canceled: 0,
        observations,
      },
      previous: {
        from: value.previous.from,
        to: value.previous.to,
        coverage: 'no_retained_observations',
        successful: 0,
        failed: 0,
        unknown: 0,
        canceled: 0,
        observations: [],
      },
    },
  ]
  value.slo_coverage = 'observed_failed_sli_inputs_only_not_a_rolling_budget_verdict'
  value.slos = [
    {
      name: 'checkout-availability',
      display_name: 'Checkout objective',
      service: 'checkout',
      definition_digest: 'c'.repeat(64),
      objective_ratio: '0.9999999999999999',
      window: '24h0m0s',
      basis: 'observed_failed_sli_inputs_only_not_a_rolling_budget_verdict',
      current: {
        failed_inputs: 1,
        sources: [
          {
            context_id: context,
            entity_id: prefix,
            test_id: id,
            agent_id: 'owned-agent',
            evidence_ids: [observations[0].evidence_id],
          },
        ],
      },
      previous: { failed_inputs: 0, sources: [] },
    },
  ]
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === `/v1/incidents/${id}/impact`) {
      selected = JSON.parse(String(init?.body))
      return Promise.resolve(jsonResponse(value))
    }
    return fallback(input, init)
  })
  const view = render(
    <Providers>
      <Harness canReadTests />
    </Providers>,
  )
  fireEvent.click(screen.getByLabelText('Include original configured-test outcomes'))
  fireEvent.click(screen.getByRole('button', { name: 'Compare incident impact' }))
  const current = await screen.findByRole('region', { name: 'Current test window' })
  expect(selected?.include_tests).toBe(true)
  expect(
    screen.getByRole('region', { name: 'SLO failed inputs: checkout-availability' }),
  ).toBeInTheDocument()
  expect(screen.getByText('0.9999999999999999')).toBeInTheDocument()
  expect(within(current).getByText(observations[0].evidence_id)).toBeInTheDocument()
  expect(within(current).queryByText(observations[200].evidence_id)).not.toBeInTheDocument()
  fireEvent.click(
    within(current).getByRole('button', { name: 'Next observations for Current test window' }),
  )
  expect(within(current).getByText(observations[200].evidence_id)).toBeInTheDocument()
  expect(
    within(current).getByText('Observation page 2 of 2; 201 observations total'),
  ).toBeInTheDocument()
  expect(screen.getByText('No retained observations; coverage is unavailable.')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Switch impact tenant' }))
  expect(screen.queryByRole('region', { name: 'Current test window' })).not.toBeInTheDocument()
  view.unmount()
})

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
      from: incident.started_at,
      to: incident.last_seen_at,
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

test('impact query and signed export preserve a one-nanosecond window and discard a late foreign download', async () => {
  const fallback = defaultFetch()
  const from = '2026-11-01T00:00:00.123456789Z',
    to = '2026-11-01T00:00:00.123456790Z'
  let selected: Record<string, string> | undefined
  let exported: { impact: Record<string, string> } | undefined
  let finish: ((value: Response) => void) | undefined
  let signal: AbortSignal | undefined
  const create = vi.fn(() => 'blob:owned-impact')
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  const revoke = vi.fn()
  const originalRevoke = Object.getOwnPropertyDescriptor(URL, 'revokeObjectURL')
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revoke })
  const original = Object.getOwnPropertyDescriptor(URL, 'createObjectURL')
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: create })
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === `/v1/incidents/${id}/impact`) {
      selected = JSON.parse(String(init?.body))
      const value = response('red')
      value.current.from = from
      value.current.to = to
      return Promise.resolve(jsonResponse(value))
    }
    if (pathOf(input) === `/v1/incidents/${id}/exports`) {
      exported = JSON.parse(String(init?.body))
      signal = init?.signal ?? undefined
      return new Promise<Response>((resolve) => {
        finish = resolve
      })
    }
    return fallback(input, init)
  })
  const view = render(
    <Providers>
      <Harness canExport />
    </Providers>,
  )
  try {
    fireEvent.change(screen.getByLabelText('Impact from (ISO 8601 with offset)'), {
      target: { value: from },
    })
    fireEvent.change(screen.getByLabelText('Impact to (exclusive, ISO 8601 with offset)'), {
      target: { value: to },
    })
    fireEvent.change(screen.getByLabelText('Customer tag key (optional)'), {
      target: { value: 'customer' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Compare incident impact' }))
    await screen.findByRole('region', { name: 'Incident impact result' })
    expect(selected).toMatchObject({ from, to, customer_tag_key: 'customer' })
    expect(screen.getByText(from)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Export signed impact evidence' }))
    await waitFor(() => expect(finish).toBeDefined())
    expect(exported).toEqual({
      impact: { from, to, dataseries: 'auto', customer_tag_key: 'customer' },
    })
    await act(async () => {
      finish?.(jsonResponse({ signing: {}, attachments: [], manifest: {} }))
    })
    await screen.findByText(
      "Downloaded a fresh signed evidence package. Verify it offline and pin the operator's signing-key fingerprint.",
    )
    expect(create).toHaveBeenCalledTimes(1)
    expect(click).toHaveBeenCalledTimes(1)
    expect(revoke).toHaveBeenCalledWith('blob:owned-impact')
    create.mockClear()
    click.mockClear()
    finish = undefined
    fireEvent.click(screen.getByRole('button', { name: 'Export signed impact evidence' }))
    await waitFor(() => expect(finish).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: 'Switch impact tenant' }))
    expect(signal?.aborted).toBe(true)
    await act(async () => {
      finish?.(jsonResponse({ signing: {}, attachments: [], manifest: {} }))
    })
    expect(create).not.toHaveBeenCalled()
    expect(
      screen.queryByText(
        "Downloaded a fresh signed evidence package. Verify it offline and pin the operator's signing-key fingerprint.",
      ),
    ).not.toBeInTheDocument()
  } finally {
    view.unmount()
    click.mockRestore()
    if (originalRevoke) Object.defineProperty(URL, 'revokeObjectURL', originalRevoke)
    else Reflect.deleteProperty(URL, 'revokeObjectURL')
    if (original) Object.defineProperty(URL, 'createObjectURL', original)
    else Reflect.deleteProperty(URL, 'createObjectURL')
  }
})
