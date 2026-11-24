// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useState } from 'react'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { axe } from 'jest-axe'
import { expect, test, vi } from 'vitest'
import { Providers } from '../App'
import { AuthContext } from '../auth/AuthProvider'
import type {
  CapacityAgreement,
  CarrierSLAStatement,
  CapacityAgreementInput,
  CapacityAgreementBill,
  CapacityBillInput,
  CapacityForecastInput,
  CapacityForecastMeasurement,
  CapacityAgreementPage,
  RoutingTransferInput,
  RoutingTransferResponse,
} from '../api/sdk.gen'
import { CapacityAgreementsPage } from '../routes/CapacityAgreementsPage'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const base = '/v1/flows/capacity/agreements'
const transferPath = '/v1/flows/routing-transfer-estimate'
const version = '9007199254740993'
const unitPrice = '1.250000000000000000000000000001'
const item = (tenant: string): CapacityAgreement => ({
  id: `${tenant}-agreement`,
  current_version: version,
  version,
  definition: {
    name: `${tenant} WAN`,
    reference: `${tenant} private terms`,
    valid_from: '2026-11-01T00:00:00.123456789Z',
    target: {
      kind: 'interface',
      context_id: '22222222-2222-4222-8222-222222222222',
      interface_id: '33333333-3333-4333-8333-333333333333',
    },
    billing_day: 31,
    timezone: 'Asia/Kathmandu',
    direction: 'max_directional_percentiles',
    currency: 'USD',
    commit_bps: '100000000000.000000000000000001',
    unit_bps: '1000000',
    unit_price: unitPrice,
  },
  target_present: true,
  created_at: '2026-11-01T01:00:00Z',
  updated_at: '2026-11-01T01:00:00Z',
  recorded_at: '2026-11-01T01:00:00Z',
})
const page = (tenant: string): CapacityAgreementPage => ({
  items: [item(tenant)],
  has_more: false,
  as_of: '2026-11-01T01:00:00Z',
})

function Harness({
  switched,
  write = true,
  forecastOnly = false,
  reportWrite = false,
  estimate = false,
}: {
  switched?: () => void
  write?: boolean
  forecastOnly?: boolean
  reportWrite?: boolean
  estimate?: boolean
}) {
  const [tenant, setTenant] = useState('red')
  const [allowed, setAllowed] = useState(true)
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        tenants: [],
        user: { id: `${tenant}-reader`, name: 'Financial reader', email: 'reader@local.test' },
        permissions: allowed
          ? forecastOnly
            ? ['flow.read']
            : [
                'flow.agreements.read',
                ...(write ? ['flow.agreements.write'] : []),
                ...(reportWrite ? ['metrics.read', 'metrics.write'] : []),
                ...(estimate
                  ? ['topology.read', 'flow.read', 'entities.read', 'metrics.read', 'events.read']
                  : []),
              ]
          : [],
        switchTenant: () => {},
        signOut: () => {},
      }}
    >
      <main>
        <button
          onClick={() => {
            switched?.()
            setTenant('blue')
          }}
        >
          Switch financial tenant
        </button>
        <button onClick={() => setAllowed(false)}>Withdraw financial permission</button>
        <CapacityAgreementsPage />
      </main>
    </AuthContext.Provider>
  )
}
function mount(props: Parameters<typeof Harness>[0] = {}) {
  return render(
    <Providers>
      <MemoryRouter>
        <Harness {...props} />
      </MemoryRouter>
    </Providers>,
  )
}
function fixture(answer: (url: URL, init?: RequestInit) => Promise<Response>) {
  const fallback = defaultFetch()
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path.startsWith('/v1/flows/capacity/') || path === transferPath)
      return answer(new URL(String(input), 'https://local.test'), init)
    return fallback(input, init)
  })
}

test('financial screen keeps exact revisions, complete history, CAS deletion and independent read authority', async () => {
  const seen: Array<{
    path: string
    method: string
    body?: CapacityAgreementInput
    search: string
  }> = []
  let removed = false
  fixture(async (url, init) => {
    seen.push({
      path: url.pathname,
      method: init?.method ?? 'GET',
      body: init?.body ? (JSON.parse(String(init.body)) as CapacityAgreementInput) : undefined,
      search: url.search,
    })
    if (init?.method === 'DELETE') {
      removed = true
      return new Response(null, { status: 204 })
    }
    if (init?.method === 'PUT') return jsonResponse(item('red'))
    if (url.pathname.endsWith('/revisions'))
      return jsonResponse({
        ...page('red'),
        has_more: !url.searchParams.get('after'),
        next: version,
      })
    if (url.pathname === base)
      return jsonResponse(removed ? { ...page('red'), items: [] } : page('red'))
    return jsonResponse(item('red'))
  })
  mount()
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
  await screen.findByRole('button', { name: 'Save revised terms' })
  expect(screen.getByLabelText('Recorded unit price')).toHaveValue(unitPrice)
  expect(screen.getByLabelText('Recorded commit (bps)')).toHaveValue(
    '100000000000.000000000000000001',
  )
  fireEvent.change(screen.getByLabelText('Recorded unit price'), {
    target: { value: '-0.000000000000000000000000000001' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Save revised terms' }))
  await waitFor(() => expect(seen.some((x) => x.method === 'PUT')).toBe(true))
  const saved = seen.find((x) => x.method === 'PUT')!.body!
  expect(saved.version).toBe(version)
  expect(saved.definition.unit_price).toBe('-0.000000000000000000000000000001')
  expect(saved.definition.valid_from).toBe('2026-11-01T00:00:00.123456789Z')
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Read recorded revisions' }))
  const history = await screen.findByRole('table', { name: 'Recorded agreement revisions' })
  expect(within(history).getByText(version)).toBeInTheDocument()
  expect(within(history).getByText(unitPrice)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Older revisions' }))
  await waitFor(() =>
    expect(
      seen.some((x) => x.path.endsWith('/revisions') && x.search.includes(`after=${version}`)),
    ).toBe(true),
  )
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Delete agreement' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: 'Delete agreement' }))
  expect(seen.some((x) => x.method === 'DELETE')).toBe(false)
  fireEvent.click(screen.getByRole('button', { name: 'Confirm deletion' }))
  await screen.findByText('No agreements are recorded on this page.')
  expect(seen.find((x) => x.method === 'DELETE')?.search).toBe(`?version=${version}`)
})

test('a late financial response cannot repopulate a different tenant and withdrawn grants clear exact terms', async () => {
  let tenant = 'red'
  let late: ((value: Response) => void) | undefined
  fixture(async () => {
    if (tenant === 'red')
      return new Promise<Response>((resolve) => {
        late = resolve
      })
    return jsonResponse(page('blue'))
  })
  mount({
    switched: () => {
      tenant = 'blue'
    },
  })
  await waitFor(() => expect(late).toBeDefined())
  fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
  await screen.findByRole('button', { name: 'Open blue WAN' })
  await act(async () => {
    late!(jsonResponse(page('red')))
  })
  expect(screen.queryByText('red WAN')).not.toBeInTheDocument()
  expect(screen.getByText('blue WAN')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Withdraw financial permission' }))
  expect(screen.queryByText(unitPrice)).not.toBeInTheDocument()
  expect(screen.queryByText('blue WAN')).not.toBeInTheDocument()
  expect(screen.queryByLabelText('Recorded unit price')).not.toBeInTheDocument()
  expect(
    screen.getByText('Financial read permission is required to view capacity agreements.'),
  ).toBeInTheDocument()
})

test('financial read-only access does not require telemetry grants or expose mutation controls', async () => {
  fixture(async () => jsonResponse(page('red')))
  mount({ write: false })
  await screen.findByRole('button', { name: 'Open red WAN' })
  expect(screen.queryByRole('button', { name: 'Record agreement' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'New agreement' })).not.toBeInTheDocument()
})

test('a current server denial clears previously read financial terms and the editor', async () => {
  fixture(async (url) => {
    if (url.pathname.endsWith('/revisions'))
      return jsonResponse({ error: { message: 'Current financial grant was withdrawn.' } }, 403)
    return jsonResponse(url.pathname === base ? page('red') : item('red'))
  })
  mount()
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
  await screen.findByRole('button', { name: 'Save revised terms' })
  expect(screen.getByLabelText('Recorded unit price')).toHaveValue(unitPrice)
  fireEvent.click(screen.getByRole('button', { name: 'Read recorded revisions' }))
  await screen.findByText('Current financial grant was withdrawn.')
  expect(screen.queryByText('red WAN')).not.toBeInTheDocument()
  expect(screen.queryByText(unitPrice)).not.toBeInTheDocument()
  expect(screen.getByLabelText('Recorded unit price')).toHaveValue('')
})

test.each(['light', 'dark'])(
  'financial terms and complete editor are accessible in %s theme',
  async (theme) => {
    const previous = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: true,
      value: { getItem: () => theme, setItem: vi.fn() },
    })
    try {
      fixture(async () => jsonResponse(page('red')))
      const view = mount()
      await screen.findByRole('button', { name: 'Open red WAN' })
      expect(document.documentElement.dataset.theme).toBe(theme)
      expect(await axe(view.container)).toHaveNoViolations()
    } finally {
      if (previous) Object.defineProperty(window, 'localStorage', previous)
      else Reflect.deleteProperty(window, 'localStorage')
    }
  },
)

function measuredBill(tenant: string): CapacityAgreementBill {
  return {
    agreement: item(tenant),
    as_of: '2026-11-01T01:00:00Z',
    source_valid_until: '2099-11-01T01:00:00Z',
    maximum_poll_gap: '5m',
    membership_basis: 'current_member_set_applied_to_complete_period',
    period: {
      from: '2026-10-01T00:00:00Z',
      to: '2026-11-01T00:00:00Z',
      timezone: 'UTC',
      billing_day: 1,
      boundary_policy: 'calendar',
    },
    percentile: {
      complete: true,
      direction: 'in',
      expected_samples: 8928,
      observed_samples: 8928,
      missing_samples: 0,
      bps_numerator: '15200',
      bps_denominator: '1',
      from: '2026-10-01T00:00:00Z',
      to: '2026-11-01T00:00:00Z',
      model: 'poll_start_mean_overlap',
      rank: 8482,
    },
    bill: {
      complete: true,
      currency: 'USD',
      from: '2026-10-01T00:00:00Z',
      to: '2026-11-01T00:00:00Z',
      model: 'recorded_terms',
      commit_numerator: '1000',
      commit_denominator: '1',
      overage_numerator: '14200',
      overage_denominator: '1',
      billable_numerator: '19',
      billable_denominator: '1',
      charge_numerator: '4750000000000000019',
      charge_denominator: '1250000000000000000',
      invoice_compared: true,
      invoice_difference_numerator: '0',
      invoice_difference_denominator: '1',
    },
    members: Array.from({ length: 201 }, (_, i) => ({
      context_id: item(tenant).definition.target.context_id!,
      interface_id: `${tenant}-interface-${i}`,
      device_id: `${tenant}-device`,
      if_index: i + 1,
      observed_not_before: '2026-09-30T00:00:00Z',
      physical_max_bps: '18446744073709551615',
    })),
  }
}
async function fillBill() {
  fireEvent.change(screen.getByLabelText('Instant within billing period'), {
    target: { value: '2026-10-15T12:00:00.123456789+05:45' },
  })
  fireEvent.change(screen.getByLabelText('Member 1 physical upper bound (bps)'), {
    target: { value: '18446744073709551615' },
  })
}

test.each(['light', 'dark'])(
  'measured bill keeps exact input, complete output and accessible %s controls',
  async (theme) => {
    const previous = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: true,
      value: { getItem: () => theme, setItem: vi.fn() },
    })
    let sent: CapacityBillInput | undefined
    const response = measuredBill('red')
    fixture(async (url, init) => {
      if (url.pathname.endsWith('/check')) {
        sent = JSON.parse(String(init?.body)) as CapacityBillInput
        return jsonResponse(response)
      }
      return jsonResponse(url.pathname === base ? page('red') : item('red'))
    })
    try {
      const view = mount({ write: false })
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled(),
      )
      fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
      await screen.findByRole('button', { name: 'Check measured bill' })
      await fillBill()
      fireEvent.change(screen.getByLabelText('Invoiced amount to compare'), {
        target: { value: '-0.000000000000000000000000000001' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Check measured bill' }))
      const result = await screen.findByRole('region', { name: 'Measured billing result' })
      expect(sent).toEqual({
        version,
        at: '2026-10-15T12:00:00.123456789+05:45',
        maximum_poll_gap: '5m',
        invoiced: '-0.000000000000000000000000000001',
        physical_bounds: [
          {
            context_id: item('red').definition.target.context_id,
            interface_id: item('red').definition.target.interface_id,
            max_bps: '18446744073709551615',
          },
        ],
      })
      expect(
        within(result).getByText('4750000000000000019 / 1250000000000000000'),
      ).toBeInTheDocument()
      const table = within(result).getByRole('table', { name: 'Complete bill member assumptions' })
      expect(within(table).getByText('red-interface-99')).toBeInTheDocument()
      fireEvent.click(within(result).getByRole('button', { name: 'Next member assumptions' }))
      fireEvent.click(within(result).getByRole('button', { name: 'Next member assumptions' }))
      expect(within(table).getByText('red-interface-200')).toBeInTheDocument()
      expect(within(result).getByRole('button', { name: 'Next member assumptions' })).toBeDisabled()
      expect(document.documentElement.dataset.theme).toBe(theme)
      expect(await axe(view.container)).toHaveNoViolations()
      response.percentile = {
        ...response.percentile,
        complete: false,
        observed_samples: 8926,
        missing_samples: 2,
        bps_numerator: undefined,
        bps_denominator: undefined,
        rank: undefined,
      }
      response.bill = {
        ...response.bill,
        complete: false,
        charge_numerator: undefined,
        charge_denominator: undefined,
        reason: 'required_coverage_incomplete',
      }
      fireEvent.click(screen.getByRole('button', { name: 'Check measured bill' }))
      await screen.findByText('No — no measured percentile or charge')
      expect(
        screen.queryByText('4750000000000000019 / 1250000000000000000'),
      ).not.toBeInTheDocument()
      expect(screen.getByText('8928 / 8926 / 2')).toBeInTheDocument()
    } finally {
      if (previous) Object.defineProperty(window, 'localStorage', previous)
      else Reflect.deleteProperty(window, 'localStorage')
    }
  },
)

test('late measured bills cannot cross tenant changes and withdrawn authority clears amounts', async () => {
  let tenant = 'red'
  let late: ((response: Response) => void) | undefined
  fixture(async (url) => {
    if (url.pathname.endsWith('/check')) {
      if (tenant === 'red')
        return new Promise<Response>((resolve) => {
          late = resolve
        })
      return jsonResponse(measuredBill('blue'))
    }
    return jsonResponse(url.pathname === base ? page(tenant) : item(tenant))
  })
  mount({
    write: false,
    switched: () => {
      tenant = 'blue'
    },
  })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
  await screen.findByRole('button', { name: 'Check measured bill' })
  await fillBill()
  fireEvent.click(screen.getByRole('button', { name: 'Check measured bill' }))
  await waitFor(() => expect(late).toBeDefined())
  fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
  await screen.findByRole('button', { name: 'Open blue WAN' })
  await act(async () => {
    late!(jsonResponse(measuredBill('red')))
  })
  expect(screen.queryByRole('region', { name: 'Measured billing result' })).not.toBeInTheDocument()
  expect(screen.queryByText('red WAN')).not.toBeInTheDocument()
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open blue WAN' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Open blue WAN' }))
  await screen.findByRole('button', { name: 'Check measured bill' })
  await fillBill()
  fireEvent.click(screen.getByRole('button', { name: 'Check measured bill' }))
  await screen.findByRole('region', { name: 'Measured billing result' })
  fireEvent.click(screen.getByRole('button', { name: 'Withdraw financial permission' }))
  expect(screen.queryByRole('region', { name: 'Measured billing result' })).not.toBeInTheDocument()
  expect(screen.queryByText('blue WAN')).not.toBeInTheDocument()
  expect(screen.queryByLabelText('Member 1 physical upper bound (bps)')).not.toBeInTheDocument()
})

function forecastResult(tenant: string): CapacityForecastMeasurement {
  const central = { reached: true, from: '2026-10-18T01:00:00Z', to: '2026-10-18T01:05:00Z' }
  return {
    target: {
      kind: 'interface',
      context_id: item(tenant).definition.target.context_id,
      interface_id: item(tenant).definition.target.interface_id,
    },
    members: measuredBill(tenant).members,
    maximum_poll_gap: '5m',
    membership_basis: 'current_member_set_applied_to_complete_period',
    as_of: '2026-10-15T00:00:01Z',
    source_valid_until: '2099-11-01T00:00:00Z',
    forecasts: [
      {
        target: `${tenant}-current-interface`,
        direction: 'in',
        counter_model: 'poll_start_mean_overlap',
        model: 'weighted_linear_weekly_5m_v1',
        interval_method: 'in_sample_residual_envelope',
        from: '2026-10-01T00:00:00Z',
        to: '2026-10-15T00:00:00Z',
        until: '2026-10-20T00:00:00Z',
        expected_samples: 4032,
        observed_samples: 4032,
        coverage_complete: true,
        trained: true,
        capacity_numerator: '9007199254740993000000000000000001',
        capacity_denominator: '1000000000000000000',
        trend_bps_per_day_numerator: '230400',
        trend_bps_per_day_denominator: '1',
        observed_exceedances: 0,
        last_sample_known: true,
        last_sample_exceeded: false,
        central,
        earliest: central,
        latest: central,
      },
    ],
  }
}
function fillForecast() {
  for (const [label, value] of [
    ['Forecast routing context ID', item('red').definition.target.context_id!],
    ['Forecast canonical interface ID', item('red').definition.target.interface_id!],
    ['Forecast training from', '2026-10-01T00:00:00.123456789Z'],
    ['Forecast training to', '2026-10-15T00:00:00.123456789Z'],
    ['Forecast horizon', '2026-10-20T00:00:00.123456789Z'],
    ['Forecast threshold (bps)', '9007199254740993.000000000000000001'],
    ['Forecast member 1 routing context ID', item('red').definition.target.context_id!],
    ['Forecast member 1 interface ID', item('red').definition.target.interface_id!],
    ['Forecast member 1 physical bound (bps)', '18446744073709551615'],
  ])
    fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

test.each(['light', 'dark'])(
  'independent forecast keeps exact thresholds and complete accessible %s result',
  async (theme) => {
    const previous = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      enumerable: true,
      value: { getItem: () => theme, setItem: vi.fn() },
    })
    let sent: CapacityForecastInput | undefined
    const result = forecastResult('red')
    fixture(async (url, init) => {
      if (url.pathname === '/v1/flows/capacity/forecast') {
        sent = JSON.parse(String(init?.body)) as CapacityForecastInput
        return jsonResponse(result)
      }
      throw new Error('telemetry-only forecast must not read financial endpoints')
    })
    try {
      const view = mount({ forecastOnly: true })
      fillForecast()
      expect(screen.queryByRole('button', { name: 'Record agreement' })).not.toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Forecast runout' }))
      const region = await screen.findByRole('region', { name: 'Measured forecast result' })
      expect(sent?.capacity_bps).toBe('9007199254740993.000000000000000001')
      expect(sent?.from).toBe('2026-10-01T00:00:00.123456789Z')
      expect(sent?.physical_bounds[0].max_bps).toBe('18446744073709551615')
      expect(
        within(region).getByText('9007199254740993000000000000000001 / 1000000000000000000'),
      ).toBeInTheDocument()
      expect(within(region).getByText('4032 / 4032')).toBeInTheDocument()
      expect(within(region).getByText('in_sample_residual_envelope')).toBeInTheDocument()
      expect(await axe(view.container)).toHaveNoViolations()
      result.forecasts[0] = {
        ...result.forecasts[0],
        trained: false,
        coverage_complete: false,
        observed_samples: 4030,
        reason: 'training_coverage_incomplete',
        central: { reached: false },
        earliest: { reached: false },
        latest: { reached: false },
        trend_bps_per_day_numerator: undefined,
        trend_bps_per_day_denominator: undefined,
      }
      fireEvent.click(screen.getByRole('button', { name: 'Forecast runout' }))
      await screen.findByText('training_coverage_incomplete')
      expect(
        screen.queryByText('2026-10-18T01:00:00Z to 2026-10-18T01:05:00Z (end exclusive)'),
      ).not.toBeInTheDocument()
      expect(screen.getByText('4032 / 4030')).toBeInTheDocument()
    } finally {
      if (previous) Object.defineProperty(window, 'localStorage', previous)
      else Reflect.deleteProperty(window, 'localStorage')
    }
  },
)

test('late forecasts cannot cross tenant identities or survive current grant withdrawal', async () => {
  let tenant = 'red'
  let late: ((response: Response) => void) | undefined
  fixture(async (url) => {
    if (url.pathname !== '/v1/flows/capacity/forecast')
      throw new Error('unexpected financial fetch')
    if (tenant === 'red')
      return new Promise<Response>((resolve) => {
        late = resolve
      })
    return jsonResponse(forecastResult('blue'))
  })
  mount({
    forecastOnly: true,
    switched: () => {
      tenant = 'blue'
    },
  })
  fillForecast()
  fireEvent.click(screen.getByRole('button', { name: 'Forecast runout' }))
  await waitFor(() => expect(late).toBeDefined())
  fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
  await act(async () => {
    late!(jsonResponse(forecastResult('red')))
  })
  expect(screen.queryByRole('region', { name: 'Measured forecast result' })).not.toBeInTheDocument()
  fillForecast()
  fireEvent.click(screen.getByRole('button', { name: 'Forecast runout' }))
  await screen.findByRole('region', { name: 'Measured forecast result' })
  fireEvent.click(screen.getByRole('button', { name: 'Withdraw financial permission' }))
  expect(screen.queryByRole('region', { name: 'Measured forecast result' })).not.toBeInTheDocument()
  expect(screen.queryByLabelText('Forecast threshold (bps)')).not.toBeInTheDocument()
})

test('carrier SLA revisions preserve exact entered terms and discard a late tenant detail', async () => {
  const current = item('red')
  current.definition.sla = {
    carrier: 'private red carrier',
    circuit_id: 'red circuit',
    site: 'red site',
    currency: 'USD',
    monthly_charge: '100.000000000000000001',
    aggregation: 'maximum',
    credit_cap_ratio: '1.25',
    rules: [
      {
        id: 'contract clause',
        metric: 'availability',
        basis: 'original_execution_ratio',
        good_when: 'at_least',
        threshold: '0.999',
        credit_bands: [{ from_inclusive: '0', to_exclusive: '0.999', credit_ratio: '0.1' }],
      },
    ],
  }
  let saved: CapacityAgreementInput | undefined
  let details = 0
  let late: ((value: Response) => void) | undefined
  fixture(async (url, init) => {
    if (init?.method === 'PUT') {
      saved = JSON.parse(String(init.body)) as CapacityAgreementInput
      return jsonResponse(current)
    }
    if (url.pathname === base) return jsonResponse(page('red'))
    details++
    if (details > 1)
      return new Promise<Response>((resolve) => {
        late = resolve
      })
    return jsonResponse(current)
  })
  const view = mount()
  try {
    fireEvent.click(await screen.findByRole('button', { name: 'Open red WAN' }))
    await screen.findByLabelText('SLA carrier')
    expect(screen.getByLabelText('Monthly recurring charge')).toHaveValue('100.000000000000000001')
    fireEvent.click(screen.getByRole('button', { name: 'Link circuit probe' }))
    fireEvent.change(screen.getByLabelText('Circuit probe 1 test ID'), {
      target: { value: '44444444-4444-4444-8444-444444444444' },
    })
    fireEvent.change(screen.getByLabelText('Circuit probe 1 agent ID'), {
      target: { value: 'operator-probe-agent' },
    })
    fireEvent.change(screen.getByLabelText('Clause 1 threshold'), {
      target: { value: '0.999000000000000001' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save revised terms' }))
    await waitFor(() =>
      expect(saved?.definition.sla?.rules[0].threshold).toBe('0.999000000000000001'),
    )
    expect(saved?.definition.sla?.monthly_charge).toBe('100.000000000000000001')
    expect(saved?.definition.sla?.credit_cap_ratio).toBe('1.25')
    expect(saved?.definition.sla?.sources).toEqual([
      { agent_id: 'operator-probe-agent', test_id: '44444444-4444-4444-8444-444444444444' },
    ])
    expect(saved?.definition.sla?.rules[0].credit_bands).toEqual(
      current.definition.sla.rules[0].credit_bands,
    )
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
    await waitFor(() => expect(late).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
    await act(async () => {
      late!(jsonResponse(current))
    })
    expect(screen.queryByDisplayValue('private red carrier')).not.toBeInTheDocument()
    expect(
      screen.queryByText('Carrier private red carrier; circuit red circuit; site red site.'),
    ).not.toBeInTheDocument()
  } finally {
    view.unmount()
  }
})

test('monthly SLA keeps exact observed populations and discards late tenant results', async () => {
  let tenant = 'red'
  let late: ((response: Response) => void) | undefined
  const selected = (id: string): CapacityAgreement => {
    const value = item(id)
    value.definition.sla = {
      carrier: `${id} carrier`,
      circuit_id: `${id} circuit`,
      site: '',
      currency: 'USD',
      monthly_charge: '100.125',
      credit_cap_ratio: '1.25',
      aggregation: 'maximum',
      sources: [{ agent_id: `${id}-agent`, test_id: '44444444-4444-4444-8444-444444444444' }],
      rules: [
        {
          id: 'loss',
          metric: 'loss',
          basis: 'original_packet_ratio',
          good_when: 'at_most',
          threshold: '0.01',
          credit_bands: [{ from_inclusive: '0.01', credit_ratio: '0.1' }],
        },
      ],
    }
    return value
  }
  const result = (id: string): CarrierSLAStatement => ({
    agreement: selected(id),
    period: {
      from: '2026-10-01T00:00:00Z',
      to: '2026-11-01T00:00:00Z',
      timezone: 'UTC',
      billing_day: 1,
      boundary_policy: 'calendar',
    },
    credit: {
      from: '2026-10-01T00:00:00Z',
      to: '2026-11-01T00:00:00Z',
      currency: 'USD',
      complete: false,
      known_credit_lower_bound: '0',
      assessments: [
        {
          rule_id: 'loss',
          state: 'unknown',
          from: '2026-10-01T00:00:00Z',
          to: '2026-11-01T00:00:00Z',
          citations: [`${id}-population`],
        },
      ],
    },
    sources: Array.from({ length: 205 }, (_, index) => ({
      id: `${id}-population-${index}`,
      context_id: 'context',
      device_id: 'device',
      agent_id: `${id}-original-agent`,
      test_id: 'test',
      originals: index === 0 ? '500001' : String(index),
      successful: '500000',
      failed: '1',
      unknown: '0',
      transmitted: '1500003',
      lost: '3',
      rtt_samples: '1500000',
      digest:
        index === 0 ? `${id}-complete-original-digest` : `${id}-complete-original-digest-${index}`,
      observed_not_before: '2026-10-01T00:00:00Z',
    })),
    as_of: '2026-10-15T00:00:00Z',
    source_valid_until: '2099-11-01T00:00:00Z',
    coverage_basis: 'observed_original_populations_only_not_schedule_or_continuous_availability',
    repair_basis:
      'maximum_observed_failed_completion_to_next_successful_completion_not_physical_repair_time',
    human_review_required: true,
  })
  let sentClaim: unknown
  let sent: unknown
  fixture(async (url, init) => {
    if (url.pathname.endsWith('/sla-claims')) {
      sentClaim = JSON.parse(String(init?.body))
      const circuit = result(tenant)
      return jsonResponse({
        contract_version: 'probectl-carrier-sla-draft/v1',
        groups: [
          {
            carrier: `${tenant} carrier`,
            currency: 'USD',
            period: circuit.period,
            complete: false,
            known_credit_lower_bound: '0',
            circuits: [circuit],
          },
        ],
        generated_at: circuit.as_of,
        source_valid_until: circuit.source_valid_until,
        human_review_required: true,
        submission_state: 'not_submitted',
      })
    }
    if (url.pathname.endsWith('/sla')) {
      sent = JSON.parse(String(init?.body))
      if (tenant === 'red')
        return new Promise<Response>((resolve) => {
          late = resolve
        })
      return jsonResponse(result('blue'))
    }
    return jsonResponse(
      url.pathname === base
        ? { items: [selected(tenant)], has_more: false, as_of: '2026-11-01T01:00:00Z' }
        : selected(tenant),
    )
  })
  mount({
    write: false,
    switched: () => {
      tenant = 'blue'
    },
  })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Open red WAN' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Open red WAN' }))
  fireEvent.change(await screen.findByLabelText(/SLA billing-period instant/), {
    target: { value: '2026-10-15T00:00:00Z' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Calculate monthly SLA' }))
  await waitFor(() => expect(late).toBeDefined())
  expect(sent).toEqual({ version, at: '2026-10-15T00:00:00Z' })
  fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
  await screen.findByRole('button', { name: 'Open blue WAN' })
  await act(async () => {
    late!(jsonResponse(result('red')))
  })
  expect(screen.queryByRole('region', { name: 'Monthly SLA result' })).not.toBeInTheDocument()
  expect(screen.queryByText('red-complete-original-digest')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Open blue WAN' }))
  fireEvent.change(await screen.findByLabelText(/SLA billing-period instant/), {
    target: { value: '2026-10-15T00:00:00Z' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Calculate monthly SLA' }))
  const displayed = await screen.findByRole('region', { name: 'Monthly SLA result' })
  expect(within(displayed).getByText('500001')).toBeInTheDocument()
  expect(within(displayed).getByText('blue-complete-original-digest')).toBeInTheDocument()
  fireEvent.click(
    within(displayed).getByRole('button', { name: 'Complete SLA original populations: last page' }),
  )
  expect(within(displayed).getByText('blue-complete-original-digest-204')).toBeInTheDocument()
  expect(
    within(displayed).getByText(/unknown coverage or an unfinished period/),
  ).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Add selected agreement to claim' }))
  fireEvent.change(screen.getByLabelText(/Claim selection 1 billing-period instant/), {
    target: { value: '2026-10-15T00:00:00Z' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Prepare grouped claim draft' }))
  await screen.findByRole('region', { name: 'Grouped carrier claim draft' })
  expect(sentClaim).toEqual({
    selections: [{ agreement_id: 'blue-agreement', version, at: '2026-10-15T00:00:00Z' }],
  })
  fireEvent.click(screen.getByRole('button', { name: 'Withdraw financial permission' }))
  expect(
    screen.queryByRole('region', { name: 'Grouped carrier claim draft' }),
  ).not.toBeInTheDocument()
  expect(screen.queryByRole('region', { name: 'Monthly SLA result' })).not.toBeInTheDocument()
  expect(screen.queryByLabelText(/SLA billing-period instant/)).not.toBeInTheDocument()
})

test('signed carrier report saves exact revisions and discards a late tenant response', async () => {
  let tenant = 'red'
  let late: ((response: Response) => void) | undefined
  const sent: Array<{
    definition: {
      carrier_claim: { selections: Array<{ agreement_id: string; version: string; at?: string }> }
    }
  }> = []
  const selected = (id: string): CapacityAgreement => ({
    ...item(id),
    definition: {
      ...item(id).definition,
      sla: {
        carrier: 'Carrier',
        circuit_id: 'Circuit',
        site: 'Site',
        currency: 'USD',
        monthly_charge: '100.125',
        aggregation: 'maximum',
        credit_cap_ratio: '1',
        sources: [{ agent_id: `${id}-agent`, test_id: `${id}-test` }],
        rules: [],
      },
    },
  })
  const fallback = defaultFetch()
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/dashboards' && init?.method === 'POST') {
      sent.push(JSON.parse(String(init.body)))
      if (tenant === 'red')
        return new Promise<Response>((resolve) => {
          late = resolve
        })
      return Promise.resolve(jsonResponse({ id: 'blue-signed-view' }))
    }
    if (path.startsWith(base))
      return Promise.resolve(
        jsonResponse(
          path === base ? { ...page(tenant), items: [selected(tenant)] } : selected(tenant),
        ),
      )
    return fallback(input, init)
  })
  mount({
    reportWrite: true,
    switched: () => {
      tenant = 'blue'
    },
  })
  fireEvent.click(await screen.findByRole('button', { name: 'Open red WAN' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Add selected agreement to claim' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: 'Add selected agreement to claim' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Save signed claim report' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: 'Save signed claim report' }))
  await waitFor(() => expect(late).toBeDefined())
  expect(sent[0].definition.carrier_claim.selections).toEqual([
    { agreement_id: 'red-agreement', version },
  ])
  fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
  await screen.findByRole('button', { name: 'Open blue WAN' })
  await act(async () => {
    late!(jsonResponse({ id: 'red-signed-view' }))
  })
  expect(
    screen.queryByRole('link', { name: 'Generate or schedule the signed claim' }),
  ).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Open blue WAN' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Add selected agreement to claim' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: 'Add selected agreement to claim' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Save signed claim report' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: 'Save signed claim report' }))
  expect(
    await screen.findByRole('link', { name: 'Generate or schedule the signed claim' }),
  ).toHaveAttribute('href', '/ui/dashboards?view=blue-signed-view#saved-dashboard')
  expect(sent[1].definition.carrier_claim.selections).toEqual([
    { agreement_id: 'blue-agreement', version },
  ])
})

const comparisonStart = '2026-11-07T00:00:00Z'
const comparisonEnd = '2026-11-08T00:00:00Z'
const comparisonContext = '22222222-2222-4222-8222-222222222222'
const primaryInterface = '33333333-3333-4333-8333-333333333333'
const candidateInterface = '44444444-4444-4444-8444-444444444444'

function transferPage(tenant: string): CapacityAgreementPage {
  const candidate = item(`${tenant}-candidate`)
  candidate.definition.target.interface_id = candidateInterface
  return { ...page(tenant), items: [item(tenant), candidate] }
}

function transferResult(tenant: string, prefix: string): RoutingTransferResponse {
  const measured = measuredBill(tenant)
  const before = measured.bill
  const after = { ...before, charge_numerator: '19', charge_denominator: '1' }
  const p95 = measured.percentile
  return {
    context_id: comparisonContext,
    destination_prefix: prefix,
    estimate_basis: 'observed_window_at_recorded_unit_rates',
    performance_status: 'no_paired_upstream_measurement',
    source_valid_until: '2099-11-08T00:00:00Z',
    estimate: {
      status: 'estimated',
      from: comparisonStart,
      to: comparisonEnd,
      source: {
        agreement_id: `${tenant}-agreement`,
        agreement_version: version,
        before,
        after,
        before_p95: p95,
        after_p95: { ...p95, complete: false },
      },
      candidate: {
        agreement_id: `${tenant}-candidate-agreement`,
        agreement_version: version,
        before: after,
        after: before,
        before_p95: { ...p95, bps_numerator: '30001', bps_denominator: '2' },
        after_p95: p95,
      },
      candidate_egress_speed_bps: '1000000000',
      candidate_egress_limit_bps: '980000000',
      moved_peak_bps: '200000000',
      candidate_peak_bps: '401000000',
      net_charge_change: '1.25',
      currency: 'USD',
    },
    policy: {
      router_id: `${tenant}-router`,
      exact_prefix: prefix,
      local_preference: 120,
      candidate_asn: 64500,
      candidate_peer: '192.0.2.2',
      current_peer: '192.0.2.1',
      operation: 'set_inbound_local_preference_for_exact_prefix',
    },
  }
}

async function submitTransfer(tenant: string, prefix: string) {
  const form = within(screen.getByRole('form', { name: 'Routing transfer estimate' }))
  const current = form.getByLabelText('Current handoff agreement')
  const candidate = form.getByLabelText('Candidate handoff agreement')
  await within(current).findByRole('option', { name: `${tenant} WAN · revision ${version}` })
  await within(candidate).findByRole('option', {
    name: `${tenant}-candidate WAN · revision ${version}`,
  })
  fireEvent.change(current, {
    target: { value: `${tenant}-agreement:${version}` },
  })
  fireEvent.change(candidate, {
    target: { value: `${tenant}-candidate-agreement:${version}` },
  })
  const enter = (label: string, value: string) =>
    fireEvent.change(form.getByLabelText(label), { target: { value } })
  enter('Current handoff member 1 physical bound (bps)', '900000000')
  enter('Candidate handoff member 1 physical bound (bps)', '980000000')
  enter('Routing context ID', comparisonContext)
  enter('Exact destination prefix', prefix)
  enter('Proposed local preference', '120')
  enter('Comparison window', 'observed')
  enter('Observation start', comparisonStart)
  enter('Observation end', comparisonEnd)
  fireEvent.click(form.getByRole('button', { name: 'Estimate transfer' }))
}

test('estimates exact-prefix transfer costs with the selected immutable revisions', async () => {
  const prefix = '203.0.113.0/24'
  const requests: RoutingTransferInput[] = []
  fixture(async (url, init) => {
    if (url.pathname !== transferPath) return jsonResponse(transferPage('red'))
    expect(init?.method).toBe('POST')
    requests.push(JSON.parse(String(init?.body)) as RoutingTransferInput)
    return jsonResponse(transferResult('red', prefix))
  })
  mount({ estimate: true, write: false })
  await submitTransfer('red', prefix)
  const result = within(await screen.findByRole('region', { name: 'Routing transfer result' }))
  expect(result.getByRole('status')).toHaveTextContent(`Transfer calculated for ${prefix}`)
  expect(result.getByText(/observation window priced at recorded rates/i)).toBeInTheDocument()
  expect(result.getByText(/comparative upstream performance is unavailable/i)).toBeInTheDocument()
  const table = within(result.getByRole('table', { name: 'Estimated handoff charges' }))
  const current = within(table.getByRole('row', { name: /^Current / }))
  expect(current.getByText('4750000000000000019/1250000000000000000 USD')).toBeInTheDocument()
  expect(current.getByText('19 USD')).toBeInTheDocument()
  expect(current.getByText('Unavailable')).toBeInTheDocument()
  expect(table.getByText('30001/2 bps')).toBeInTheDocument()
  expect(result.queryByRole('button')).not.toBeInTheDocument()
  expect(requests).toEqual([
    {
      context_id: comparisonContext,
      destination_prefix: prefix,
      local_preference: 120,
      maximum_poll_gap: '5m',
      observed_from: comparisonStart,
      observed_to: comparisonEnd,
      source: {
        agreement_id: 'red-agreement',
        agreement_version: version,
        egress_interface_id: primaryInterface,
        physical_bounds: [
          { context_id: comparisonContext, interface_id: primaryInterface, max_bps: '900000000' },
        ],
      },
      candidate: {
        agreement_id: 'red-candidate-agreement',
        agreement_version: version,
        egress_interface_id: candidateInterface,
        physical_bounds: [
          { context_id: comparisonContext, interface_id: candidateInterface, max_bps: '980000000' },
        ],
      },
    },
  ])
})

test('a delayed routing transfer estimate cannot repopulate a second tenant workspace', async () => {
  const firstPrefix = '203.0.113.0/24'
  const secondPrefix = '198.51.100.0/24'
  let tenant = 'red'
  let firstSignal: AbortSignal | null | undefined
  let finishFirst: ((response: Response) => void) | undefined
  const submittedAgreements: string[] = []
  fixture(async (url, init) => {
    if (url.pathname !== transferPath) return jsonResponse(transferPage(tenant))
    const request = JSON.parse(String(init?.body)) as RoutingTransferInput
    submittedAgreements.push(request.source.agreement_id)
    if (tenant === 'blue') return jsonResponse(transferResult(tenant, secondPrefix))
    firstSignal = init?.signal
    return new Promise<Response>((resolve) => {
      finishFirst = resolve
    })
  })
  mount({
    estimate: true,
    write: false,
    switched: () => {
      tenant = 'blue'
    },
  })
  await submitTransfer('red', firstPrefix)
  await waitFor(() => expect(firstSignal?.aborted).toBe(false))
  fireEvent.click(screen.getByRole('button', { name: 'Switch financial tenant' }))
  expect(firstSignal?.aborted).toBe(true)
  await act(async () => {
    finishFirst?.(jsonResponse(transferResult('red', firstPrefix)))
  })
  expect(screen.queryByRole('region', { name: 'Routing transfer result' })).not.toBeInTheDocument()
  expect(screen.queryAllByRole('option', { name: /^red WAN/ })).toHaveLength(0)
  await submitTransfer('blue', secondPrefix)
  const result = within(await screen.findByRole('region', { name: 'Routing transfer result' }))
  expect(result.getByRole('status')).toHaveTextContent(secondPrefix)
  expect(result.queryByText(/red-router/)).not.toBeInTheDocument()
  expect(submittedAgreements).toEqual(['red-agreement', 'blue-agreement'])
})
