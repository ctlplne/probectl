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
  CapacityAgreementInput,
  CapacityAgreementBill,
  CapacityBillInput,
  CapacityForecastInput,
  CapacityForecastMeasurement,
  CapacityAgreementPage,
} from '../api/sdk.gen'
import { CapacityAgreementsPage } from '../routes/CapacityAgreementsPage'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const base = '/v1/flows/capacity/agreements'
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
}: {
  switched?: () => void
  write?: boolean
  forecastOnly?: boolean
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
            : ['flow.agreements.read', ...(write ? ['flow.agreements.write'] : [])]
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
    if (pathOf(input).startsWith('/v1/flows/capacity/'))
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
