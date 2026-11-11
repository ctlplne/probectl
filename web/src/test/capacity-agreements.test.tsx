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

function Harness({ switched, write = true }: { switched?: () => void; write?: boolean }) {
  const [tenant, setTenant] = useState('red')
  const [allowed, setAllowed] = useState(true)
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        tenants: [],
        user: { id: `${tenant}-reader`, name: 'Financial reader', email: 'reader@local.test' },
        permissions: allowed
          ? ['flow.agreements.read', ...(write ? ['flow.agreements.write'] : [])]
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
    if (pathOf(input).startsWith(base))
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
