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
import { IncidentCarrierCard } from '../routes/IncidentCarrierCard'
import type { Incident } from '../api/incidents'
import { defaultFetch, pathOf } from './fetchStub'

const id = '11111111-1111-4111-8111-111111111111'
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
const permissions = [
  'incident.read',
  'ai.query',
  'entities.read',
  'metrics.read',
  'events.read',
  'test.read',
  'change.read',
]
function Harness() {
  const [tenant, setTenant] = useState('red')
  const [allowed, setAllowed] = useState(true)
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        tenants: [],
        user: { id: 'reader', email: 'reader@example.test', name: 'Reader' },
        permissions: allowed ? permissions : ['incident.read'],
        switchTenant: () => {},
        signOut: () => {},
      }}
    >
      <button onClick={() => setTenant('blue')}>Switch carrier tenant</button>
      <button onClick={() => setAllowed(false)}>Withdraw carrier access</button>
      <IncidentCarrierCard incident={incident} />
    </AuthContext.Provider>
  )
}

test('carrier download keeps the exact window and bytes and discards late tenant results', async () => {
  const fallback = defaultFetch()
  const signed = new Uint8Array([123, 32, 34, 110, 34, 58, 57, 125])
  let selection: unknown
  let finish: ((response: Response) => void) | undefined
  let calls = 0
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === `/v1/incidents/${id}/exports`) {
      selection = JSON.parse(String(init?.body))
      calls++
      if (calls === 1) return Promise.resolve(new Response(signed))
      return new Promise<Response>((resolve) => {
        finish = resolve
      })
    }
    return fallback(input, init)
  })
  const create = vi.fn(() => 'blob:carrier'),
    revoke = vi.fn()
  const properties = ['createObjectURL', 'revokeObjectURL'].map((key) =>
    Object.getOwnPropertyDescriptor(URL, key),
  )
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: create })
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revoke })
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  const view = render(
    <Providers>
      <Harness />
    </Providers>,
  )
  try {
    const from = '2026-11-01T00:00:00.000000001Z',
      to = '2026-11-01T00:00:00.000000002Z'
    fireEvent.change(screen.getByLabelText('Carrier from (ISO 8601 with offset)'), {
      target: { value: from },
    })
    fireEvent.change(screen.getByLabelText('Carrier to (exclusive, ISO 8601 with offset)'), {
      target: { value: to },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Download carrier ticket pack' }))
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1))
    expect(selection).toEqual({ carrier: { from, to } })
    expect(create).toHaveBeenCalledTimes(1)
    expect(revoke).toHaveBeenCalledWith('blob:carrier')
    expect(await screen.findByText(/Signed carrier pack downloaded/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Download carrier ticket pack' }))
    await waitFor(() => expect(finish).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: 'Switch carrier tenant' }))
    await act(async () => {
      finish!(new Response(signed))
    })
    expect(click).toHaveBeenCalledTimes(1)
    expect(create).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw carrier access' }))
    expect(
      screen.queryByRole('button', { name: 'Download carrier ticket pack' }),
    ).not.toBeInTheDocument()
  } finally {
    view.unmount()
    click.mockRestore()
    for (const [index, key] of ['createObjectURL', 'revokeObjectURL'].entries()) {
      if (properties[index]) Object.defineProperty(URL, key, properties[index])
      else Reflect.deleteProperty(URL, key)
    }
  }
})
