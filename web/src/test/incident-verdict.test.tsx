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
import type { Incident } from '../api/incidents'
import type { IncidentVerdictResponse } from '../api/sdk.gen'
import { IncidentVerdictCard } from '../routes/IncidentVerdictCard'
import { TimeProvider } from '../time/TimeProvider'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

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
const permissions = ['incident.read', 'entities.read', 'metrics.read', 'events.read', 'test.read']
function response(tenant: string): IncidentVerdictResponse {
  return {
    contract_version: 'probectl.incident-verdict.v1',
    preview: true,
    incident_id: id,
    evaluated_at: incident.last_seen_at,
    from: incident.started_at,
    to: incident.last_seen_at,
    domain: 'unknown',
    confidence: 'insufficient',
    reason: 'insufficient_original_evidence',
    hypotheses: (['your_network', 'carrier', 'wider_internet', 'remote_service'] as const).map(
      (domain) => ({
        domain,
        confidence: 'insufficient' as const,
        against: [],
        missing: [`${domain}_coverage_unavailable`],
        for:
          domain === 'your_network'
            ? [
                {
                  context_id: id,
                  entity_id: id,
                  evidence_id: id,
                  digest: 'a'.repeat(64),
                  agent_id: `${tenant}-source`,
                  observed_at: incident.last_seen_at,
                  reason: 'original_admin_up_oper_down_local_interface',
                },
              ]
            : [],
      }),
    ),
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
      <TimeProvider>
        <main>
          <button onClick={() => setTenant('blue')}>Switch verdict tenant</button>
          <button onClick={() => setAllowed(false)}>Withdraw verdict access</button>
          <IncidentVerdictCard incident={incident} />
        </main>
      </TimeProvider>
    </AuthContext.Provider>
  )
}
for (const theme of ['light', 'dark'])
  test(`fault verdict retains hypotheses and original citations in ${theme}`, async () => {
    document.documentElement.dataset.theme = theme
    const fallback = defaultFetch()
    let selected: Record<string, string> | undefined
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === `/v1/incidents/${id}/verdict`) {
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
    const start = '2026-11-01T00:00:00.000000001Z',
      end = '2026-11-01T00:00:00.000000002Z'
    fireEvent.change(screen.getByLabelText('Verdict from (ISO 8601 with offset)'), {
      target: { value: start },
    })
    fireEvent.change(screen.getByLabelText('Verdict to (exclusive, ISO 8601 with offset)'), {
      target: { value: end },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate fault domain' }))
    expect(await screen.findByText('red-source')).toBeInTheDocument()
    expect(selected).toEqual({ from: start, to: end })
    for (const name of ['Your network', 'Carrier', 'Wider internet', 'Remote service'])
      expect(screen.getByRole('region', { name })).toBeInTheDocument()
    expect(screen.getByText('carrier coverage unavailable')).toBeInTheDocument()
    expect(screen.getByText('insufficient original evidence')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw verdict access' }))
    expect(screen.queryByText('red-source')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Evaluate fault domain' })).not.toBeInTheDocument()
    view.unmount()
  })

test('late verdict completion cannot disclose the previous tenant', async () => {
  const fallback = defaultFetch()
  let finish: ((value: Response) => void) | undefined
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === `/v1/incidents/${id}/verdict`)
      return new Promise<Response>((resolve) => {
        finish = resolve
      })
    return fallback(input, init)
  })
  const view = render(
    <Providers>
      <Harness />
    </Providers>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'Evaluate fault domain' }))
  await waitFor(() => expect(finish).toBeDefined())
  fireEvent.click(screen.getByRole('button', { name: 'Switch verdict tenant' }))
  await act(async () => {
    finish!(jsonResponse(response('red')))
  })
  expect(screen.queryByText('red-source')).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Evaluate fault domain' })).toBeEnabled()
  view.unmount()
})
