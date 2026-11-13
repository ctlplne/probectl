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
        against:
          domain === 'carrier'
            ? [
                {
                  context_id: id,
                  entity_id: id,
                  source_kind: 'control_plane_path' as const,
                  path_round_id: '01234567890123456789abcdefabcdef',
                  agent_id: 'control_plane',
                  digest: 'b'.repeat(64),
                  observed_at: incident.last_seen_at,
                  reason: 'control_plane_terminal_reply_not_an_agent_path',
                },
              ]
            : [],
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
            : domain === 'carrier'
              ? [
                  {
                    context_id: id,
                    entity_id: id,
                    evidence_id: id,
                    agent_id: `${tenant}-peer`,
                    digest: 'c'.repeat(64),
                    observed_at: incident.last_seen_at,
                    reason: 'original_carrier_neighbor_hold_timer_expired',
                    peer_asn: 4294967295,
                    handoff_interface_id: id,
                  },
                ]
              : domain === 'wider_internet'
                ? [
                    {
                      context_id: id,
                      entity_id: id,
                      source_kind: 'router_bgp' as const,
                      agent_id: `${tenant}-router`,
                      digest: 'd'.repeat(64),
                      observed_at: incident.last_seen_at,
                      reason:
                        'current_selected_prefix_origin_beyond_declared_provider_not_forwarding_proof',
                      routing: {
                        view_id: id,
                        generation_id: '22222222-2222-4222-8222-222222222222',
                        sequence: '9223372036854775807',
                        address: '2001:db8::7',
                        prefix: '2001:db8::/64',
                        origin_asn: 4294967294,
                      },
                    },
                  ]
                : [],
      }),
    ),
  }
}
function Harness({ canExport = false }: { canExport?: boolean }) {
  const [tenant, setTenant] = useState('red')
  const [allowed, setAllowed] = useState(true)
  return (
    <AuthContext.Provider
      value={{
        tenant: { id: tenant, name: tenant, slug: tenant },
        tenants: [],
        user: { id: 'reader', name: 'Reader', email: 'reader@local.test' },
        permissions: allowed
          ? [...permissions, ...(canExport ? ['ai.query'] : [])]
          : ['incident.read'],
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
    expect(screen.getByText('AS4294967295')).toBeInTheDocument()
    expect(screen.getByText('Hand-off interface')).toBeInTheDocument()
    expect(screen.getByText('Selected routing view')).toBeInTheDocument()
    expect(
      screen.getByText('AS4294967294 (routing context, not forwarding proof)'),
    ).toBeInTheDocument()
    expect(screen.getByText('2001:db8::7 / 2001:db8::/64')).toBeInTheDocument()
    expect(selected).toEqual({ from: start, to: end })
    for (const name of ['Your network', 'Carrier', 'Wider internet', 'Remote service'])
      expect(screen.getByRole('region', { name })).toBeInTheDocument()
    expect(screen.getByText('carrier coverage unavailable')).toBeInTheDocument()
    expect(screen.getByText('insufficient original evidence')).toBeInTheDocument()
    expect(screen.getByText('Control-plane path round')).toBeInTheDocument()
    expect(screen.getByText('01234567890123456789abcdefabcdef')).toBeInTheDocument()
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

test('signed verdict download retains the exact window and refuses a late tenant export', async () => {
  const fallback = defaultFetch()
  const from = '2026-11-01T00:00:00.000000001Z'
  const to = '2026-11-01T00:00:00.000000002Z'
  const verdict = { ...response('red'), from, to }
  const signed = new Uint8Array([123, 32, 34, 110, 34, 58, 57, 125])
  let selected: unknown
  let finish: ((value: Response) => void) | undefined
  let exports = 0
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === `/v1/incidents/${id}/verdict`)
      return Promise.resolve(jsonResponse(verdict))
    if (pathOf(input) === `/v1/incidents/${id}/exports`) {
      selected = JSON.parse(String(init?.body))
      exports++
      if (exports === 1) return Promise.resolve(new Response(signed))
      return new Promise<Response>((resolve) => {
        finish = resolve
      })
    }
    return fallback(input, init)
  })
  const create = vi.fn(() => 'blob:verdict')
  const revoke = vi.fn()
  const originals = ['createObjectURL', 'revokeObjectURL'].map((key) =>
    Object.getOwnPropertyDescriptor(URL, key),
  )
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: create })
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revoke })
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  const view = render(
    <Providers>
      <Harness canExport />
    </Providers>,
  )
  try {
    fireEvent.click(screen.getByRole('button', { name: 'Evaluate fault domain' }))
    const download = await screen.findByRole('button', { name: 'Export signed fault evidence' })
    fireEvent.click(download)
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1))
    expect(selected).toEqual({ verdict: { from, to } })
    expect(create).toHaveBeenCalledTimes(1)
    expect(revoke).toHaveBeenCalledWith('blob:verdict')
    expect(await screen.findByText(/Signed evidence downloaded/)).toBeInTheDocument()
    fireEvent.click(download)
    await waitFor(() => expect(finish).toBeDefined())
    fireEvent.click(screen.getByRole('button', { name: 'Switch verdict tenant' }))
    await act(async () => {
      finish!(new Response(signed))
    })
    expect(click).toHaveBeenCalledTimes(1)
    expect(create).toHaveBeenCalledTimes(1)
    expect(screen.queryByText(/Signed evidence downloaded/)).not.toBeInTheDocument()
  } finally {
    view.unmount()
    click.mockRestore()
    for (const [i, key] of ['createObjectURL', 'revokeObjectURL'].entries()) {
      if (originals[i]) Object.defineProperty(URL, key, originals[i])
      else Reflect.deleteProperty(URL, key)
    }
  }
})
