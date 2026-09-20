// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import type { SIEMStatus } from '../api/siem'

const configured: SIEMStatus = {
  id: 'siem-export',
  name: 'SIEM export',
  summary: 'Forwarding the audit and threat streams to the configured collector.',
  siem_running: true,
  enabled: true,
  configured: true,
  reason: 'configured',
  preset: 'splunk',
  format: 'splunk-hec',
  endpoint_configured: true,
  endpoint_tls_configured: true,
  endpoint_host: 'siem.probectl.test:8088',
  token_configured: true,
  audit_poll_interval: '30s',
  buffer_size: 1000,
  redact_key_count: 4,
  tls_required: true,
  no_drop_delivery: true,
  streams: ['audit', 'threat'],
}

function siemFetch(status: Partial<SIEMStatus> | 'error') {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === '/v1/siem/status') {
      if (status === 'error') {
        return new Response(JSON.stringify({ error: { message: 'no' } }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return jsonResponse({ ...configured, ...status })
    }
    return base(input, init)
  })
}

/**
 * DPR-254 (F26): the SIEM status API and CLI existed with no screen, so an
 * operator could not see whether their audit and threat records were leaving
 * the deployment without opening a terminal. These tests pin the two things
 * that make the card worth having: it states the posture in words, and it
 * cannot leak the credential material the API deliberately withholds.
 */
describe('SIEM delivery posture card', () => {
  test('shows what is forwarded, where, and under what back-pressure policy', async () => {
    vi.stubGlobal('fetch', siemFetch({}))
    renderApp('/admin', { me: { permissions: ['threat.read'] } })

    expect(await screen.findByText('SIEM export posture')).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: /SIEM delivery posture/i })
    expect(table).toHaveTextContent('Exporter running')
    expect(table).toHaveTextContent('audit')
    expect(table).toHaveTextContent('threat')
    expect(table).toHaveTextContent('splunk-hec')
    expect(table).toHaveTextContent('siem.probectl.test:8088')
    expect(table).toHaveTextContent('Never drop')
  })

  test('a configured endpoint without TLS is named as such, not softened', async () => {
    vi.stubGlobal(
      'fetch',
      siemFetch({
        endpoint_tls_configured: false,
        tls_required: false,
        endpoint_host: 'plain:514',
      }),
    )
    renderApp('/admin', { me: { permissions: ['threat.read'] } })

    const table = await screen.findByRole('table', { name: /SIEM delivery posture/i })
    expect(table).toHaveTextContent('Configured WITHOUT TLS')
    expect(table).toHaveTextContent('Not required')
  })

  test('a drop-oldest buffer says the SIEM copy can be incomplete', async () => {
    vi.stubGlobal('fetch', siemFetch({ no_drop_delivery: false, buffer_size: 250 }))
    renderApp('/admin', { me: { permissions: ['threat.read'] } })

    const table = await screen.findByRole('table', { name: /SIEM delivery posture/i })
    expect(table).toHaveTextContent('Drop oldest when full')
    expect(table).toHaveTextContent(/250-event buffer discards the oldest record/i)
    expect(table).toHaveTextContent(/can be incomplete/i)
  })

  test('an unconfigured exporter is blocked with the server reason, never blank', async () => {
    vi.stubGlobal(
      'fetch',
      siemFetch({ configured: false, siem_running: false, reason: 'insecure_endpoint' }),
    )
    renderApp('/admin', { me: { permissions: ['threat.read'] } })

    expect(await screen.findByText(/Endpoint refused \(not TLS\)/i)).toBeInTheDocument()
    expect(screen.getByText(/reason=insecure_endpoint/)).toBeInTheDocument()
    expect(
      screen.getByText(/exist only inside this deployment/i),
      'a blocked exporter must say what the consequence is',
    ).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: /SIEM delivery posture/i })).not.toBeInTheDocument()
  })

  test('an omitted reason code is reported as unknown, not inferred as disabled', async () => {
    // `reason` is optional in the API. Guessing "disabled" from its absence
    // would send an operator to check an environment variable the server never
    // mentioned.
    vi.stubGlobal('fetch', siemFetch({ configured: false, siem_running: false, reason: undefined }))
    renderApp('/admin', { me: { permissions: ['threat.read'] } })

    expect(await screen.findByText(/reason not reported/i)).toBeInTheDocument()
    expect(screen.getByText(/sent no reason code/i)).toBeInTheDocument()
    expect(screen.queryByText(/PROBECTL_SIEM_ENABLED is off/)).not.toBeInTheDocument()
  })

  test('an unreachable status endpoint does not read as "forwarding is fine"', async () => {
    vi.stubGlobal('fetch', siemFetch('error'))
    renderApp('/admin', { me: { permissions: ['threat.read'] } })

    await waitFor(() =>
      expect(screen.getByText(/Absence here is not evidence/i)).toBeInTheDocument(),
    )
  })

  test('renders no endpoint path, query, or token even when the server sends one', async () => {
    // The API contract says these are never returned. If a future server
    // regresses and sends them, the card must still not put them on screen.
    vi.stubGlobal(
      'fetch',
      siemFetch({
        ...({
          endpoint: 'https://siem.probectl.test:8088/services/collector?index=audit',
          token: 'hec-SUPERSECRET-token',
        } as unknown as Partial<SIEMStatus>),
      }),
    )
    const { container } = renderApp('/admin', { me: { permissions: ['threat.read'] } })

    await screen.findByRole('table', { name: /SIEM delivery posture/i })
    expect(container.textContent).not.toContain('SUPERSECRET')
    expect(container.textContent).not.toContain('/services/collector')
    expect(container.textContent).not.toContain('index=audit')
  })
})
