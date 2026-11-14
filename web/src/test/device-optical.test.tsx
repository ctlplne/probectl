// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, screen, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

test('paired optical-only fleets keep every component and distinguish component levels from channel zero', async () => {
  for (const lane of [1, 2]) {
    const fallback = defaultFetch()
    const rows = Array.from({ length: 512 }, (_, index) => ({
      id: `component-${lane}-${index}`,
      device: '192.0.2.50',
      agent_id: `agent-${lane}`,
      component: `optic-${lane}-${index}`,
      physical_channel: index === 0 ? undefined : '0',
      metric: 'probectl_device_optical_input_power_dbm',
      value: -3.25 - lane,
      last_seen: '2026-11-14T00:00:00Z',
      source: 'gnmi',
    }))
    let requestedLimit = 0
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) !== '/v1/device/metrics') return fallback(input, init)
      const url = new URL(
        typeof input === 'string' ? input : input instanceof URL ? input : input.url,
        'https://local.invalid',
      )
      requestedLimit = Number(url.searchParams.get('limit'))
      return jsonResponse({ items: rows, metrics_running: true, effective_limit: requestedLimit })
    })
    renderApp('/planes/device', {
      me: { tenant_id: `tenant-${lane}`, permissions: ['metrics.read'] },
    })
    const table = await screen.findByRole('table', { name: 'Component sensors' })
    expect(requestedLimit).toBeGreaterThanOrEqual(512)
    expect(within(table).getAllByRole('row')).toHaveLength(513)
    expect(within(table).getByText('Component level')).toBeVisible()
    expect(within(table).getAllByText('0')).toHaveLength(511)
    expect(table).toHaveTextContent(`optic-${lane}-511`)
    expect(table).not.toHaveTextContent(`optic-${3 - lane}-511`)
    expect(table).toHaveTextContent(`${-3.25 - lane} dBm`)
    expect(screen.queryByText('No device telemetry yet')).not.toBeInTheDocument()
    const interfaces = screen.getByRole('table', { name: 'Interface counters' })
    expect(interfaces).not.toHaveTextContent(`optic-${lane}`)
    cleanup()
  }
})
