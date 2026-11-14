// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, screen, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

test('paired tenant interface views keep FCS and alignment separate with explicit missing counters', async () => {
  for (const lane of [1, 2]) {
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) =>
      pathOf(input) === '/v1/device/metrics'
        ? jsonResponse({
            metrics_running: true,
            effective_limit: 500,
            items: [
              ...[
                { metric: 'probectl_device_if_in_fcs_errors', value: 711 + lane },
                { metric: 'probectl_device_if_in_alignment_errors', value: 811 + lane },
              ].map((sample) => ({
                ...sample,
                device: '192.0.2.9',
                agent_id: `collector-${lane}`,
                if_index: '7',
                if_name: 'same-port',
                source: 'snmp',
                last_seen: '2026-11-14T00:01:00Z',
              })),
              {
                metric: 'probectl_device_if_oper_status',
                value: 1,
                device: '192.0.2.9',
                agent_id: `collector-${lane}`,
                if_index: '8',
                if_name: 'unsupported-port',
                source: 'snmp',
                last_seen: '2026-11-14T00:01:00Z',
              },
            ],
          })
        : fallback(input, init),
    )
    renderApp('/planes/device', {
      me: { tenant_id: `tenant-${lane}`, permissions: ['metrics.read'] },
    })
    const table = await screen.findByRole('table', { name: 'Interface counters' })
    expect(within(table).getByRole('columnheader', { name: 'FCS errors' })).toBeVisible()
    expect(within(table).getByRole('columnheader', { name: 'Alignment errors' })).toBeVisible()
    const row = within(table).getByText('same-port').closest('tr')
    if (!row) throw new Error('missing owned interface row')
    expect(within(row).getByText(String(711 + lane))).toBeVisible()
    expect(within(row).getByText(String(811 + lane))).toBeVisible()
    expect(table).not.toHaveTextContent(String(711 + 3 - lane))
    const unsupported = within(table).getByText('unsupported-port').closest('tr')
    if (!unsupported) throw new Error('missing unsupported interface row')
    expect(within(unsupported).getAllByText('Not reported').length).toBeGreaterThanOrEqual(2)
    cleanup()
  }
})
