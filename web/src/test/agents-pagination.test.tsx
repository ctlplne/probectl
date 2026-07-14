// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import { MAX_RENDERED_ROWS } from '../components/Table'
import { AGENTS_PAGE_SIZE } from '../api/agents'

// UX-004: the agents list must ride the backend's cursor pagination
// (?after=<id>&limit=<n>) instead of fetching every row, and the table must
// render a BOUNDED number of rows even when the backend returns a fleet-scale
// response. Before the fix useAgents() called bare `/agents` and Table rendered
// rows.map over the full array — unbounded.
describe('Agents list pagination + bounded render (UX-004)', () => {
  test('useAgents requests ?after=&limit= and the tbody stays bounded under a 10k-row fixture', async () => {
    // 10k agents in one page (the over-large response we must NOT fully render).
    const fleet = Array.from({ length: 10_000 }, (_, i) => ({
      id: `a${i}`,
      name: `agent-${i}`,
      hostname: `host-${i}`,
      agent_version: '0.4.0',
      status: 'online' as const,
      capabilities: ['icmp'],
    }))

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/v1/me') && !url.includes('/provider/')) {
        return jsonResponse({
          tenant_id: '00000000-0000-0000-0000-000000000001',
          user_id: 'u_test',
          email: 'operator@probectl.test',
          display_name: 'Test Operator',
          mfa_satisfied: true,
          permissions: [],
        })
      }
      if (/\/v1\/agents(\?|$)/.test(url)) {
        // Full page → backend returns a next_cursor; FE may load more.
        return jsonResponse({ items: fleet, next_cursor: 'a9999' })
      }
      return jsonResponse({ items: [] })
    })
    vi.stubGlobal('fetch', fetchMock)

    renderApp('/admin')

    await screen.findByText('agent-0')

    // 1. The request MUST carry both cursor-pagination params.
    const agentsCall = fetchMock.mock.calls.find(([u]) => /\/v1\/agents\?/.test(String(u)))
    expect(agentsCall, 'useAgents must request /v1/agents with a query string').toBeTruthy()
    const reqUrl = String(agentsCall![0])
    expect(reqUrl).toContain(`limit=${AGENTS_PAGE_SIZE}`)
    // First page has no cursor; the param appears once a next page is fetched.
    expect(reqUrl).toMatch(/[?&]limit=\d+/)

    // 2. The rendered tbody must stay bounded — NOT 10k <tr>.
    const table = await screen.findByRole('table', { name: /registered agents/i })
    const bodyRows = table.querySelectorAll('tbody tr')
    // <= the table cap + 1 truncation-notice row.
    await waitFor(() => {
      expect(bodyRows.length).toBeLessThanOrEqual(MAX_RENDERED_ROWS + 1)
    })
    expect(bodyRows.length).toBeLessThan(fleet.length)
  })
})
