// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { expect, test, vi } from 'vitest'
import { screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

for (const tenant of [
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000002',
]) {
  test(`keeps complete pinned flow samples alongside assessment bounds for ${tenant}`, async () => {
    const fallback = defaultFetch()
    const source = '33333333-3333-4333-8333-333333333333'
    const selected = {
      id: source,
      version: '9007199254740993',
      owner_id: 'u_test',
      definition: { name: `Flow sample ${tenant}`, visibility: 'private' },
    }
    const saved: Array<Record<string, unknown>> = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        if (path === '/v1/explorer/flow-views') return jsonResponse({ items: [selected] })
        if (path === '/v1/dashboards') {
          if (init?.method === 'POST') {
            const body = JSON.parse(String(init.body)) as Record<string, unknown>
            saved.push(body)
            return jsonResponse(
              { ...body, id: 'assessment-sample', tenant_id: tenant, owner_id: 'u_test' },
              201,
            )
          }
          return jsonResponse({ items: [] })
        }
        return fallback(input, init)
      }),
    )
    renderApp('/dashboards', {
      me: {
        tenant_id: tenant,
        permissions: [
          'metrics.read',
          'metrics.write',
          'entities.read',
          'topology.read',
          'test.read',
          'incident.read',
          'change.read',
          'events.read',
          'flow.read',
          'ai.query',
        ],
      },
    })
    const user = userEvent.setup()
    await user.click(
      await screen.findByRole('checkbox', { name: 'Build a client report (preview)' }),
    )
    const editor = screen.getByRole('region', { name: 'Client report configuration' })
    await user.selectOptions(
      within(editor).getByRole('combobox', { name: 'Report period' }),
      'assessment',
    )
    await user.type(within(editor).getByLabelText('Assessment start'), '2026-10-01T00:00:00Z')
    await user.type(within(editor).getByLabelText('Assessment end'), '2026-10-15T00:00:00Z')
    await user.type(within(editor).getByLabelText('Assessment prepared by'), 'Example MSP')
    await user.click(screen.getByRole('checkbox', { name: 'Include saved flow query sample' }))
    expect(screen.getByRole('button', { name: 'Save dashboard' })).toBeDisabled()
    await user.click(await screen.findByRole('button', { name: `Open Flow sample ${tenant}` }))
    await user.click(screen.getByRole('button', { name: 'Save dashboard' }))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(saved[0].definition).toMatchObject({
      client_report: {
        period: 'assessment',
        assessment: {
          from: '2026-10-01T00:00:00Z',
          to: '2026-10-15T00:00:00Z',
          preparer: 'Example MSP',
        },
      },
      flow_sources: [{ id: source, version: '9007199254740993' }],
    })
    expect(saved[0].definition).not.toHaveProperty('metrics')
    await user.selectOptions(
      within(editor).getByRole('combobox', { name: 'Report period' }),
      'completed_month',
    )
    expect(
      screen.getByRole('checkbox', { name: 'Build from saved flow queries' }),
    ).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Build a client report (preview)' })).toBeChecked()
  })
}
