// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import type { LatestResult } from '../api/results'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { I18nProvider } from '../i18n/I18nProvider'
import { ResultDetail } from '../routes/ResultDetail'
import { TimeProvider } from '../time/TimeProvider'
import { jsonResponse, pathOf } from './fetchStub'

test('browser results stay scoped when tenants reuse identifiers and history access is withdrawn', async () => {
  const observed = '2026-11-24T10:00:00Z'
  const testID = '00000000-0000-4000-8000-000000000101'
  const target = 'https://fixture.example.test/'
  const latest = [260, 170]
  const history = [491, 394]
  const tenantIDs = ['tenant-alpha', 'tenant-beta']
  let activeTenant = 0
  let historyDenied = false
  function row(inp: number): LatestResult {
    return {
      agent_id: 'same-agent',
      type: 'browser',
      target,
      success: true,
      observed_at: observed,
      attributes: { 'browser.driver': 'browser', 'probectl.test.id': testID },
      metrics: { 'browser.web_vitals.inp_ms': inp },
    }
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      switch (pathOf(input)) {
        case '/v1/results/latest':
          return jsonResponse({ items: [row(latest[activeTenant])], collector_running: true })
        case '/v1/results/history':
          if (historyDenied) return jsonResponse({ error: { message: 'refused' } }, 403)
          return jsonResponse({
            items: [row(history[activeTenant])],
            collector_running: true,
            window: '1h',
          })
        default:
          throw new Error('unexpected browser result request')
      }
    }),
  )
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity } } })
  function view() {
    const id = tenantIDs[activeTenant]
    const tenant = { id, name: id, slug: id }
    const auth: AuthContextValue = {
      tenant,
      tenants: [tenant],
      user: { id: 'operator', name: 'Operator', email: 'operator@example.test' },
      permissions: ['test.read', 'metrics.read'],
      switchTenant: () => {},
      signOut: () => {},
    }
    return (
      <QueryClientProvider client={client}>
        <AuthContext.Provider value={auth}>
          <I18nProvider initialLocale="en">
            <TimeProvider>
              <ResultDetail
                test={{
                  id: testID,
                  tenant_id: id,
                  name: 'Synthetic result',
                  target,
                  type: 'browser',
                  created_at: observed,
                  updated_at: observed,
                }}
                onClose={() => {}}
              />
            </TimeProvider>
          </I18nProvider>
        </AuthContext.Provider>
      </QueryClientProvider>
    )
  }
  const { rerender, unmount } = render(view())
  expect(await screen.findByText(/p75 491/)).toBeInTheDocument()
  expect(screen.getByText(/Latest 260/)).toBeInTheDocument()

  activeTenant = 1
  rerender(view())
  expect(screen.queryByText(/Latest 260/)).not.toBeInTheDocument()
  expect(screen.queryByText(/p75 491/)).not.toBeInTheDocument()
  expect(await screen.findByText(/p75 394/)).toBeInTheDocument()
  expect(screen.getByText(/Latest 170/)).toBeInTheDocument()

  historyDenied = true
  await act(async () => {
    await client.refetchQueries({ queryKey: ['results', 'history'], type: 'active' })
  })
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not load Web Vitals history.')
  expect(screen.queryByText(/p75 394/)).not.toBeInTheDocument()
  expect(screen.getByText(/Latest 170/)).toBeInTheDocument()
  unmount()
  client.clear()
})
