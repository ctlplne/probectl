// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse } from './fetchStub'
import { renderApp } from './renderApp'

/** defaultFetch with /v1/editions overridden — the license ladder's banner
 * states (internal/license: grace = "full function + banner"). */
function editionsStub(response: unknown, status = 200) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (new URL(url, 'https://probectl.test').pathname === '/v1/editions') {
      return jsonResponse(response, status)
    }
    return defaultFetch()(input, init)
  }) as unknown as typeof fetch
}

const IN_FIVE_DAYS = new Date(Date.now() + 5 * 86_400_000).toISOString()

const graceInfo = {
  tier: 'enterprise',
  state: 'grace',
  read_only_at: IN_FIVE_DAYS,
  features: [],
}

describe('edition/license lifecycle banner', () => {
  test('grace shows the countdown and dismiss is session-only memory', async () => {
    vi.stubGlobal('fetch', editionsStub(graceInfo))
    renderApp('/targets')

    const banner = await screen.findByLabelText('License status')
    expect(banner).toHaveTextContent(/license expired/i)
    expect(banner).toHaveTextContent(/read-only in 5 days/i)
    expect(banner).toHaveTextContent('License grace')

    await userEvent.click(screen.getByRole('button', { name: /^dismiss$/i }))
    await waitFor(() => expect(screen.queryByLabelText('License status')).toBeNull())
  })

  test('read_only shows the quiet factual strip with telemetry reassurance', async () => {
    vi.stubGlobal('fetch', editionsStub({ tier: 'enterprise', state: 'read_only', features: [] }))
    renderApp('/targets')

    const banner = await screen.findByLabelText('License status')
    expect(banner).toHaveTextContent(/commercial features are read-only/i)
    expect(banner).toHaveTextContent(/telemetry is unaffected/i)
  })

  test('community and active deployments never see a pixel', async () => {
    // Default fixture is state:community.
    vi.stubGlobal('fetch', defaultFetch())
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })
    expect(screen.queryByLabelText('License status')).toBeNull()

    vi.stubGlobal('fetch', editionsStub({ tier: 'enterprise', state: 'active', features: [] }))
    renderApp('/dashboards')
    await screen.findByRole('heading', { name: /^dashboards$/i })
    expect(screen.queryByLabelText('License status')).toBeNull()
  })

  test('a role that cannot read /editions gets silence, not an error', async () => {
    vi.stubGlobal(
      'fetch',
      editionsStub({ error: { message: 'missing permission: editions.read' } }, 403),
    )
    renderApp('/targets')
    await screen.findByRole('heading', { name: /targets & tests/i })
    expect(screen.queryByLabelText('License status')).toBeNull()
  })

  test('demo mode never queries editions and never shows the banner', async () => {
    const fetcher = editionsStub(graceInfo)
    vi.stubGlobal('fetch', fetcher)
    renderApp('/targets?demo=1')

    await screen.findByLabelText(/demo mode is active/i)
    expect(screen.queryByLabelText('License status')).toBeNull()
    const editionCalls = (fetcher as ReturnType<typeof vi.fn>).mock.calls.filter(([input]) =>
      String(input).includes('/v1/editions'),
    )
    expect(editionCalls).toHaveLength(0)
  })
})
