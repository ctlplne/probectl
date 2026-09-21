// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

describe('cross-source identity conflict review', () => {
  test('renders provenance in the Device workflow and pivots to exact topology evidence', async () => {
    renderApp('/planes/device')

    const table = await screen.findByRole('table', {
      name: /tenant-local identity disagreements/i,
    })
    expect(within(table).getByText('edge-r1')).toBeInTheDocument()
    expect(within(table).getByText('edge-router-1')).toBeInTheDocument()
    expect(within(table).getByText('device-snmp-1')).toBeInTheDocument()
    expect(within(table).getByText('device-gnmi-1')).toBeInTheDocument()
    expect(within(table).getByText(/high confidence/i)).toBeInTheDocument()

    await userEvent.click(within(table).getByText(/review proposal/i))
    expect(within(table).getByRole('button', { name: /merge unavailable/i })).toBeDisabled()
    expect(within(table).getByText(/will not select a winner/i)).toBeInTheDocument()

    await userEvent.click(
      within(table).getByRole('button', {
        name: /inspect topology evidence device:10\.0\.0\.1/i,
      }),
    )
    expect(await screen.findByRole('heading', { name: 'Topology' })).toBeInTheDocument()
    expect(screen.getByLabelText(/search topology/i)).toHaveValue('10.0.0.1')
  })

  test('sends keyboard-operable identity, source, and state filters to the bounded API', async () => {
    const fallback = defaultFetch()
    const calls: string[] = []
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(input))
      return fallback(input, init)
    })
    const user = userEvent.setup()
    renderApp('/topology')
    await screen.findByRole('table', { name: /tenant-local identity disagreements/i })

    await user.type(screen.getByLabelText('Find identity'), 'edge')
    await user.selectOptions(screen.getByLabelText('Identity field'), 'interface_name')
    await user.type(screen.getByLabelText('Source'), 'gnmi')
    await user.selectOptions(screen.getByLabelText('Review state'), 'stale')

    await waitFor(() => {
      expect(
        calls.some((call) => {
          const url = new URL(call, 'http://t.invalid')
          return (
            url.pathname === '/v1/device/identity-conflicts' &&
            url.searchParams.get('q') === 'edge' &&
            url.searchParams.get('kind') === 'interface_name' &&
            url.searchParams.get('source') === 'gnmi' &&
            url.searchParams.get('status') === 'stale' &&
            url.searchParams.get('limit') === '100'
          )
        }),
      ).toBe(true)
    })
  })

  test('distinguishes no-conflict, filtered-empty, unavailable, truncated, and error states', async () => {
    const fallback = defaultFetch()
    let mode: 'clean' | 'filtered' | 'unavailable' | 'truncated' | 'error' = 'clean'
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) !== '/v1/device/identity-conflicts') return fallback(input, init)
      if (mode === 'error') {
        return Promise.resolve(
          jsonResponse(
            { error: { code: 'unavailable', message: 'identity store unavailable' } },
            503,
          ),
        )
      }
      if (mode === 'unavailable') {
        return Promise.resolve(
          jsonResponse({
            items: [],
            topology_running: false,
            effective_limit: 100,
            truncated: false,
            partial_reasons: ['topology identity store is not wired'],
          }),
        )
      }
      if (mode === 'truncated') {
        return Promise.resolve(
          jsonResponse({
            items: [],
            topology_running: true,
            effective_limit: 100,
            filtered_count: 0,
            truncated: true,
            partial_reasons: ['tenant identity claim store reached its safety bound'],
          }),
        )
      }
      return Promise.resolve(
        jsonResponse({
          items: [],
          topology_running: true,
          effective_limit: 100,
          filtered_count: 0,
          truncated: false,
          partial_reasons: [],
        }),
      )
    })

    const first = renderApp('/planes/device')
    expect(await screen.findByText(/no identity conflicts observed/i)).toBeInTheDocument()
    mode = 'filtered'
    await userEvent.type(screen.getByLabelText('Find identity'), 'missing')
    expect(await screen.findByText(/no conflicts match these filters/i)).toBeInTheDocument()
    first.unmount()

    mode = 'unavailable'
    const second = renderApp('/planes/device')
    expect(await screen.findByText(/identity conflict detection unavailable/i)).toBeInTheDocument()
    expect(screen.getByText(/not a clean bill of health/i)).toBeInTheDocument()
    second.unmount()

    mode = 'truncated'
    const third = renderApp('/planes/device')
    expect(await screen.findByRole('note')).toHaveTextContent(/partial result/i)
    expect(screen.getByRole('note')).toHaveTextContent(/safety bound/i)
    third.unmount()

    mode = 'error'
    renderApp('/planes/device')
    expect(
      await screen.findByText(/could not load identity conflict evidence/i),
    ).toBeInTheDocument()
  })
})
