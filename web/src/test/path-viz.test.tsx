// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'
import { samplePath, stubPathFetch } from './pathFixture'

describe('path visualization', () => {
  test('shows ECMP evidence inline and synchronizes keyboard selection', async () => {
    const user = userEvent.setup()
    stubPathFetch()
    renderApp('/path')

    await screen.findByRole('heading', { name: /path & topology/i })
    const graph = await screen.findByRole('group', { name: /network path to 9\.9\.9\.9/i })

    expect(screen.getByText('Full-hop acquisition')).toBeInTheDocument()
    expect(screen.getByText('raw icmp')).toBeInTheDocument()
    expect(
      screen.getByText(
        'application monotonic · kernel timestamps off · hardware timestamps off',
      ),
    ).toBeInTheDocument()

    // Branch identity, loss, latency, and MPLS evidence are visible before drill-down.
    expect(within(graph).getByText(/Branch 1.*12 ms.*66% loss/i)).toBeInTheDocument()
    expect(within(graph).getByText(/MPLS.*16001/i)).toBeInTheDocument()

    // The lossy ECMP branch is a focusable node whose accessible name states the loss.
    const lossy = within(graph).getByRole('button', {
      name: /hop 2, branch 1, 10\.0\.0\.2.*66% loss/i,
    })
    lossy.focus()
    expect(lossy).toHaveFocus()

    // Keyboard-operable: Enter selects the branch in every view and opens its details.
    await user.keyboard('{Enter}')
    expect(lossy).toHaveAttribute('aria-pressed', 'true')

    const lossChart = screen.getByRole('group', { name: /packet loss by hop/i })
    expect(
      within(lossChart).getByRole('button', { name: /hop 2, branch 1, 10\.0\.0\.2/i }),
    ).toHaveAttribute('aria-pressed', 'true')

    const table = screen.getByRole('table', { name: /path to 9\.9\.9\.9 by hop/i })
    const selectedRow = within(table).getByText('10.0.0.2').closest('tr')
    expect(selectedRow).not.toBeNull()
    expect(within(selectedRow!).getByRole('button', { name: 'Selected' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )

    const dialog = await screen.findByRole('dialog', {
      name: /hop 2 .*branch 1.*10\.0\.0\.2/i,
    })
    expect(within(dialog).getByText(/16001/)).toBeInTheDocument()
  })

  test('exposes an accessible per-hop table alternative', async () => {
    stubPathFetch()
    renderApp('/path')
    const table = await screen.findByRole('table', { name: /path to 9\.9\.9\.9 by hop/i })
    expect(within(table).getByText('10.0.0.2')).toBeInTheDocument()
    const destinationRow = within(table).getByText('9.9.9.9').closest('tr')
    expect(destinationRow).not.toBeNull()
    expect(within(destinationRow!).getByText('destination')).toBeInTheDocument()
  })

  test('shows an empty state when no path has been discovered', async () => {
    stubPathFetch(null)
    renderApp('/path')
    expect(await screen.findByText(/no path discovered yet/i)).toBeInTheDocument()
  })

  test('does not infer precision for a legacy path snapshot', async () => {
    stubPathFetch({ ...samplePath, measurement_fidelity: undefined })
    renderApp('/path')
    expect(await screen.findByText('Unknown · legacy snapshot')).toBeInTheDocument()
    expect(
      screen.getByText('Acquisition capabilities were not stored; no precision is inferred.'),
    ).toBeInTheDocument()
  })

  test('loads additional test pages into the path selector', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://t.invalid')
        const method = init?.method ?? 'GET'
        if (url.pathname === '/v1/tests' && method === 'GET') {
          const after = url.searchParams.get('after')
          if (!after) {
            return jsonResponse({
              items: [
                {
                  id: 't1',
                  name: 'first-path-test',
                  type: 'icmp',
                  target: '1.1.1.1',
                  interval_seconds: 30,
                  timeout_seconds: 3,
                  params: {},
                  enabled: true,
                  created_at: '',
                  updated_at: '',
                },
              ],
              next_cursor: 'cursor-2',
            })
          }
          if (after === 'cursor-2') {
            return jsonResponse({
              items: [
                {
                  id: 't2',
                  name: 'second-path-test',
                  type: 'icmp',
                  target: '9.9.9.9',
                  interval_seconds: 30,
                  timeout_seconds: 3,
                  params: {},
                  enabled: true,
                  created_at: '',
                  updated_at: '',
                },
              ],
            })
          }
        }
        if (url.pathname === '/v1/tests/t1/path') {
          return jsonResponse({ error: { code: 'not_found', message: 'no path' } }, 404)
        }
        return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
      }),
    )

    renderApp('/path')
    await screen.findByRole('option', { name: 'first-path-test' })
    expect(screen.queryByRole('option', { name: 'second-path-test' })).toBeNull()

    await user.click(screen.getByRole('button', { name: /load more tests/i }))

    expect(await screen.findByRole('option', { name: 'second-path-test' })).toBeInTheDocument()
  })

  test('the path page has no axe violations', async () => {
    stubPathFetch()
    const { container } = renderApp('/path')
    await screen.findByRole('group', { name: /network path/i })
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })
})
