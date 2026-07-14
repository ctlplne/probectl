// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.


import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { Path } from '../api/paths'
import { renderApp } from './renderApp'
import { jsonResponse, pathOf } from './fetchStub'

const TARGET = '203.0.113.40'

const densePath: Path = {
  target: TARGET,
  target_ip: TARGET,
  mode: 'icmp',
  max_hops: 40,
  trace_count: 12,
  destination_reached: true,
  hops: Array.from({ length: 40 }, (_, hopIndex) => {
    const ttl = hopIndex + 1
    return {
      ttl,
      nodes: Array.from({ length: 10 }, (_, branch) => {
        const ip = ttl === 40 && branch === 0 ? TARGET : `10.${ttl}.${branch}.1`
        const loss = ttl === 17 && branch === 9 ? 0.82 : branch / 100
        const rtt = ttl * 2 + branch
        return {
          ip,
          sent: 12,
          received: Math.round(12 * (1 - loss)),
          loss_ratio: loss,
          rtt_min_ms: rtt - 1,
          rtt_avg_ms: rtt,
          rtt_max_ms: rtt + 1,
          ...(ttl === 25 && branch === 9
            ? { mpls: [{ label: 16259, tc: 0, s: true, ttl: 1 }] }
            : {}),
        }
      }),
    }
  }),
  links: Array.from({ length: 39 }, (_, hopIndex) => {
    const ttl = hopIndex + 1
    return Array.from({ length: 10 }, (_, branch) => ({
      ttl,
      from: `10.${ttl}.${branch}.1`,
      to: ttl === 39 && branch === 0 ? TARGET : `10.${ttl + 1}.${branch}.1`,
    }))
  }).flat(),
}

const denseTest = {
  id: 'dense-path',
  name: 'dense-edge-path',
  type: 'icmp',
  target: TARGET,
  interval_seconds: 30,
  timeout_seconds: 3,
  params: {},
  enabled: true,
  created_at: '',
  updated_at: '',
}

function stubDensePathFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const pathname = pathOf(input)
      const method = init?.method ?? 'GET'
      if (pathname === '/v1/tests' && method === 'GET') {
        return jsonResponse({ items: [denseTest] })
      }
      if (pathname === '/v1/tests/dense-path/path' && method === 'GET') {
        return jsonResponse(densePath)
      }
      if (pathname === '/v1/tests/dense-path/path/history' && method === 'GET') {
        return jsonResponse({
          items: [
            {
              id: 'dense-latest',
              observed_at: '2026-07-14T12:30:00Z',
              path: densePath,
            },
          ],
        })
      }
      if (pathname === '/v1/incidents' || pathname === '/v1/changes') {
        return jsonResponse({ items: [] })
      }
      return jsonResponse({ error: { code: 'not_found', message: 'no route' } }, 404)
    }),
  )
}

describe('dense path visualization', () => {
  test('bounds the graph but keeps all 400 responders searchable and selectable', async () => {
    const user = userEvent.setup()
    stubDensePathFetch()
    renderApp('/path')

    const graph = await screen.findByRole('group', {
      name: new RegExp(`network path to ${TARGET}`, 'i'),
    })
    expect(within(graph).getByText(TARGET)).toBeInTheDocument()
    expect(screen.getByRole('note', { name: /path graph coverage/i })).toHaveTextContent(
      /80 representative responders of 400/i,
    )

    const table = screen.getByRole('table', {
      name: new RegExp(`path to ${TARGET} by hop`, 'i'),
    })
    const exactData = screen.getByRole('region', { name: /exact searchable hop data/i })
    expect(within(exactData).getByRole('status')).toHaveTextContent(
      /400 matching responders of 400 exact path responders/i,
    )
    expect(within(table).getByText(/showing 200 of 400/i)).toBeInTheDocument()

    const summarizedOutIP = '10.39.0.1'
    expect(within(graph).queryByText(summarizedOutIP)).toBeNull()
    expect(within(table).queryByText(summarizedOutIP)).toBeNull()

    await user.type(
      screen.getByRole('textbox', { name: /search all responders/i }),
      summarizedOutIP,
    )
    expect(within(exactData).getByRole('status')).toHaveTextContent(
      /1 matching responder of 400 exact path responders/i,
    )
    const recovered = within(table).getByText(summarizedOutIP).closest('tr')
    expect(recovered).not.toBeNull()
    await user.click(within(recovered!).getByRole('button', { name: 'Select' }))

    expect(within(graph).getByText(summarizedOutIP)).toBeInTheDocument()
    expect(
      within(graph).getByRole('button', {
        name: new RegExp(`hop 39, branch 1, ${summarizedOutIP}`, 'i'),
      }),
    ).toHaveAttribute('aria-pressed', 'true')
    expect(within(table).getByRole('button', { name: 'Selected' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
  })

  test('places triage before the graph and preserves it across both themes', async () => {
    const user = userEvent.setup()
    stubDensePathFetch()
    renderApp('/path?from=2026-07-14T12%3A00%3A00Z&to=2026-07-14T13%3A00%3A00Z')

    const triage = await screen.findByRole('region', { name: /path triage summary/i })
    const graph = screen.getByRole('group', { name: new RegExp(`network path to ${TARGET}`, 'i') })
    expect(triage.compareDocumentPosition(graph) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(within(triage).getByText('Selected path')).toBeInTheDocument()
    expect(within(triage).getByText('Scope / time')).toBeInTheDocument()
    expect(within(triage).getByText('Worst hop')).toBeInTheDocument()
    expect(within(triage).getByText('Next action')).toBeInTheDocument()
    expect(within(triage).getByText(/hop 17.*branch 10/i)).toBeInTheDocument()
    expect(within(triage).getByText(/82% loss/i)).toBeInTheDocument()
    expect(within(triage).getByRole('link', { name: /open in topology/i })).toHaveAttribute(
      'href',
      expect.stringContaining('ctx_filter=path_test%3Adense-path'),
    )

    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
    await user.click(screen.getByRole('button', { name: /switch theme \(current: dark\)/i }))
    expect(document.documentElement).toHaveAttribute('data-theme', 'aurora')
    expect(within(triage).getByText(/review evidence first/i)).toBeVisible()
  })
})
