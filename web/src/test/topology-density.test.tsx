// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { jsonResponse } from './fetchStub'

const topology = {
  topology_running: true,
  at: '2026-06-04T12:00:00Z',
  nodes: [
    { id: 'service:api', kind: 'service', label: 'api', site: 'core', tags: ['prod'] },
    { id: 'service:db', kind: 'service', label: 'db', site: 'core', tags: ['prod'] },
  ],
  edges: [{ from: 'service:api', to: 'service:db', kind: 'flow' }],
  coverage: { path_edges: 0, flow_edges: 1, routing_edges: 0, device_edges: 0, notes: [] },
}

describe('Topology visual hierarchy', () => {
  test('keeps the graph primary while history, filters, and saved views remain reachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).includes('/v1/topology')
          ? jsonResponse(topology)
          : jsonResponse({ error: { code: 'not_found', message: 'not found' } }, 404),
      ),
    )
    renderApp('/topology')

    const graph = await screen.findByRole('group', { name: /topology graph/i })
    const graphCard = graph.closest('[data-topology-graph]')
    const controlsLabel = screen.getByText('History & filters')
    const controls = controlsLabel.closest('details')
    const identityConflicts = document.querySelector('[data-identity-conflicts]')
    if (!graphCard || !controls || !identityConflicts)
      throw new Error('missing topology hierarchy markers')

    expect(controls).not.toHaveAttribute('open')
    const summary = controlsLabel.closest('summary')
    if (!summary) throw new Error('missing topology control summary')
    expect(within(summary).getByText('Live topology')).toBeInTheDocument()
    expect(within(summary).getByText(/2 of 2 nodes · no active filters/i)).toBeInTheDocument()
    expect(controls.compareDocumentPosition(graphCard) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(
      0,
    )
    expect(
      graphCard.compareDocumentPosition(identityConflicts) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0)

    await userEvent.click(controlsLabel)
    expect(controls).toHaveAttribute('open')
    expect(within(controls).getByLabelText('As of')).toBeInTheDocument()
    expect(within(controls).getByLabelText('Search topology')).toBeInTheDocument()
    expect(within(controls).getByLabelText('Kind')).toBeInTheDocument()
    expect(within(controls).getByLabelText('Site')).toBeInTheDocument()
    expect(within(controls).getByLabelText('Tag')).toBeInTheDocument()
    expect(within(controls).getByText('Saved views')).toBeInTheDocument()
  })
})
