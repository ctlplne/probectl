// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf, sampleExplorerTemplates } from './fetchStub'

describe('structured and natural-language Explorer', () => {
  test('synchronizes the grammar and returns exact rows, suggestions, saved views, and safe pivots', async () => {
    const user = userEvent.setup()
    const base = defaultFetch()
    const requests: { path: string; method: string; body?: unknown }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = pathOf(input)
        const method = init?.method ?? 'GET'
        requests.push({ path, method, body: init?.body })
        if (path === '/v1/inventory/views' && method === 'GET') return jsonResponse({ items: [] })
        if (path === '/v1/inventory/views' && method === 'POST') {
          const body = JSON.parse(String(init?.body)) as Record<string, unknown>
          return jsonResponse(
            {
              id: 'view-explorer',
              tenant_id: 'current',
              owner_id: 'operator',
              ...body,
              created_at: '2026-07-14T12:00:00Z',
              updated_at: '2026-07-14T12:00:00Z',
            },
            201,
          )
        }
        return base(input, init)
      }),
    )

    renderApp('/explore?template=service-dependencies')
    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()
    const workspace = screen.getByRole('heading', { name: 'Query builder' }).closest('section')
    const recipes = screen.getByRole('group', { name: 'Canonical Explorer questions' })
    const builder = document.querySelector<HTMLElement>('[data-explorer-builder]')
    if (!workspace || !builder) throw new Error('missing Explorer workspace markers')
    expect(workspace).toContainElement(recipes)
    expect(workspace).toContainElement(builder)
    expect(recipes.compareDocumentPosition(builder) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0)
    for (const template of sampleExplorerTemplates) {
      expect(
        within(recipes).getByRole('button', { name: String(template.question) }),
      ).toBeInTheDocument()
    }
    expect(screen.getByLabelText('Ask in natural language')).toHaveValue(
      'Show service dependencies',
    )
    expect(screen.getByLabelText('Source / plane')).toHaveValue('topology')
    expect(screen.getByLabelText('Dimensions')).toHaveValue('from, to, kind')
    expect(screen.getByLabelText('Group by')).toHaveValue('kind')
    expect(screen.getByLabelText('Measures')).toHaveValue('edges')
    expect(screen.getByLabelText('Visualization')).toHaveValue('topology')
    expect(screen.getByLabelText('Readable query preview')).toHaveTextContent(
      /FROM topology.*GROUP BY kind.*MEASURE edges.*VIEW topology/,
    )

    await user.click(screen.getByRole('button', { name: 'Run query' }))
    const table = await screen.findByRole('table', { name: 'Explorer exact-value results' })
    expect(within(table).getByText('from-value')).toBeInTheDocument()
    expect(within(table).getByText('to-value')).toBeInTheDocument()
    expect(within(table).getByText('kind-value')).toBeInTheDocument()
    expect(
      screen.getByRole('img', { name: /topology visualization of authorized Explorer results/i }),
    ).toBeInTheDocument()
    expect(document.querySelector('datalist option[value="from-value"]')).not.toBeNull()

    const stable = screen.getByRole('link', { name: 'Stable view link' }).getAttribute('href') ?? ''
    const pivot = screen.getByRole('link', { name: 'Open evidence' }).getAttribute('href') ?? ''
    expect(stable).toMatch(/^\/explore\?template=service-dependencies/)
    expect(pivot).toMatch(/^\/topology\?ctx_v=1/)
    expect(`${stable}${pivot}`).not.toMatch(/tenant|secret|token/i)

    await user.type(screen.getByLabelText('View name'), 'Service graph')
    await user.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() =>
      expect(
        requests.some(({ path, method, body }) => {
          if (path !== '/v1/inventory/views' || method !== 'POST') return false
          const value = JSON.parse(String(body)) as { surface: string; tenant_id?: string }
          return value.surface === 'explorer' && value.tenant_id === undefined
        }),
      ).toBe(true),
    )

    await user.clear(screen.getByLabelText('Dimensions'))
    await user.type(screen.getByLabelText('Dimensions'), 'from, to')
    expect(screen.getByLabelText('Ask in natural language')).toHaveValue(
      'Show edges by kind from topology',
    )
  })
})
