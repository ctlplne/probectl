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
    const execution = screen.getByText('Query execution receipt')
    expect(execution).toBeInTheDocument()
    await user.click(execution)
    expect(screen.getByText('Authenticated tenant enforced')).toBeInTheDocument()
    expect(
      screen.getByText(/1 returned \/ 100 maximum from 1 authorized source rows/),
    ).toBeInTheDocument()
    expect(screen.getByText(/never contains SQL/i)).toBeInTheDocument()

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

  test('compares two explicit windows with stable links and honest delta states', async () => {
    const user = userEvent.setup()
    const base = defaultFetch()
    const requests: unknown[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) === '/v1/explorer/compare' && init?.method === 'POST')
          requests.push(JSON.parse(String(init.body)))
        return base(input, init)
      }),
    )

    renderApp(
      '/explore?template=service-dependencies&from=2026-07-14T11%3A00%3A00Z&to=2026-07-14T12%3A00%3A00Z',
    )
    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()
    const compare = screen.getByRole('checkbox', { name: 'Compare with another period' })
    expect(compare).toBeEnabled()
    await user.click(compare)
    expect(screen.getByLabelText('Previous from')).toBeInTheDocument()
    expect(screen.getByLabelText('Previous to')).toBeInTheDocument()
    expect(screen.getByLabelText('Readable query preview')).toHaveTextContent(
      /Current query preview.*Previous query preview/,
    )

    const stable = screen.getByRole('link', { name: 'Stable view link' })
    expect(stable.getAttribute('href')).toMatch(/compare=1&previous_from=.*&previous_to=/)
    await user.click(screen.getByRole('button', { name: 'Compare periods' }))
    const table = await screen.findByRole('table', {
      name: 'Explorer period comparison results',
    })
    expect(within(table).getByText('kind-value')).toBeInTheDocument()
    expect(within(table).getByText('edges')).toBeInTheDocument()
    expect(within(table).getByText('100%')).toBeInTheDocument()
    expect(screen.getByText('explorer-comparison/v1')).toBeInTheDocument()
    const execution = screen.getByText('Comparison execution receipt')
    await user.click(execution)
    expect(screen.getAllByText('Authenticated tenant enforced')).toHaveLength(2)
    expect(screen.getByText(/1 aligned rows \/ 100 maximum/)).toBeInTheDocument()
    expect(screen.getByText(/explorer-comparison-execution\/v1/)).toBeInTheDocument()
    expect(
      screen.getByRole('img', {
        name: /Current and previous values for 1 aligned Explorer measure/,
      }),
    ).toBeInTheDocument()

    expect(requests).toHaveLength(1)
    const request = requests[0] as {
      query: { tenant_id?: string; from: string; to: string }
      previous_from: string
      previous_to: string
      tenant_id?: string
    }
    expect(request.tenant_id).toBeUndefined()
    expect(request.query.tenant_id).toBeUndefined()
    expect(request.query.from).toBe('2026-07-14T11:00:00.000Z')
    expect(request.query.to).toBe('2026-07-14T12:00:00.000Z')
    expect(request.previous_from).toBe('2026-07-14T10:00:00.000Z')
    expect(request.previous_to).toBe('2026-07-14T11:00:00.000Z')

    await user.selectOptions(screen.getByLabelText('Source / plane'), 'path')
    expect(compare).not.toBeChecked()
    expect(compare).toBeDisabled()
    expect(screen.getByText(/current snapshot/i)).toBeInTheDocument()
  })

  test('keeps empty, partial, and failed comparisons explicit', async () => {
    const user = userEvent.setup()
    const base = defaultFetch()
    let attempts = 0
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) !== '/v1/explorer/compare') return base(input, init)
        attempts++
        if (attempts > 1)
          return jsonResponse(
            { error: { code: 'unavailable', message: 'previous window unavailable' } },
            503,
          )
        const request = JSON.parse(String(init?.body)) as {
          query: Record<string, unknown>
          previous_from: string
          previous_to: string
        }
        return jsonResponse({
          contract_version: 'explorer-comparison/v1',
          current: request.query,
          previous: {
            ...request.query,
            from: request.previous_from,
            to: request.previous_to,
          },
          current_preview: 'current empty window',
          previous_preview: 'previous empty window',
          groupings: ['kind'],
          rows: [],
          suggestions: {},
          evidence_path: '/topology',
          state: 'empty',
          current_truncated: true,
          previous_truncated: false,
          rows_truncated: false,
          execution: {
            contract_version: 'explorer-comparison-execution/v1',
            tenant_scoped: true,
            current: {
              contract_version: 'explorer-execution/v1',
              recipe: 'service-dependencies',
              source: 'topology',
              tenant_scoped: true,
              bounds: {
                from: String(request.query.from),
                to: String(request.query.to),
                row_limit: 100,
              },
              projection: {
                dimensions: ['from', 'to', 'kind'],
                groupings: ['kind'],
                measures: ['edges'],
              },
              filter_keys: [],
              source_rows: 0,
              returned_rows: 0,
              truncated: true,
              truncation_reason: 'row_limit',
              timings: { source_ms: 1, shaping_ms: 0, total_ms: 1 },
            },
            previous: {
              contract_version: 'explorer-execution/v1',
              recipe: 'service-dependencies',
              source: 'topology',
              tenant_scoped: true,
              bounds: { from: request.previous_from, to: request.previous_to, row_limit: 100 },
              projection: {
                dimensions: ['from', 'to', 'kind'],
                groupings: ['kind'],
                measures: ['edges'],
              },
              filter_keys: [],
              source_rows: 0,
              returned_rows: 0,
              truncated: false,
              truncation_reason: 'none',
              timings: { source_ms: 1, shaping_ms: 0, total_ms: 1 },
            },
            alignment: {
              row_limit: 100,
              returned_rows: 0,
              truncated: false,
              truncation_reason: 'none',
              elapsed_ms: 0,
            },
            total_ms: 2,
          },
        })
      }),
    )

    renderApp('/explore?template=service-dependencies')
    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: 'Compare with another period' }))
    await user.click(screen.getByRole('button', { name: 'Compare periods' }))
    expect(await screen.findByText(/Neither window has authorized rows/i)).toBeInTheDocument()
    expect(screen.getByText(/comparison is partial/i)).toBeInTheDocument()
    expect(screen.getByText('Comparison execution receipt')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Compare periods' }))
    expect(
      await screen.findByText(/comparison failed inside the authorized tenant scope/i),
    ).toBeInTheDocument()
  })

  test('fails closed on an older schema that does not advertise comparison', async () => {
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) === '/v1/explorer/schema')
          return jsonResponse({
            templates: sampleExplorerTemplates,
            visualizations: ['table', 'bar', 'line', 'timeline', 'topology'],
            max_rows: 500,
          })
        return base(input, init)
      }),
    )

    renderApp('/explore?template=service-dependencies')
    expect(await screen.findByRole('heading', { name: 'Explorer' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Compare with another period' })).toBeDisabled()
    expect(screen.getByText(/current snapshot/i)).toBeInTheDocument()
  })
})
