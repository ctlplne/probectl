// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { coldFetch, defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

describe('plane workspaces', () => {
  test('renders native BGP, flow, device, and eBPF tabs', async () => {
    renderApp('/planes')

    expect(await screen.findByRole('heading', { name: /planes/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'BGP' })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByRole('table', { name: /bgp routing edges/i })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Flow' }))
    const flowQuality = await screen.findByRole('list', {
      name: /per-exporter flow ingest quality receipts/i,
    })
    expect(within(flowQuality).getByText('2001:db8:100:200::1234')).toBeInTheDocument()
    expect(within(flowQuality).getByText('Healthy')).toBeInTheDocument()
    expect(within(flowQuality).getByText('Degraded')).toBeInTheDocument()
    expect(
      within(flowQuality).getByText('Verify template export on this configured exporter.'),
    ).toBeInTheDocument()
    expect(
      within(flowQuality)
        .getByText('Continue monitoring; no change is recommended.')
        .closest('[data-action-tone]'),
    ).toHaveAttribute('data-action-tone', 'healthy')
    expect(
      within(flowQuality)
        .getByText('Verify template export on this configured exporter.')
        .closest('[data-action-tone]'),
    ).toHaveAttribute('data-action-tone', 'degraded')
    expect(within(flowQuality).queryByRole('table')).not.toBeInTheDocument()
    const topTalkers = await screen.findByRole('table', { name: /flow top talkers/i })
    expect(within(topTalkers).getByText('10.0.0.10')).toBeInTheDocument()
    expect(within(topTalkers).getByText('Observed by 2 exporters')).toBeInTheDocument()
    expect(within(topTalkers).getByText('Observed by 1 exporter')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Device' }))
    const deviceNodes = await screen.findByRole('table', { name: /topology device nodes/i })
    expect(deviceNodes).toBeInTheDocument()
    expect(within(deviceNodes).getByText('edge-r1')).toBeInTheDocument()
    const physicalNeighbors = await screen.findByRole('table', {
      name: /lldp and cdp physical adjacency evidence/i,
    })
    expect(within(physicalNeighbors).getByText('leaf-1')).toBeInTheDocument()
    expect(within(physicalNeighbors).getByText('LLDP')).toBeInTheDocument()
    expect(within(physicalNeighbors).getByText('95%')).toBeInTheDocument()
    const collectionOutcomes = await screen.findByRole('list', {
      name: /per-target device collection outcome receipts/i,
    })
    expect(within(collectionOutcomes).getAllByText('edge-r1.internal')).toHaveLength(2)
    expect(within(collectionOutcomes).getByText('Failed')).toBeInTheDocument()
    expect(within(collectionOutcomes).getByText('Healthy, empty')).toBeInTheDocument()
    expect(within(collectionOutcomes).getByText('The protocol read failed.')).toBeInTheDocument()
    expect(
      within(collectionOutcomes).getByText('Verify local access to the configured target.'),
    ).toBeInTheDocument()
    expect(within(collectionOutcomes).queryByRole('table')).not.toBeInTheDocument()
    const deviceCoverage = screen
      .getByRole('heading', { name: /device coverage/i })
      .closest('section')
    if (!deviceCoverage) throw new Error('missing device coverage card')
    expect(within(deviceCoverage).getByText('Device nodes').nextElementSibling).toHaveTextContent(
      /^2$/,
    )
    expect(within(deviceCoverage).getByText('Physical links').nextElementSibling).toHaveTextContent(
      /^1$/,
    )
    expect(await screen.findByRole('table', { name: /device syslog events/i })).toBeInTheDocument()
    expect(screen.getByText('Interface Gi0/1 down')).toBeInTheDocument()
    expect(
      await screen.findByRole('table', { name: /device config versions/i }),
    ).toBeInTheDocument()
    expect(screen.getByText('changed')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'eBPF' }))
    const ebpf = await screen.findByRole('table', { name: /ebpf service edges/i })
    expect(within(ebpf).getByText('checkout')).toBeInTheDocument()
  })

  test('cold device evidence and physical-link coverage remain honestly empty', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/planes/device')

    expect(await screen.findByText('No physical neighbors observed')).toBeInTheDocument()
    expect(await screen.findByText('No collection receipts yet')).toBeInTheDocument()
    expect(screen.queryByText('leaf-1')).not.toBeInTheDocument()
    const deviceCoverage = screen
      .getByRole('heading', { name: /device coverage/i })
      .closest('section')
    if (!deviceCoverage) throw new Error('missing device coverage card')
    expect(within(deviceCoverage).getByText('Device nodes').nextElementSibling).toHaveTextContent(
      /^0$/,
    )
    expect(within(deviceCoverage).getByText('Physical links').nextElementSibling).toHaveTextContent(
      /^0$/,
    )
  })

  test('cold flow ingest remains honestly empty', async () => {
    vi.stubGlobal('fetch', coldFetch())
    renderApp('/planes/flow')

    expect(await screen.findByText('No flow ingest receipts yet')).toBeInTheDocument()
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
  })

  test('Spanish physical-neighbor copy is natural across populated, unavailable, and empty states', async () => {
    const populated = renderApp('/planes/device', { locale: 'es' })

    expect(await screen.findByRole('heading', { name: 'Vecinos físicos' })).toBeInTheDocument()
    expect(
      screen.getByText(/dispositivos configurados explícitamente.*nunca realiza un escaneo/i),
    ).toBeInTheDocument()
    expect(
      await screen.findByRole('table', {
        name: 'Evidencia de adyacencia física LLDP y CDP',
      }),
    ).toBeInTheDocument()
    expect(screen.getByText(/Las instantáneas conservan evidencia obsoleta/i)).toBeInTheDocument()
    populated.unmount()

    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === '/v1/device/neighbors') {
        return Promise.resolve(
          jsonResponse({
            contract_version: 'probectl.device-neighbors/v1',
            items: [],
            collection_running: false,
            effective_limit: 100,
            truncated: false,
            as_of: '2026-06-04T12:00:00Z',
            retention: {
              max_per_device: 256,
              max_per_tenant: 16384,
              stale_retention_hours: 24,
            },
          }),
        )
      }
      return fallback(input, init)
    })
    const unavailable = renderApp('/planes/device', { locale: 'es' })

    expect(await screen.findByText('Colección de vecinos no disponible')).toBeInTheDocument()
    expect(screen.getByText(/almacén LLDP\/CDP.*estado de la topología/i)).toBeInTheDocument()
    unavailable.unmount()

    vi.stubGlobal('fetch', coldFetch())
    renderApp('/planes/device', { locale: 'es' })

    expect(await screen.findByText('No se observaron vecinos físicos')).toBeInTheDocument()
    expect(screen.getByText(/vacío explícito/i)).toBeInTheDocument()
  })

  test('renders BGP AS-path arcs with a table fallback', async () => {
    renderApp('/planes/bgp')

    expect(
      await screen.findByRole('img', { name: /bgp as-path arc view with 1 of 1/i }),
    ).toBeInTheDocument()
    expect(screen.getByText(/showing 1 of 1 routing relationships/i)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: /bgp routing edges/i })
    expect(within(table).getByText('AS64500')).toBeInTheDocument()
    expect(within(table).getByText('203.0.113.0/24')).toBeInTheDocument()
  })

  test('renders flow Sankey lanes with a table fallback', async () => {
    renderApp('/planes/flow')

    expect(
      await screen.findByRole('table', {
        name: /flow bytes over time for the highest-ranked contributors/i,
      }),
    ).toBeInTheDocument()
    expect(
      await screen.findByRole('img', { name: /flow sankey view with 2 of 2/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('region', { name: /scrollable flow sankey visualization/i }),
    ).toHaveAttribute('tabindex', '0')
    expect(screen.getByText(/showing 2 of 2 contributors/i)).toBeInTheDocument()
    const table = screen.getByRole('table', { name: /flow top talkers/i })
    expect(within(table).getByText('10.0.0.10')).toBeInTheDocument()
    expect(within(table).getByText('checkout')).toBeInTheDocument()
    expect(within(table).getByText('Observed by 2 exporters')).toBeInTheDocument()
  })

  test('localizes flow observation multiplicity without implying deduplication', async () => {
    const spanish = renderApp('/planes/flow', { locale: 'es' })
    const spanishTable = await screen.findByRole('table', {
      name: 'Principales conversadores de flujo',
    })
    expect(within(spanishTable).getByText('Observado por 2 exportadores')).toBeInTheDocument()
    expect(within(spanishTable).getByText('Observado por 1 exportador')).toBeInTheDocument()
    expect(within(spanishTable).queryByText(/deduplic/i)).not.toBeInTheDocument()
    spanish.unmount()

    renderApp('/planes/flow', { locale: 'ar' })
    const arabicTable = await screen.findByRole('table', {
      name: 'أعلى متحدثي التدفق',
    })
    expect(within(arabicTable).getByText('شوهد بواسطة 2 مُصدّرين')).toBeInTheDocument()
    expect(within(arabicTable).getByText('شوهد بواسطة مُصدّر واحد')).toBeInTheDocument()
  })

  test('pivots facets and narrows flows with removable filter chips', async () => {
    const calls: string[] = []
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(input))
      return fallback(input, init)
    })
    const user = userEvent.setup()
    renderApp('/planes/flow')

    const table = await screen.findByRole('table', { name: /flow top talkers/i })
    const narrow = within(table).getByRole('button', {
      name: /narrow flows to 10\.0\.0\.10.*checkout/i,
    })
    narrow.focus()
    expect(narrow).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(
      await screen.findByRole('button', { name: /remove src filter 10\.0\.0\.10/i }),
    ).toBeInTheDocument()
    expect(calls.some((call) => call.includes('filter=src%3A10.0.0.10'))).toBe(true)

    await user.selectOptions(screen.getByLabelText('Group'), 'protocol')
    expect(calls.some((call) => call.includes('by=protocol'))).toBe(true)

    await user.click(screen.getByRole('button', { name: /clear filters/i }))
    expect(screen.queryByRole('button', { name: /remove src filter/i })).not.toBeInTheDocument()
  })

  test('discloses visualization cardinality guardrails', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      if (path === '/v1/topology') {
        const ases = Array.from({ length: 20 }, (_, i) => ({
          id: `as:${64500 + i}`,
          kind: 'as',
          label: `AS${64500 + i}`,
        }))
        const prefixes = Array.from({ length: 20 }, (_, i) => ({
          id: `prefix:203.0.${i}.0/24`,
          kind: 'prefix',
          label: `203.0.${i}.0/24`,
        }))
        return Promise.resolve(
          jsonResponse({
            topology_running: true,
            nodes: [...ases, ...prefixes],
            edges: ases.map((asNode, i) => ({
              from: asNode.id,
              to: prefixes[i].id,
              kind: 'routing',
            })),
            coverage: { path_edges: 0, flow_edges: 0, routing_edges: 20, device_edges: 0 },
          }),
        )
      }
      if (path === '/v1/flows/top') {
        return Promise.resolve(
          jsonResponse({
            items: Array.from({ length: 12 }, (_, i) => ({
              key: `10.0.0.${i + 1}`,
              detail: `service-${i + 1}`,
              bytes: 100_000 * (12 - i),
              packets: 10_000 - i,
              flows: 20 - i,
            })),
            effective_limit: 12,
            window: '1h',
          }),
        )
      }
      return fallback(input, init)
    })

    renderApp('/planes/bgp')

    expect(await screen.findByText(/showing 16 of 20 routing relationships/i)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /bgp routing edges/i })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('tab', { name: 'Flow' }))
    expect(await screen.findByText(/showing 8 of 12 contributors/i)).toBeInTheDocument()
    expect(screen.getByRole('table', { name: /flow top talkers/i })).toBeInTheDocument()
  })
})
