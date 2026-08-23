// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { coldFetch, defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'
import { pivotHref } from '../routes/pivotContext'

describe('plane workspaces', () => {
  test('prioritizes the active workspace over redundant overview cards on mobile', async () => {
    renderApp('/planes/flow')

    expect(
      await screen.findByRole('list', {
        name: /per-exporter flow ingest quality receipts/i,
      }),
    ).toBeInTheDocument()
    expect(document.querySelector('[data-plane-overview]')).toBeInTheDocument()

    const css = readFileSync(resolve(process.cwd(), 'src/routes/planes.module.css'), 'utf8')
    const mobile = css.slice(css.indexOf('@media (max-width: 40rem)'))
    expect(mobile).toMatch(/\.overview\s*\{\s*order:\s*1;\s*\}/)
    expect(mobile).toMatch(/\.explain\s*\{\s*order:\s*2;\s*\}/)
  })

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
    expect(
      within(topTalkers).getByRole('button', {
        name: 'View 2 contributing exporters for 10.0.0.10 → checkout',
      }),
    ).toBeInTheDocument()
    expect(
      within(topTalkers).getByRole('button', {
        name: 'View contributing exporter for 10.0.0.20 → payments',
      }),
    ).toBeInTheDocument()
    const mobileTopTalkers = document.querySelector<HTMLElement>('[data-flow-top-mobile]')
    if (!mobileTopTalkers) throw new Error('missing mobile Flow top-talkers list')
    expect(mobileTopTalkers).toHaveAttribute('aria-label', 'Flow top talkers')
    const mobileRecords = mobileTopTalkers.querySelectorAll<HTMLElement>(
      '[data-flow-top-mobile-record]',
    )
    expect(mobileRecords).toHaveLength(2)
    for (const record of mobileRecords) {
      for (const field of ['contributor', 'bytes', 'packets', 'flows', 'observation']) {
        expect(record.querySelector(`[data-flow-top-field="${field}"]`)).toBeInTheDocument()
      }
    }
    expect(within(mobileTopTalkers).getByText('Observed by 2 exporters')).toBeInTheDocument()
    expect(within(mobileTopTalkers).getByText('Observed by 1 exporter')).toBeInTheDocument()
    expect(mobileTopTalkers.querySelectorAll('[data-flow-exporter-action]')).toHaveLength(2)

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
    const configVersions = await screen.findByRole('table', { name: /device config versions/i })
    expect(within(configVersions).getByText('changed')).toBeInTheDocument()
    expect(within(configVersions).getByText('baseline')).toBeInTheDocument()
    const mobileConfigs = document.querySelector<HTMLElement>('[data-config-versions-mobile]')
    if (!mobileConfigs) throw new Error('missing mobile config-version list')
    expect(mobileConfigs).toHaveAttribute('aria-label', 'Device config versions')
    expect(mobileConfigs.querySelectorAll('[data-config-version-mobile-record]')).toHaveLength(2)
    expect(
      within(mobileConfigs).getByRole('button', {
        name: 'Compare edge-r1 version 2 with version 1',
        hidden: true,
      }),
    ).toBeInTheDocument()
    const compareConfig = within(configVersions).getByRole('button', {
      name: 'Compare edge-r1 version 2 with version 1',
    })
    await userEvent.click(compareConfig)
    const comparison = await screen.findByRole('dialog', {
      name: 'edge-r1: version 1 → 2',
    })
    expect(
      within(comparison).getByText(
        'Compared deterministically from content redacted before archival. No device was contacted and no configuration can be changed here.',
      ),
    ).toBeInTheDocument()
    expect(within(comparison).getByText('2 removed')).toBeInTheDocument()
    expect(within(comparison).getByText('2 added')).toBeInTheDocument()
    const diffTable = within(comparison).getByRole('table', {
      name: /redacted device config line comparison/i,
    })
    expect(within(diffTable).getByText('description checkout uplink')).toBeInTheDocument()
    expect(within(diffTable).getByText('description payments uplink')).toBeInTheDocument()
    expect(within(diffTable).getByText(/community \[REDACTED\]/)).toBeInTheDocument()
    expect(diffTable.querySelectorAll('[data-config-diff-row="removed"]')).toHaveLength(2)
    expect(diffTable.querySelectorAll('[data-config-diff-row="added"]')).toHaveLength(2)
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(compareConfig).toHaveFocus())

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

  test('does not guess a config predecessor when exact authorized content is absent', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        pathOf(input) === '/v1/device/configs'
          ? Promise.resolve(
              jsonResponse({
                items: [
                  {
                    id: 'config-orphan',
                    device: 'edge-r1',
                    version: 2,
                    content: 'hostname edge-r1\n[REDACTED]',
                    content_hash: 'hash-current',
                    previous_hash: 'hash-not-returned',
                    drifted: true,
                    archived_at: '2026-06-04T12:00:00Z',
                  },
                ],
                archive_running: true,
              }),
            )
          : fallback(input, init),
      ),
    )
    renderApp('/planes/device')

    const versions = await screen.findByRole('table', { name: /device config versions/i })
    expect(within(versions).getByText('Prior redacted content unavailable')).toBeInTheDocument()
    expect(
      within(versions).queryByRole('button', { name: /compare edge-r1/i }),
    ).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  test('localizes the redacted config comparison and keeps evidence LTR in RTL', async () => {
    const spanish = renderApp('/planes/device', { locale: 'es' })
    const spanishVersions = await screen.findByRole('table', {
      name: 'Versiones de configuración de dispositivos',
    })
    await userEvent.click(
      within(spanishVersions).getByRole('button', {
        name: 'Comparar la versión 2 de edge-r1 con la versión 1',
      }),
    )
    const spanishDialog = await screen.findByRole('dialog', {
      name: 'edge-r1: versión 1 → 2',
    })
    expect(
      within(spanishDialog).getByRole('table', {
        name: 'Comparación de líneas censuradas de configuración del dispositivo',
      }),
    ).toBeInTheDocument()
    expect(within(spanishDialog).getByText('2 añadidas')).toBeInTheDocument()
    spanish.unmount()

    renderApp('/planes/device', { locale: 'ar' })
    const arabicVersions = await screen.findByRole('table', {
      name: 'إصدارات إعدادات الأجهزة',
    })
    await userEvent.click(
      within(arabicVersions).getByRole('button', {
        name: 'قارن الإصدار 2 للجهاز edge-r1 بالإصدار 1',
      }),
    )
    const arabicDialog = await screen.findByRole('dialog', {
      name: 'edge-r1: الإصدار 1 ← 2',
    })
    expect(document.documentElement.dir).toBe('rtl')
    expect(
      within(arabicDialog).getByRole('table', {
        name: 'مقارنة أسطر إعدادات الجهاز المنقحة',
      }),
    ).toBeInTheDocument()
    expect(arabicDialog.querySelector('[dir="ltr"][tabindex="0"]')).toBeInTheDocument()
  })

  test('opens an exact incident config pair outside the ordinary five-row archive', async () => {
    const fallback = defaultFetch()
    const newer = Array.from({ length: 5 }, (_, index) => ({
      id: `newer-${index}`,
      device: `other-${index}`,
      version: 1,
      content: `hostname other-${index}`,
      content_hash: `newer-hash-${index}`,
      drifted: false,
      archived_at: `2026-06-04T12:0${index}:00Z`,
    }))
    const exactPair = [
      {
        id: 'config-2',
        device: 'edge-r1',
        version: 2,
        content: 'hostname edge-r1\nno shutdown',
        content_hash: 'hash-current',
        previous_hash: 'hash-previous',
        drifted: true,
        archived_at: '2026-06-04T11:00:00Z',
      },
      {
        id: 'config-1',
        device: 'edge-r1',
        version: 1,
        content: 'hostname edge-r1\nshutdown',
        content_hash: 'hash-previous',
        drifted: false,
        archived_at: '2026-06-04T10:00:00Z',
      },
    ]
    const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) !== '/v1/device/configs') return fallback(input, init)
      const raw =
        typeof input === 'string' ? input : input instanceof URL ? input.href : String(input)
      const limit = new URL(raw, 'http://probectl.invalid').searchParams.get('limit')
      return Promise.resolve(
        jsonResponse({
          items: limit === '500' ? [...newer, ...exactPair] : newer,
          archive_running: true,
        }),
      )
    })
    vi.stubGlobal('fetch', fetcher)
    const href = pivotHref(
      '/planes/device',
      {
        incidentId: 'incident-1',
        from: '2026-06-04T10:00:00Z',
        to: '2026-06-04T13:00:00Z',
        filters: { severity: 'warning' },
        selection: { kind: 'evidence', id: 'device-config:config-2' },
        returnTo: '/incidents?incident=incident-1',
        expiresAt: '2099-01-01T00:00:00Z',
      },
      { config: 'config-2', previous_config: 'config-1' },
    )
    renderApp(href)

    const versions = await screen.findByRole('table', { name: /device config versions/i })
    expect(within(versions).queryByText('edge-r1')).not.toBeInTheDocument()
    const dialog = await screen.findByRole('dialog', { name: 'edge-r1: version 1 → 2' })
    expect(within(dialog).getByText('no shutdown')).toBeInTheDocument()
    expect(
      fetcher.mock.calls
        .filter(([input]) => pathOf(input) === '/v1/device/configs')
        .map(([input]) => {
          const raw =
            typeof input === 'string' ? input : input instanceof URL ? input.href : String(input)
          return new URL(raw, 'http://probectl.invalid').searchParams.get('limit')
        }),
    ).toEqual(expect.arrayContaining(['5', '500']))
  })

  test('fails closed when a config pivot does not name the exact predecessor', async () => {
    const href = pivotHref(
      '/planes/device',
      {
        incidentId: 'incident-1',
        from: '2026-06-04T10:00:00Z',
        to: '2026-06-04T13:00:00Z',
        filters: { severity: 'warning' },
        selection: { kind: 'evidence', id: 'device-config:config-2' },
        returnTo: '/incidents?incident=incident-1',
        expiresAt: '2099-01-01T00:00:00Z',
      },
      { config: 'config-2', previous_config: 'config-does-not-match' },
    )
    renderApp(href)

    await screen.findByRole('table', { name: /device config versions/i })
    await waitFor(() => {
      expect(screen.queryByText('Loading config archive...')).not.toBeInTheDocument()
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
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
    const spanishMobile = document.querySelector<HTMLElement>('[data-flow-top-mobile]')
    if (!spanishMobile) throw new Error('missing Spanish mobile Flow top-talkers list')
    expect(spanishMobile).toHaveAttribute('aria-label', 'Principales conversadores de flujo')
    expect(within(spanishMobile).getByText('Observado por 2 exportadores')).toBeInTheDocument()
    expect(within(spanishMobile).getByText('Observado por 1 exportador')).toBeInTheDocument()
    expect(
      within(spanishTable).getByRole('button', {
        name: 'Ver los 2 exportadores contribuyentes de 10.0.0.10 → checkout',
      }),
    ).toBeInTheDocument()
    spanish.unmount()

    renderApp('/planes/flow', { locale: 'ar' })
    const arabicTable = await screen.findByRole('table', {
      name: 'أعلى متحدثي التدفق',
    })
    expect(within(arabicTable).getByText('شوهد بواسطة 2 مُصدّرين')).toBeInTheDocument()
    expect(within(arabicTable).getByText('شوهد بواسطة مُصدّر واحد')).toBeInTheDocument()
    const arabicMobile = document.querySelector<HTMLElement>('[data-flow-top-mobile]')
    if (!arabicMobile) throw new Error('missing Arabic mobile Flow top-talkers list')
    expect(arabicMobile).toHaveAttribute('aria-label', 'أعلى متحدثي التدفق')
    expect(within(arabicMobile).getByText('شوهد بواسطة 2 مُصدّرين')).toBeInTheDocument()
    expect(within(arabicMobile).getByText('شوهد بواسطة مُصدّر واحد')).toBeInTheDocument()
    expect(
      within(arabicTable).getByRole('button', {
        name: 'عرض 2 مُصدّرين مساهمين في 10.0.0.10 → checkout',
      }),
    ).toBeInTheDocument()
  })

  test('renders missing exporter provenance as unavailable instead of one observer', async () => {
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === '/v1/flows/top') {
        return Promise.resolve(
          jsonResponse({
            items: [
              {
                key: '203.0.113.8',
                bytes: 100,
                packets: 1,
                flows: 1,
                exporter_count: 0,
              },
            ],
            series: [],
            effective_limit: 10,
            series_limit: 6,
            window: '1h',
          }),
        )
      }
      return fallback(input, init)
    })

    renderApp('/planes/flow')
    const table = await screen.findByRole('table', { name: /flow top talkers/i })
    expect(within(table).getByText('Exporter identity unavailable')).toBeInTheDocument()
    expect(within(table).queryByText(/observed by 0 exporters/i)).not.toBeInTheDocument()
    const mobile = document.querySelector<HTMLElement>('[data-flow-top-mobile]')
    if (!mobile) throw new Error('missing mobile Flow top-talkers list')
    expect(within(mobile).getByText('Exporter identity unavailable')).toBeInTheDocument()
    expect(within(mobile).queryByText(/observed by 0 exporters/i)).not.toBeInTheDocument()
    expect(document.querySelector('[data-flow-exporter-action]')).not.toBeInTheDocument()
  })

  test('pivots observation evidence directly to the existing exporter grouping', async () => {
    const calls: string[] = []
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(input))
      return fallback(input, init)
    })
    const user = userEvent.setup()
    renderApp('/planes/flow')

    const table = await screen.findByRole('table', { name: /flow top talkers/i })
    const inspect = within(table).getByRole('button', {
      name: /view 2 contributing exporters for 10\.0\.0\.10.*checkout/i,
    })
    inspect.focus()
    expect(inspect).toHaveFocus()
    await user.keyboard('{Enter}')

    expect(screen.getByLabelText('Group')).toHaveValue('exporter')
    expect(
      await screen.findByRole('button', { name: /remove src filter 10\.0\.0\.10/i }),
    ).toBeInTheDocument()
    await waitFor(() => {
      expect(
        calls.some(
          (call) => call.includes('by=exporter') && call.includes('filter=src%3A10.0.0.10'),
        ),
      ).toBe(true)
    })
    await waitFor(() => {
      const updatedTable = screen.getByRole('table', { name: /flow top talkers/i })
      expect(within(updatedTable).getByText('edge-r1')).toBeInTheDocument()
      expect(within(updatedTable).getByText('edge-r2')).toBeInTheDocument()
      expect(within(updatedTable).queryByText('10.0.0.10')).not.toBeInTheDocument()
      expect(within(updatedTable).queryByText('10.0.0.20')).not.toBeInTheDocument()
    })
    expect(
      screen.queryByRole('button', { name: /view .*contributing exporter/i }),
    ).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /clear filters/i }))
    expect(screen.getByLabelText('Group')).toHaveValue('exporter')
    await waitFor(() => {
      const updatedTable = screen.getByRole('table', { name: /flow top talkers/i })
      expect(within(updatedTable).getByText('edge-r1')).toBeInTheDocument()
      expect(within(updatedTable).getByText('edge-r2')).toBeInTheDocument()
    })

    await user.selectOptions(screen.getByLabelText('Group'), 'src')
    await waitFor(() => {
      const updatedTable = screen.getByRole('table', { name: /flow top talkers/i })
      expect(within(updatedTable).getByText('10.0.0.10')).toBeInTheDocument()
      expect(within(updatedTable).getByText('10.0.0.20')).toBeInTheDocument()
      expect(within(updatedTable).queryByText('edge-r2')).not.toBeInTheDocument()
    })
  })

  test('fixture Flow responses echo filters and keep exporter totals coherent', async () => {
    const response = await defaultFetch()(
      '/v1/flows/top?by=exporter&window=1h&bucket=3m&limit=8&filter=src%3A10.0.0.10',
    )
    const body = (await response.json()) as {
      items: Array<{
        key: string
        bytes: number
        packets: number
        flows: number
        exporter_count: number
      }>
      series: Array<{ key: string; bytes: number; packets: number; flows: number }>
      filters: Array<{ field: string; value: string }>
      window: string
      bucket: string
    }

    expect(body.filters).toEqual([{ field: 'src', value: '10.0.0.10' }])
    expect(body.window).toBe('1h')
    expect(body.bucket).toBe('3m')
    expect(body.items).toEqual([
      {
        key: 'edge-r1',
        bytes: 314_572_800,
        packets: 70_000,
        flows: 24,
        exporter_count: 1,
      },
      {
        key: 'edge-r2',
        bytes: 209_715_200,
        packets: 50_000,
        flows: 18,
        exporter_count: 1,
      },
    ])
    expect(
      body.series.reduce(
        (totals, row) => ({
          bytes: totals.bytes + row.bytes,
          packets: totals.packets + row.packets,
          flows: totals.flows + row.flows,
        }),
        { bytes: 0, packets: 0, flows: 0 },
      ),
    ).toEqual({ bytes: 524_288_000, packets: 120_000, flows: 42 })

    const cold = await coldFetch()('/v1/flows/top?by=exporter&filter=src%3A10.0.0.10')
    await expect(cold.json()).resolves.toEqual({ items: [] })
  })

  test('uses exact grouping-key filters for fallback AS-name and port contributor pivots', async () => {
    const calls: string[] = []
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(input))
      return fallback(input, init)
    })
    const user = userEvent.setup()
    renderApp('/planes/flow')

    const pivot = async (group: 'as_name' | 'port', exactField: string, value: string) => {
      await user.selectOptions(await screen.findByLabelText('Group'), group)
      const table = await screen.findByRole('table', { name: /flow top talkers/i })
      await user.click(
        within(table).getByRole('button', {
          name: new RegExp(`view 2 contributing exporters for ${value}`, 'i'),
        }),
      )

      expect(screen.getByLabelText('Group')).toHaveValue('exporter')
      expect(
        await screen.findByRole('button', {
          name: new RegExp(`remove ${exactField} filter ${value}`, 'i'),
        }),
      ).toBeInTheDocument()
      await waitFor(() => {
        expect(
          calls.some((call) => {
            const url = new URL(call, 'http://fixture.probectl.test')
            return (
              url.searchParams.get('by') === 'exporter' &&
              url.searchParams.getAll('filter').includes(`${exactField}:${value}`)
            )
          }),
        ).toBe(true)
      })
      expect(
        calls.some((call) => {
          const url = new URL(call, 'http://fixture.probectl.test')
          return (
            url.searchParams.get('by') === 'exporter' &&
            url.searchParams.getAll('filter').includes(`${group}:${value}`)
          )
        }),
      ).toBe(false)
      await user.click(screen.getByRole('button', { name: /clear filters/i }))
    }

    await pivot('as_name', 'group_as_name', 'Acme Payments')
    await pivot('port', 'group_port', '443')
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
