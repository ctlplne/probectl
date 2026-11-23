// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { fireEvent, screen, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse } from './fetchStub'
import { renderApp } from './renderApp'

const context = '00000000-0000-4000-8000-000000000156'
const device = '00000000-0000-4000-8000-000000000257'
const observed = '2026-11-21T12:34:56Z'
const oldPoll = '00000000-0000-4000-8000-000000000301'
const newPoll = '00000000-0000-4000-8000-000000000302'
const exact = {
  context_id: context,
  device_entity_id: device,
  agent_id: 'inventory-collector',
  source_ref: '192.0.2.1',
}
const lifecycle = {
  source_date: '2026-11-21',
  notice: {
    manufacturer: 'Example Networks',
    model: 'Example chassis',
    end_of_support: '2027-01-30',
    notice_published_at: '2026-04-01',
    notice_url: 'https://equipment.example.invalid/notice',
  },
}
const item = {
  index: 1,
  class: 3,
  parent: 0,
  model: 'Example chassis',
  firmware: '8.1.4',
  serial: 'original-poll-serial',
  references: {
    lifecycle,
    vulnerability_coverage: 'available',
    vulnerabilities: [
      {
        id: 'CVE-2026-99101',
        version_field: 'firmware',
        observed_version: '8.1.4',
        nvd_source: 'https://nvd.nist.gov/vuln/detail/CVE-2026-99101',
        nvd_source_date: observed,
        last_modified_at: observed,
        published_at: observed,
        kev_source: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        kev_source_date: observed,
        kev_added_at: '2026-11-21',
      },
    ],
  },
}

test('continues the original observation and clears the old snapshot when a poll replaces it', async () => {
  const fallback = defaultFetch()
  const reads: Record<string, string>[] = []
  let replacement = false
  let sourceUnavailable = true
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new URL(String(input), 'https://probectl.test')
    switch (request.pathname) {
      case '/v1/entity-contexts':
        return jsonResponse({
          items: [{ context_id: context, site_label: 'Edge', vrf_label: 'Blue' }],
        })
      case '/v1/entities':
        expect(request.searchParams.get('context_id')).toEqual(context)
        return jsonResponse({ items: [{ id: device, label: 'Edge chassis', kind: 'device' }] })
      case `/v1/entities/${device}/evidence`:
        if (sourceUnavailable) return jsonResponse({ error: { message: 'Unavailable' } }, 503)
        return jsonResponse({
          items: [
            {
              id: oldPoll,
              current: true,
              source_ref: 'snmp:physical-inventory',
              source_key: {
                source_kind: 'device_target',
                agent_id: exact.agent_id,
                source_ref: exact.source_ref,
              },
            },
          ],
        })
      case '/v1/device/physical-inventory':
        reads.push(Object.fromEntries(request.searchParams))
        if (request.searchParams.has('after_index')) {
          replacement = true
          return jsonResponse({ error: { code: 'conflict', message: 'New poll' } }, 409)
        }
        if (replacement)
          return jsonResponse({
            observation_id: newPoll,
            observed_at: observed,
            available: true,
            methodology: 'snmp:physical-inventory',
            items: [
              {
                ...item,
                serial: 'latest-poll-serial',
                references: { vulnerability_coverage: 'unavailable' },
              },
            ],
          })
        return jsonResponse({
          observation_id: oldPoll,
          observed_at: observed,
          available: true,
          methodology: 'snmp:physical-inventory',
          items: [item],
          next_index: 1,
        })
      default:
        return fallback(input, init)
    }
  })
  renderApp('/planes/device', { me: { permissions: ['entities.read', 'metrics.read'] } })
  fireEvent.click(await screen.findByRole('button', { name: 'Find physical inventory' }))
  expect(reads).toEqual([])
  await screen.findByRole('option', { name: 'Edge / Blue' })
  fireEvent.change(screen.getByRole('combobox', { name: 'Routing context' }), {
    target: { value: context },
  })
  await screen.findByRole('option', { name: 'Edge chassis' })
  fireEvent.change(screen.getByRole('combobox', { name: 'Device' }), {
    target: { value: device },
  })
  expect(await screen.findByText('Inventory sources could not be loaded.')).toBeInTheDocument()
  sourceUnavailable = false
  fireEvent.click(screen.getByRole('button', { name: 'Retry inventory sources' }))
  const option = await screen.findByRole('option', { name: '192.0.2.1 · inventory-collector' })
  fireEvent.change(screen.getByRole('combobox', { name: 'Inventory source' }), {
    target: { value: (option as HTMLOptionElement).value },
  })
  const table = within(await screen.findByRole('table', { name: 'Physical inventory' }))
  expect(table.getByText('Parent index 0')).toBeInTheDocument()
  expect(table.getByText('original-poll-serial')).toBeInTheDocument()
  expect(table.getByRole('link', { name: 'Vendor notice' })).toHaveAttribute(
    'href',
    lifecycle.notice.notice_url,
  )
  expect(table.getByRole('link', { name: 'CVE-2026-99101' })).toHaveAttribute(
    'href',
    item.references.vulnerabilities[0].nvd_source,
  )
  expect(table.getByRole('link', { name: 'CISA known exploited' })).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Next components' }))
  expect(
    await screen.findByText('A newer poll replaced this inventory snapshot.'),
  ).toBeInTheDocument()
  expect(screen.queryByText('original-poll-serial')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Open latest snapshot' }))
  expect(await screen.findByText('latest-poll-serial')).toBeInTheDocument()
  expect(screen.getByText('Vulnerability coverage unknown.')).toBeInTheDocument()
  expect(reads).toEqual([exact, { ...exact, observation_id: oldPoll, after_index: '1' }, exact])
})

test('keeps inventory out of the device view without canonical device permission', async () => {
  vi.stubGlobal('fetch', defaultFetch())
  renderApp('/planes/device', { me: { permissions: ['metrics.read'] } })
  expect(await screen.findByRole('tab', { name: /device/i })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Find physical inventory' })).not.toBeInTheDocument()
})
