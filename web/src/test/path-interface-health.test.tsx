// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { expect, test, vi } from 'vitest'
import { cleanup, fireEvent, screen, within } from '@testing-library/react'
import { renderApp } from './renderApp'
import { jsonResponse, pathOf } from './fetchStub'
import { stubPathHistoryFetch } from './pathHistoryFixture'

test('path health retains exact originals and assumptions across paired tenant screens', async () => {
  for (const lane of [1, 2]) {
    const tenant = `00000000-0000-4000-8000-00000000010${lane}`
    const context = `00000000-0000-4000-8000-00000000020${lane}`
    const entity = `00000000-0000-4000-8000-00000000030${lane}`
    const requests: string[] = []
    stubPathHistoryFetch([], { tenant, context, entity })
    const fallback = globalThis.fetch
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) !== '/v1/tests/t1/path/entities') return fallback(input, init)
      requests.push(String(input))
      return jsonResponse({
        test_id: 't1',
        context_id: context,
        status: 'current',
        truncated: false,
        items: Array.from({ length: 101 }, (_, index) => ({
          ttl: index + 1,
          ip: `192.0.2.${index + 1}`,
          resolution: {
            scope: { tenant_id: tenant, context_id: context },
            alias: { kind: 'address', value: `192.0.2.${index + 1}` },
            status: 'resolved',
            entity_id: entity,
            more_candidates: false,
          },
          health:
            index > 0
              ? undefined
              : {
                  status: 'observed_originals',
                  context_id: context,
                  device_id: entity,
                  interface_id: `interface-${lane}`,
                  agent_id: 'snmp-agent',
                  source_ref: '192.0.2.1',
                  from: '2026-11-14T00:00:00Z',
                  to: '2026-11-14T00:01:00Z',
                  method: 'original_counter_poll_start_mean',
                  config_coverage: 'unavailable_no_context_bound_archive',
                  counters: [
                    {
                      metric: 'probectl.device.if.in.octets',
                      value: '9007199255965993',
                      previous_value: '9007199254740993',
                      rate_numerator: '9800000',
                      rate_denominator: '1',
                      rate_kind: 'minimum_under_counter_continuity',
                      rate_unit: 'bits/s',
                      utilization_numerator: '98',
                      utilization_denominator: '1',
                      utilization_kind:
                        'minimum_under_counter_continuity_and_constant_polled_speed',
                      capture_key: `capture-${lane}`,
                      previous_capture_key: `previous-${lane}`,
                      raw_digest: `digest-${lane}`,
                    },
                    {
                      metric: 'probectl.device.if.in.errors',
                      rate_kind: 'unavailable',
                      rate_unit: 'packets/s',
                      reason: 'one_original_poll',
                      value: '0',
                    },
                  ],
                },
        })),
      })
    })
    renderApp('/path', {
      me: { tenant_id: tenant, permissions: ['test.read', 'entities.read', 'metrics.read'] },
    })
    const summary = await screen.findByText('Polled interface health preview · observed originals')
    fireEvent.click(summary)
    const health = summary.parentElement as HTMLElement
    expect(health).toHaveTextContent(`interface-${lane}`)
    expect(health).toHaveTextContent('9800000 bits/s · Minimum if counter continuity holds')
    expect(health).toHaveTextContent(
      '98% · minimum if counter continuity holds and constant polled speed',
    )
    expect(health).toHaveTextContent('one original poll')
    expect(health).toHaveTextContent('9007199254740993')
    expect(health).toHaveTextContent(`capture-${lane}`)
    expect(health).not.toHaveTextContent(`capture-${3 - lane}`)
    expect(
      within(health).getByRole('table', { name: 'Original directional interface counters' }),
    ).toBeInTheDocument()
    expect(screen.getByText('192.0.2.101')).toBeInTheDocument()
    expect(requests.length).toBeGreaterThan(0)
    expect(
      requests.every(
        (url) =>
          new URL(url, 'https://probectl.invalid').searchParams.get('include_health') === 'true' &&
          !url.includes('tenant_id='),
      ),
    ).toBe(true)
    cleanup()
  }
})
