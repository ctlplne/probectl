// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { expect, test, vi } from 'vitest'
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
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
                  config_coverage: 'operator_bound_archives',
                  config_changes: Array.from({ length: 501 }, (_, revision) => ({
                    id: `original-config-${lane}-${revision + 1}`,
                    version: revision + 1,
                    content_hash: `original-hash-${lane}-${revision + 1}`,
                    previous_id: revision > 0 ? `original-config-${lane}-${revision}` : undefined,
                    previous_hash: revision > 0 ? `original-hash-${lane}-${revision}` : undefined,
                    previous_version: revision > 0 ? revision : undefined,
                    drifted: revision > 0,
                    change_status:
                      revision === 0 ? 'initial_archive' : 'original_predecessor_verified',
                    observed_at: '2026-11-14T00:00:30Z',
                    archived_at: '2026-11-14T00:00:30Z',
                    binding: {
                      kind: 'operator_bound_archive',
                      context_id: context,
                      device_entity_id: entity,
                      agent_id: 'snmp-agent',
                      source_ref: '192.0.2.1',
                      source_assigned_at: '2026-11-14T00:00:00Z',
                      agent_assigned_at: '2026-11-14T00:00:00Z',
                      bound_at: '2026-11-14T00:00:30Z',
                    },
                  })),
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
    const from = '2026-11-14T00:00:00.000Z'
    const to = '2026-11-14T00:01:00.000Z'
    const range = new URLSearchParams({
      ctx_v: '1',
      ctx_from: from,
      ctx_to: to,
      ctx_expires: new Date(Date.now() + 300_000).toISOString(),
    })
    renderApp(`/path?${range.toString()}`, {
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
    expect(health).toHaveTextContent(`original-config-${lane}-501`)
    expect(health).not.toHaveTextContent(`original-config-${3 - lane}-501`)
    expect(
      within(health).getByRole('table', { name: 'Original directional interface counters' }),
    ).toBeInTheDocument()
    expect(screen.getByText('192.0.2.101')).toBeInTheDocument()
    expect(requests.length).toBeGreaterThan(0)
    expect(
      requests.every(
        (url) =>
          new URL(url, 'https://probectl.invalid').searchParams.get('include_health') === 'true' &&
          new URL(url, 'https://probectl.invalid').searchParams.get('health_from') === from &&
          new URL(url, 'https://probectl.invalid').searchParams.get('health_to') === to &&
          !url.includes('tenant_id='),
      ),
    ).toBe(true)
    cleanup()
  }
})

test('path explanation pins the owned test and shows its complete original cited snapshot for each tenant', async () => {
  for (const lane of [1, 2]) {
    const tenant = `00000000-0000-4000-8000-00000000010${lane}`
    stubPathHistoryFetch([], {
      tenant,
      context: `00000000-0000-4000-8000-00000000020${lane}`,
      entity: `00000000-0000-4000-8000-00000000030${lane}`,
    })
    const fallback = globalThis.fetch
    const asks: Array<{ question: string; subject: Record<string, string> }> = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) !== '/v1/ai/ask') return fallback(input, init)
      asks.push(JSON.parse(String(init?.body)))
      return jsonResponse({
        id: `answer-${lane}`,
        tenant,
        root_cause: 'Current interface observations; causal attribution remains unproven.',
        root_cause_grounded: true,
        root_cause_citations: [{ evidence_id: 'E1' }],
        confidence: 'low',
        insufficient_evidence: true,
        findings: [],
        evidence: [
          {
            id: 'E1',
            domain: 'metrics',
            plane: 'path',
            title: 'Current interface observations',
            fields: {
              path_health: {
                test_id: 't1',
                items: [{ value: '9007199254740993', capture_key: `original-${lane}` }],
              },
            },
          },
        ],
      })
    })
    renderApp('/path', {
      me: {
        tenant_id: tenant,
        permissions: ['test.read', 'entities.read', 'metrics.read', 'ai.query'],
      },
    })
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Test' })).toHaveValue('t1'))
    fireEvent.click(screen.getByRole('button', { name: 'Explain this view' }))
    const snapshot = await screen.findByLabelText('Complete original path evidence')
    expect(snapshot).toHaveTextContent('9007199254740993')
    expect(snapshot).toHaveTextContent(`original-${lane}`)
    expect(snapshot).not.toHaveTextContent(`original-${3 - lane}`)
    expect(asks).toHaveLength(1)
    expect(asks[0].subject.path_test_id).toBe('t1')
    expect(asks[0].subject).not.toHaveProperty('tenant_id')
    expect(asks[0].question).toContain('latest owned path')
    cleanup()
  }
})
