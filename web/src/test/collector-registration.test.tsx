// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

function collectorFetch(capture: {
  mint?: Record<string, unknown>
  register?: Record<string, unknown>
}) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/agents/enroll-tokens' && method === 'POST') {
      capture.mint = JSON.parse(String(init!.body)) as Record<string, unknown>
      return jsonResponse(
        {
          token: 'pjt_collectortoken',
          id: 'enrtok_collector',
          tenant_id: '00000000-0000-0000-0000-000000000001',
          expires_at: '2026-06-20T20:05:00Z',
        },
        201,
      )
    }
    if (path === '/v1/collectors/register' && method === 'POST') {
      capture.register = JSON.parse(String(init!.body)) as Record<string, unknown>
      const plane = String(capture.register.plane ?? 'flow')
      const hostname = String(capture.register.hostname ?? 'edge-flow-1')
      const bgp = plane === 'bgp'
      const device = plane === 'device'
      const collectionProfile = String(capture.register.collection_profile ?? 'standard')
      return jsonResponse(
        {
          tenant_id: '00000000-0000-0000-0000-000000000001',
          agent_id: '11111111-1111-4111-8111-111111111111',
          plane,
          hostname,
          capabilities: ['collector', plane],
          config: {
            env: bgp
              ? {
                  PROBECTL_BGP_TENANT_ID: '00000000-0000-0000-0000-000000000001',
                  PROBECTL_BMP_COLLECTOR: '11111111-1111-4111-8111-111111111111',
                }
              : device
                ? {
                    PROBECTL_DEVICE_TENANT: '00000000-0000-0000-0000-000000000001',
                    PROBECTL_DEVICE_AGENT_ID: '11111111-1111-4111-8111-111111111111',
                    PROBECTL_DEVICE_PROFILE: collectionProfile,
                  }
                : {
                    PROBECTL_FLOW_TENANT: '00000000-0000-0000-0000-000000000001',
                    PROBECTL_FLOW_AGENT_ID: '11111111-1111-4111-8111-111111111111',
                  },
            yaml: bgp
              ? {
                  tenant_id: '00000000-0000-0000-0000-000000000001',
                  collector: '11111111-1111-4111-8111-111111111111',
                  source_type: 'bmp',
                }
              : device
                ? {
                    tenant_id: '00000000-0000-0000-0000-000000000001',
                    agent_id: '11111111-1111-4111-8111-111111111111',
                    collection_profile: collectionProfile,
                  }
                : {
                    tenant_id: '00000000-0000-0000-0000-000000000001',
                    agent_id: '11111111-1111-4111-8111-111111111111',
                  },
            ...(bgp ? { startup_command: 'probectl-bmp-listener' } : {}),
          },
        },
        201,
      )
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('Admin collector registration journey (JOURNEY-003)', () => {
  test('deep-links to eBPF registration with Linux capability prerequisites before token minting', async () => {
    const capture: { mint?: Record<string, unknown>; register?: Record<string, unknown> } = {}
    vi.stubGlobal('fetch', collectorFetch(capture))
    renderApp('/admin?register_collector=ebpf')

    const dialog = await screen.findByRole('dialog', { name: /register collector/i })
    expect(within(dialog).getByLabelText(/collector plane/i)).toHaveValue('ebpf')
    expect(
      within(dialog).getByText(/Linux host with CAP_BPF, CAP_PERFMON, and BTF/i),
    ).toBeInTheDocument()
    expect(capture.mint).toBeUndefined()
    expect(capture.register).toBeUndefined()
  })

  test('mints and consumes a tenant token without sending tenant_id from the browser', async () => {
    const capture: { mint?: Record<string, unknown>; register?: Record<string, unknown> } = {}
    vi.stubGlobal('fetch', collectorFetch(capture))
    renderApp('/admin')

    await userEvent.click(await screen.findByRole('button', { name: /register collector/i }))
    await userEvent.selectOptions(screen.getByLabelText(/collector plane/i), 'flow')
    await userEvent.type(screen.getByLabelText(/collector label/i), 'edge-flow-1')
    await userEvent.type(
      screen.getByLabelText(/pinned collector id/i),
      '11111111-1111-4111-8111-111111111111',
    )

    const dialog = screen.getByRole('dialog', { name: /register collector/i })
    await userEvent.click(within(dialog).getByRole('button', { name: /register collector/i }))

    expect(
      await screen.findByDisplayValue('11111111-1111-4111-8111-111111111111'),
    ).toBeInTheDocument()
    expect(
      screen.getByDisplayValue('PROBECTL_FLOW_AGENT_ID=11111111-1111-4111-8111-111111111111'),
    ).toBeInTheDocument()
    expect(capture.mint).toEqual({
      agent_id: '11111111-1111-4111-8111-111111111111',
      name: 'edge-flow-1',
      ttl_seconds: 300,
    })
    expect(capture.mint).not.toHaveProperty('tenant_id')
    expect(capture.register).toEqual({
      token: 'pjt_collectortoken',
      plane: 'flow',
      hostname: 'edge-flow-1',
    })
    expect(capture.register).not.toHaveProperty('tenant_id')
  })

  test('configures a BGP source with BMP startup hints from the product surface', async () => {
    const capture: { mint?: Record<string, unknown>; register?: Record<string, unknown> } = {}
    vi.stubGlobal('fetch', collectorFetch(capture))
    renderApp('/admin')

    await userEvent.click(await screen.findByRole('button', { name: /register collector/i }))
    await userEvent.selectOptions(screen.getByLabelText(/collector plane/i), 'bgp')
    await userEvent.type(screen.getByLabelText(/collector label/i), 'rrc00')
    await userEvent.type(
      screen.getByLabelText(/pinned collector id/i),
      '11111111-1111-4111-8111-111111111111',
    )

    const dialog = screen.getByRole('dialog', { name: /register collector/i })
    await userEvent.click(within(dialog).getByRole('button', { name: /register collector/i }))

    expect(await screen.findByDisplayValue('bgp')).toBeInTheDocument()
    expect(screen.getByDisplayValue('probectl-bmp-listener')).toBeInTheDocument()
    expect(
      screen.getByDisplayValue('PROBECTL_BMP_COLLECTOR=11111111-1111-4111-8111-111111111111'),
    ).toBeInTheDocument()
    expect(screen.getByDisplayValue('source_type: "bmp"')).toBeInTheDocument()
    expect(screen.getByText(/collector, bgp/i)).toBeInTheDocument()
    expect(capture.mint).toEqual({
      agent_id: '11111111-1111-4111-8111-111111111111',
      name: 'rrc00',
      ttl_seconds: 300,
    })
    expect(capture.mint).not.toHaveProperty('tenant_id')
    expect(capture.register).toEqual({
      token: 'pjt_collectortoken',
      plane: 'bgp',
      hostname: 'rrc00',
    })
    expect(capture.register).not.toHaveProperty('tenant_id')
  })

  test('previews and registers a bounded device evidence profile without tenant input', async () => {
    const capture: { mint?: Record<string, unknown>; register?: Record<string, unknown> } = {}
    vi.stubGlobal('fetch', collectorFetch(capture))
    renderApp('/admin?register_collector=device')

    const dialog = await screen.findByRole('dialog', { name: /register collector/i })
    const profile = within(dialog).getByRole('combobox', { name: /device evidence profile/i })
    const preview = within(dialog).getByRole('region', {
      name: /credential-free effective collection preview/i,
    })
    expect(profile).toHaveValue('standard')
    expect(within(preview).getByText(/interface counters/i)).toBeInTheDocument()
    expect(within(preview).getByText(/configured targets only/i)).toBeInTheDocument()

    await userEvent.selectOptions(profile, 'topology-rich')
    expect(within(preview).getByText(/LLDP neighbors/i)).toBeInTheDocument()
    expect(within(preview).getByText(/CDP neighbors/i)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: /register collector/i }))

    expect(
      await screen.findByDisplayValue('PROBECTL_DEVICE_PROFILE=topology-rich'),
    ).toBeInTheDocument()
    expect(screen.getByDisplayValue('collection_profile: "topology-rich"')).toBeInTheDocument()
    expect(capture.register).toEqual({
      token: 'pjt_collectortoken',
      plane: 'device',
      collection_profile: 'topology-rich',
    })
    expect(capture.register).not.toHaveProperty('tenant_id')
  })
})
