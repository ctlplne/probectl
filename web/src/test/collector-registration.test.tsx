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
      return jsonResponse(
        {
          tenant_id: '00000000-0000-0000-0000-000000000001',
          agent_id: '11111111-1111-4111-8111-111111111111',
          plane: 'flow',
          hostname: 'edge-flow-1',
          capabilities: ['collector', 'flow'],
          config: {
            env: {
              PROBECTL_FLOW_TENANT: '00000000-0000-0000-0000-000000000001',
              PROBECTL_FLOW_AGENT_ID: '11111111-1111-4111-8111-111111111111',
            },
            yaml: {
              tenant_id: '00000000-0000-0000-0000-000000000001',
              agent_id: '11111111-1111-4111-8111-111111111111',
            },
          },
        },
        201,
      )
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('Admin collector registration journey (JOURNEY-003)', () => {
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
})
