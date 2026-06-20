import { describe, expect, test, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

function enrollmentFetch(capture: { body?: Record<string, unknown> }) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/agents/enroll-tokens' && method === 'POST') {
      capture.body = JSON.parse(String(init!.body)) as Record<string, unknown>
      return jsonResponse(
        {
          token: 'pjt_testtoken',
          id: 'enrtok_1',
          tenant_id: '00000000-0000-0000-0000-000000000001',
          expires_at: '2026-06-20T20:00:00Z',
          server_cert_pin: '012345abcdef',
        },
        201,
      )
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('Admin agent enrollment journey (JOURNEY-002)', () => {
  test('mints a tenant-scoped token and prints the exact enroll command with trust pin', async () => {
    const capture: { body?: Record<string, unknown> } = {}
    vi.stubGlobal('fetch', enrollmentFetch(capture))
    renderApp('/admin')

    await userEvent.click(await screen.findByRole('button', { name: /enroll agent/i }))
    await userEvent.type(screen.getByLabelText(/agent label/i), 'edge canary')
    await userEvent.type(screen.getByLabelText(/pinned agent id/i), 'edge-a')
    await userEvent.clear(screen.getByLabelText(/token ttl minutes/i))
    await userEvent.type(screen.getByLabelText(/token ttl minutes/i), '30')
    await userEvent.clear(screen.getByLabelText(/control plane url/i))
    await userEvent.type(
      screen.getByLabelText(/control plane url/i),
      'https://control.example:8443',
    )

    await userEvent.click(screen.getByRole('button', { name: /mint token/i }))

    expect(await screen.findByDisplayValue('pjt_testtoken')).toBeInTheDocument()
    const command = (await screen.findByLabelText(/enrollment command/i)) as HTMLInputElement
    expect(command.value).toBe(
      'probectl-agent enroll --server https://control.example:8443 --token pjt_testtoken --dir /var/lib/probectl-agent/identity --ca-pin 012345abcdef',
    )
    expect(capture.body).toEqual({
      agent_id: 'edge-a',
      name: 'edge canary',
      ttl_seconds: 1800,
    })
    expect(capture.body).not.toHaveProperty('tenant_id')
  })
})
