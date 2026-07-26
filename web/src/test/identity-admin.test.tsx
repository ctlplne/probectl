// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import { renderApp } from './renderApp'
import { assertNoDoublePrefix, defaultFetch, jsonResponse, pathOf } from './fetchStub'

function identityFetch(capture: {
  idpBody?: unknown
  tokenBody?: unknown
  policyBody?: unknown
  revoked?: string
  deleted?: string
}) {
  const base = defaultFetch()
  let tokens: Record<string, unknown>[] = [
    {
      id: 'scim-1',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      name: 'okta',
      created_at: '2026-06-01T00:00:00Z',
    },
  ]
  let policies: Record<string, unknown>[] = [
    {
      id: 'pol-1',
      name: 'contractor write guard',
      effect: 'deny',
      permission: 'test.write',
      subject: { department: 'contractor' },
      priority: 10,
      enabled: true,
    },
  ]
  let idpSettings = {
    source: 'environment',
    configured: true,
    valid: true,
    issuer: 'https://env-idp.example',
    client_id: 'probectl-env',
    client_secret_configured: true,
    redirect_url: 'https://probectl.example/auth/callback',
    scopes: ['openid', 'email', 'profile'],
    enabled: true,
    flags: {},
  }

  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assertNoDoublePrefix(input)
    const path = pathOf(input)
    const method = init?.method ?? 'GET'
    if (path === '/v1/identity/settings' && method === 'GET') return jsonResponse(idpSettings)
    if (path === '/v1/identity/settings' && method === 'PUT') {
      capture.idpBody = JSON.parse(String(init!.body))
      idpSettings = {
        ...idpSettings,
        ...(capture.idpBody as typeof idpSettings),
        source: 'tenant',
        configured: true,
        valid: true,
        client_secret_configured: true,
      }
      return jsonResponse(idpSettings)
    }
    if (path === '/v1/directory/scim-tokens' && method === 'GET')
      return jsonResponse({ items: tokens })
    if (path === '/v1/directory/scim-tokens' && method === 'POST') {
      capture.tokenBody = JSON.parse(String(init!.body))
      tokens = [
        {
          id: 'scim-2',
          tenant_id: '00000000-0000-0000-0000-000000000001',
          name: (capture.tokenBody as { name: string }).name,
          created_at: '2026-06-02T00:00:00Z',
        },
        ...tokens,
      ]
      return jsonResponse({ id: 'scim-2', name: 'entra', token: 'plain-scim-token' }, 201)
    }
    if (path === '/v1/directory/scim-tokens/scim-1' && method === 'DELETE') {
      capture.revoked = 'scim-1'
      tokens = tokens.map((t) =>
        t.id === 'scim-1' ? { ...t, revoked_at: '2026-06-03T00:00:00Z' } : t,
      )
      return jsonResponse(undefined, 204)
    }
    if (path === '/v1/abac/policies' && method === 'GET') return jsonResponse({ items: policies })
    if (path === '/v1/abac/policies' && method === 'POST') {
      capture.policyBody = JSON.parse(String(init!.body))
      policies = [{ id: 'pol-2', ...(capture.policyBody as object) }, ...policies]
      return jsonResponse({ id: 'pol-2', ...(capture.policyBody as object) }, 201)
    }
    if (path === '/v1/abac/policies/pol-1' && method === 'DELETE') {
      capture.deleted = 'pol-1'
      policies = policies.filter((p) => p.id !== 'pol-1')
      return jsonResponse(undefined, 204)
    }
    return base(input, init)
  }) as unknown as typeof fetch
}

describe('Admin identity surface', () => {
  test('manages SCIM tokens and ABAC policies through session-backed APIs', async () => {
    const capture: {
      idpBody?: unknown
      tokenBody?: unknown
      policyBody?: unknown
      revoked?: string
      deleted?: string
    } = {}
    vi.stubGlobal('fetch', identityFetch(capture))
    renderApp('/admin')

    expect(await screen.findByText(/identity administration/i)).toBeInTheDocument()
    const surfaces = screen.getByRole('table', { name: /identity surfaces/i })
    expect(within(surfaces).getByText('/scim/v2/Users')).toBeInTheDocument()
    expect(within(surfaces).getByText('/scim/v2/Groups')).toBeInTheDocument()

    await userEvent.clear(await screen.findByLabelText(/oidc issuer/i))
    await userEvent.type(screen.getByLabelText(/oidc issuer/i), 'https://tenant-idp.example')
    await userEvent.type(screen.getByLabelText(/oidc client secret/i), 'tenant-secret')
    await userEvent.click(screen.getByRole('button', { name: /save oidc settings/i }))
    expect(await screen.findByText(/tenant oidc settings saved/i)).toBeInTheDocument()
    expect(capture.idpBody).toMatchObject({
      issuer: 'https://tenant-idp.example',
      client_id: 'probectl-env',
      client_secret: 'tenant-secret',
      redirect_url: 'https://probectl.example/auth/callback',
      scopes: ['openid', 'email', 'profile'],
      enabled: true,
    })

    await userEvent.clear(screen.getByLabelText(/scim token name/i))
    await userEvent.type(screen.getByLabelText(/scim token name/i), 'entra')
    await userEvent.click(screen.getByRole('button', { name: /create scim token/i }))
    expect(await screen.findByText(/plain-scim-token/i)).toBeInTheDocument()
    expect(capture.tokenBody).toEqual({ name: 'entra' })

    const oktaRow = screen.getByText('okta').closest('tr')
    expect(oktaRow).not.toBeNull()
    await userEvent.click(within(oktaRow!).getByRole('button', { name: /revoke/i }))
    expect(capture.revoked).toBe('scim-1')

    await userEvent.clear(screen.getByLabelText(/policy name/i))
    await userEvent.type(screen.getByLabelText(/policy name/i), 'payment contractor guard')
    await userEvent.clear(screen.getByLabelText(/resource attributes/i))
    await userEvent.type(screen.getByLabelText(/resource attributes/i), 'org=payments')
    await userEvent.click(screen.getByRole('button', { name: /create abac policy/i }))
    expect(capture.policyBody).toMatchObject({
      name: 'payment contractor guard',
      effect: 'deny',
      permission: 'test.write',
      subject: { department: 'contractor' },
      resource: { org: 'payments' },
      priority: 10,
      enabled: true,
    })

    const originalPolicyRow = screen.getByText('contractor write guard').closest('tr')
    expect(originalPolicyRow).not.toBeNull()
    await userEvent.click(within(originalPolicyRow!).getByRole('button', { name: /delete/i }))
    expect(capture.deleted).toBe('pol-1')
  })

  test('failed ABAC-policy deletion stays visible as an accessible error', async () => {
    const base = identityFetch({})
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) === '/v1/abac/policies/pol-1' && (init?.method ?? 'GET') === 'DELETE') {
          return Promise.resolve(
            jsonResponse(
              { error: { code: 'unavailable', message: 'policy store unavailable' } },
              500,
            ),
          )
        }
        return base(input, init)
      }),
    )
    renderApp('/admin')

    const originalPolicyRow = (await screen.findByText('contractor write guard')).closest('tr')
    expect(originalPolicyRow).not.toBeNull()
    await userEvent.click(within(originalPolicyRow!).getByRole('button', { name: /delete/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/policy store unavailable/i)
    expect(screen.getByText('contractor write guard')).toBeInTheDocument()
  })

  test('a11y: identity administration card has no axe violations', async () => {
    vi.stubGlobal('fetch', identityFetch({}))
    const { container } = renderApp('/admin')
    await screen.findByText(/identity administration/i)
    expect(await axe(container)).toHaveNoViolations()
  })
})
