// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
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
  // TQ-12: these were one 15-interaction mega-test. Under the full parallel
  // vitest run it occasionally blew the per-test timeout mid-flight, and a
  // timed-out test does not finish its React unmount — so the NEXT test found
  // two identity cards in the DOM ("Found multiple elements with the text:
  // contractor write guard"). Splitting it per surface keeps every test short
  // (afterEach cleanup runs cleanly between them), and the capture assertions
  // wait for the stubbed request to land instead of reading it on wall-clock
  // faith.
  type IdentityCapture = {
    idpBody?: unknown
    tokenBody?: unknown
    policyBody?: unknown
    revoked?: string
    deleted?: string
  }
  async function openAdmin(capture: IdentityCapture = {}): Promise<IdentityCapture> {
    vi.stubGlobal('fetch', identityFetch(capture))
    renderApp('/admin')
    expect(await screen.findByText(/identity administration/i)).toBeInTheDocument()
    return capture
  }

  test('lists the read-only SCIM identity surfaces', async () => {
    await openAdmin()
    const surfaces = screen.getByRole('table', { name: /identity surfaces/i })
    expect(within(surfaces).getByText('/scim/v2/Users')).toBeInTheDocument()
    expect(within(surfaces).getByText('/scim/v2/Groups')).toBeInTheDocument()
  })

  test('saves tenant OIDC settings through the session-backed API', async () => {
    const capture = await openAdmin()
    await userEvent.clear(await screen.findByLabelText(/oidc issuer/i))
    await userEvent.type(screen.getByLabelText(/oidc issuer/i), 'https://tenant-idp.example')
    await userEvent.type(screen.getByLabelText(/oidc client secret/i), 'tenant-secret')
    await userEvent.click(screen.getByRole('button', { name: /save oidc settings/i }))
    expect(await screen.findByText(/tenant oidc settings saved/i)).toBeInTheDocument()
    await waitFor(() =>
      expect(capture.idpBody).toMatchObject({
        issuer: 'https://tenant-idp.example',
        client_id: 'probectl-env',
        client_secret: 'tenant-secret',
        redirect_url: 'https://probectl.example/auth/callback',
        scopes: ['openid', 'email', 'profile'],
        enabled: true,
      }),
    )
  })

  test('creates and revokes a SCIM token through the session-backed API', async () => {
    const capture = await openAdmin()
    await userEvent.clear(screen.getByLabelText(/scim token name/i))
    await userEvent.type(screen.getByLabelText(/scim token name/i), 'entra')
    await userEvent.click(screen.getByRole('button', { name: /create scim token/i }))
    expect(await screen.findByText(/plain-scim-token/i)).toBeInTheDocument()
    await waitFor(() => expect(capture.tokenBody).toEqual({ name: 'entra' }))

    const oktaRow = (await screen.findByText('okta')).closest('tr')
    expect(oktaRow).not.toBeNull()
    await userEvent.click(within(oktaRow!).getByRole('button', { name: /revoke/i }))
    // WEB-21/G8: the row only opens the gate; the revoke fires from the dialog.
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: /revoke token/i }),
    )
    await waitFor(() => expect(capture.revoked).toBe('scim-1'))
  })

  test('creates and deletes an ABAC policy through the session-backed API', async () => {
    const capture = await openAdmin()
    await userEvent.clear(screen.getByLabelText(/policy name/i))
    await userEvent.type(screen.getByLabelText(/policy name/i), 'payment contractor guard')
    await userEvent.clear(screen.getByLabelText(/resource attributes/i))
    await userEvent.type(screen.getByLabelText(/resource attributes/i), 'org=payments')
    await userEvent.click(screen.getByRole('button', { name: /create abac policy/i }))
    await waitFor(() =>
      expect(capture.policyBody).toMatchObject({
        name: 'payment contractor guard',
        effect: 'deny',
        permission: 'test.write',
        subject: { department: 'contractor' },
        resource: { org: 'payments' },
        priority: 10,
        enabled: true,
      }),
    )

    const originalPolicyRow = (await screen.findByText('contractor write guard')).closest('tr')
    expect(originalPolicyRow).not.toBeNull()
    await userEvent.click(within(originalPolicyRow!).getByRole('button', { name: /delete/i }))
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: /delete policy/i }),
    )
    await waitFor(() => expect(capture.deleted).toBe('pol-1'))
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
    await userEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: /delete policy/i }),
    )

    expect(await screen.findByRole('alert')).toHaveTextContent(/policy store unavailable/i)
    expect(screen.getByText('contractor write guard')).toBeInTheDocument()
  })

  test('a11y: identity administration card has no axe violations', async () => {
    vi.stubGlobal('fetch', identityFetch({}))
    const { container } = renderApp('/admin')
    await screen.findByText(/identity administration/i)
    // TQ-12: scan only once the async-loaded surfaces have settled. The card's
    // SCIM-token and ABAC-policy tables arrive on separate fetches; running axe
    // on a half-populated card trips a transient violation under the full
    // parallel run (it passed 19/20 before this wait). Waiting for a row from
    // each table pins a fully-rendered, deterministic DOM.
    await screen.findByText('okta')
    await screen.findByText('contractor write guard')
    expect(await axe(container)).toHaveNoViolations()
  })

  test('WEB-22: the one-time SCIM token can be dismissed and leaves the DOM', async () => {
    vi.stubGlobal('fetch', identityFetch({}))
    renderApp('/admin')

    await userEvent.clear(await screen.findByLabelText(/scim token name/i))
    await userEvent.type(screen.getByLabelText(/scim token name/i), 'entra')
    await userEvent.click(screen.getByRole('button', { name: /create scim token/i }))
    expect(await screen.findByText(/plain-scim-token/i)).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /dismiss/i }))
    expect(screen.queryByText(/plain-scim-token/i)).not.toBeInTheDocument()
  })
})
