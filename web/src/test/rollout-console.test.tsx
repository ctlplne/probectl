// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import { useIsMutating } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import userEvent from '@testing-library/user-event'
import { Providers } from '../App'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import type { Rollout } from '../api/rollouts'
import { AuthContext, type AuthContextValue } from '../auth/AuthProvider'
import { AdminPage } from '../routes/admin/AdminPage'
import { TimeProvider } from '../time/TimeProvider'

const applyingRollout: Rollout = {
  id: 'rollout-7',
  target: 'v1.4.0',
  digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  halted: false,
  halt_reason: '',
  done: false,
  progress: 'rollout to v1.4.0: canary[2]=applying early[8]=pending main[30]=pending',
  waves: [
    { cohort: 'canary', agents: 2, status: 'applying' },
    { cohort: 'early', agents: 8, status: 'pending' },
    { cohort: 'main', agents: 30, status: 'pending' },
  ],
}

const macEndpoint = {
  platform: 'darwin/arm64',
  executable_identity: `cdhash:${'c'.repeat(40)}`,
}

function rolloutFetch(initial = applyingRollout) {
  const base = defaultFetch()
  let state = structuredClone(initial)
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/rollouts' && (init?.method ?? 'GET') === 'GET') {
      return jsonResponse({ items: [state] })
    }
    if (path === '/v1/rollouts/rollout-7/verify' && init?.method === 'POST') {
      state = {
        ...state,
        progress: 'rollout to v1.4.0: canary[2]=complete early[8]=pending main[30]=pending',
        waves: state.waves.map((wave) =>
          wave.cohort === 'canary' ? { ...wave, status: 'complete' } : wave,
        ),
      }
      return jsonResponse(state)
    }
    if (path === '/v1/rollouts/rollout-7/halt' && init?.method === 'POST') {
      const { reason } = JSON.parse(String(init.body)) as { reason: string }
      state = {
        ...state,
        halted: true,
        halt_reason: reason,
        progress: `rollout to v1.4.0 — HALTED: ${reason}`,
        waves: state.waves.map((wave) =>
          wave.status === 'applying' ? { ...wave, status: 'halted' } : wave,
        ),
      }
      return jsonResponse(state)
    }
    if (path === '/v1/rollouts/rollout-7/resume' && init?.method === 'POST') {
      state = {
        ...state,
        halted: false,
        halt_reason: '',
        progress: 'rollout to v1.4.0: canary[2]=applying early[8]=pending main[30]=pending',
        waves: state.waves.map((wave) =>
          wave.status === 'halted' ? { ...wave, status: 'applying' } : wave,
        ),
      }
      return jsonResponse(state)
    }
    return base(input, init)
  })
}

describe('Admin staged rollout control', () => {
  test('shows native installer and process evidence before human verification', async () => {
    const user = userEvent.setup()
    const fetchMock = rolloutFetch({ ...applyingRollout, endpoint: macEndpoint })
    vi.stubGlobal('fetch', fetchMock)
    renderApp('/admin')

    const table = await screen.findByRole('table', { name: 'Tenant staged rollouts' })
    expect(within(table).getByText('canary 2 · Applying externally')).toBeInTheDocument()
    expect(within(table).getByText('early 8 · Pending')).toBeInTheDocument()
    expect(screen.getByText(/every wave member must report v1.4.0/i)).toBeInTheDocument()
    expect(screen.getByText(/advance releases the signed installer/i)).toBeInTheDocument()
    expect(screen.getByText('Installer SHA-256')).toBeInTheDocument()
    expect(screen.getByText(applyingRollout.digest)).toBeInTheDocument()
    expect(screen.getByText('Expected running executable identity')).toBeInTheDocument()
    expect(screen.getByText(macEndpoint.executable_identity)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Verify health gate' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm: Verify health gate' })
    expect(within(dialog).getByText(/never sends an update command/i)).toBeInTheDocument()
    expect(within(dialog).getByText(macEndpoint.platform)).toBeInTheDocument()
    expect(within(dialog).getByText(applyingRollout.digest)).toBeInTheDocument()
    expect(within(dialog).getByText(macEndpoint.executable_identity)).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          pathOf(input) === '/v1/rollouts/rollout-7/verify' && init?.method === 'POST',
      ),
    ).toBe(false)

    await user.click(within(dialog).getByRole('button', { name: 'Confirm Verify health gate' }))
    expect(await screen.findByText(/verify health gate accepted/i)).toBeInTheDocument()
    expect(screen.getAllByText('Verified complete').length).toBeGreaterThan(0)
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) =>
          pathOf(input) === '/v1/rollouts/rollout-7/verify' && init?.method === 'POST',
      ),
    ).toBe(true)
  })

  test('requires audited reasons for rollout halt and resume', async () => {
    const user = userEvent.setup()
    const fetchMock = rolloutFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderApp('/admin')

    await screen.findByRole('table', { name: 'Tenant staged rollouts' })
    expect(screen.getByText(/advance does not deploy code/i)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Halt rollout' }))
    let dialog = await screen.findByRole('dialog', { name: 'Confirm: Halt rollout' })
    const haltConfirm = within(dialog).getByRole('button', { name: 'Confirm Halt rollout' })
    expect(haltConfirm).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Operator reason'), 'canary error budget burned')
    expect(haltConfirm).toBeEnabled()
    await user.click(haltConfirm)

    expect(await screen.findByText('canary error budget burned')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Resume rollout' }))
    dialog = await screen.findByRole('dialog', { name: 'Confirm: Resume rollout' })
    const resumeConfirm = within(dialog).getByRole('button', { name: 'Confirm Resume rollout' })
    expect(resumeConfirm).toBeDisabled()
    await user.type(
      within(dialog).getByLabelText('Operator reason'),
      'node replaced and fresh heartbeat checked',
    )
    await user.click(resumeConfirm)

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    const actionCalls = fetchMock.mock.calls.filter(
      ([input, init]) =>
        pathOf(input).startsWith('/v1/rollouts/rollout-7/') && init?.method === 'POST',
    )
    expect(actionCalls.map(([input]) => pathOf(input))).toEqual([
      '/v1/rollouts/rollout-7/halt',
      '/v1/rollouts/rollout-7/resume',
    ])
    expect(JSON.parse(String(actionCalls[0][1]?.body))).toEqual({
      reason: 'canary error budget burned',
    })
    expect(JSON.parse(String(actionCalls[1][1]?.body))).toEqual({
      reason: 'node replaced and fresh heartbeat checked',
    })
  })

  test('a late rollout decision stays with its original tenant', async () => {
    const user = userEvent.setup()
    const red = '00000000-0000-4000-8000-000000000101'
    const blue = '00000000-0000-4000-8000-000000000102'
    const windowsEndpoint = {
      platform: 'windows/amd64',
      executable_identity: `sha256:${'d'.repeat(64)}`,
    }
    const nativeRollout = { ...applyingRollout, endpoint: macEndpoint }
    const fallback = defaultFetch()
    let finishRedVerification!: (response: Response) => void
    const pending = new Promise<Response>((resolve) => {
      finishRedVerification = resolve
    })
    const requests: { path: string; tenant: string | null }[] = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      const tenant = new Headers(init?.headers).get('X-Probectl-Tenant')
      if (path === '/v1/agents') {
        requests.push({ path, tenant })
        return jsonResponse({
          items: [
            {
              id: 'same-agent',
              name: tenant === blue ? 'Blue fleet agent' : 'Red fleet agent',
              hostname: 'endpoint-1',
              status: 'online',
              agent_version: 'v1.3.0',
              capabilities: [],
            },
          ],
          rollouts_available: true,
        })
      }
      if (path === '/v1/rollouts') {
        requests.push({ path, tenant })
        return jsonResponse({
          items: [{ ...nativeRollout, endpoint: tenant === blue ? windowsEndpoint : macEndpoint }],
        })
      }
      if (path === '/v1/rollouts/rollout-7/verify' && init?.method === 'POST') {
        requests.push({ path, tenant })
        return pending
      }
      return fallback(input, init)
    })

    function Pending() {
      const count = useIsMutating({ mutationKey: ['rollouts', red] })
      return <output aria-label="Pending red rollout decisions">{count}</output>
    }

    function view(id: string) {
      const tenant = { id, name: 'Customer', slug: 'customer' }
      const auth: AuthContextValue = {
        tenant,
        tenants: [tenant],
        user: { id: 'operator', name: 'Operator', email: 'operator@example.test' },
        permissions: ['agent.read', 'agent.write'],
        switchTenant: () => {},
        signOut: () => {},
      }
      return (
        <Providers>
          <MemoryRouter initialEntries={['/admin']}>
            <AuthContext.Provider value={auth}>
              <TimeProvider>
                <Pending />
                <AdminPage />
              </TimeProvider>
            </AuthContext.Provider>
          </MemoryRouter>
        </Providers>
      )
    }

    const { rerender } = render(view(red))
    expect(await screen.findByText(macEndpoint.executable_identity)).toBeInTheDocument()
    expect(screen.getByText('Red fleet agent')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Verify health gate' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm: Verify health gate' })
    await user.click(within(dialog).getByRole('button', { name: 'Confirm Verify health gate' }))
    await waitFor(() =>
      expect(requests).toContainEqual({ path: '/v1/rollouts/rollout-7/verify', tenant: red }),
    )
    expect(screen.getByLabelText('Pending red rollout decisions')).toHaveTextContent('1')

    rerender(view(blue))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText(macEndpoint.executable_identity)).not.toBeInTheDocument()
    expect(await screen.findByText(windowsEndpoint.executable_identity)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByText('Blue fleet agent')).toBeInTheDocument()
    expect(screen.queryByText('Red fleet agent')).not.toBeInTheDocument()
    expect(requests).toContainEqual({ path: '/v1/agents', tenant: blue })
    expect(requests).toContainEqual({ path: '/v1/rollouts', tenant: blue })

    await act(async () => {
      finishRedVerification(jsonResponse({ ...nativeRollout, progress: 'red wave verified' }))
    })
    await waitFor(() =>
      expect(screen.getByLabelText('Pending red rollout decisions')).toHaveTextContent('0'),
    )
    expect(screen.getByText(windowsEndpoint.executable_identity)).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(
      screen.queryByText(/red wave verified|verify health gate accepted/i),
    ).not.toBeInTheDocument()
  })
})
