// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { describe, expect, test, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import type { Rollout } from '../api/rollouts'

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

function rolloutFetch() {
  const base = defaultFetch()
  let state = structuredClone(applyingRollout)
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
  test('shows rollout waves and requires human confirmation before registry verification', async () => {
    const user = userEvent.setup()
    const fetchMock = rolloutFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderApp('/admin')

    const table = await screen.findByRole('table', { name: 'Tenant staged rollouts' })
    expect(within(table).getByText('canary 2 · Applying externally')).toBeInTheDocument()
    expect(within(table).getByText('early 8 · Pending')).toBeInTheDocument()
    expect(screen.getByText(/every wave member must report v1.4.0/i)).toBeInTheDocument()
    expect(screen.getByText(/advance does not deploy code/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Verify health gate' }))
    const dialog = await screen.findByRole('dialog', { name: 'Confirm: Verify health gate' })
    expect(within(dialog).getByText(/never sends an update command/i)).toBeInTheDocument()
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
})
