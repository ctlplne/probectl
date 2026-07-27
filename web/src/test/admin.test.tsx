// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

const staleAgent = {
  id: 'agent-stale',
  name: 'edge-stale',
  hostname: 'edge-stale.example',
  agent_version: 'v1.3.0',
  status: 'online' as const,
  capabilities: ['flow'],
  last_seen_at: '2026-07-14T11:45:00Z',
  heartbeat_age_seconds: 900,
  heartbeat_state: 'stale' as const,
  heartbeat_reason: 'Last authenticated heartbeat is older than the 5m0s health gate.',
  version_state: 'supported_skew' as const,
  version_reason: 'Agent v1.3.0 is inside the supported N/N-1 window.',
  readiness_state: 'stale' as const,
  readiness_reason: 'Last authenticated heartbeat is older than the 5m0s health gate.',
  rollout_id: 'rollout-7',
  rollout_target: 'v1.4.0',
  rollout_cohort: 'canary' as const,
  rollout_state: 'applying' as const,
  rollout_halted: false,
  last_failure: 'Last authenticated heartbeat is older than the 5m0s health gate.',
  next_safe_action: {
    kind: 'verify_rollout_wave' as const,
    label: 'Review rollout health gate',
    reason: 'Confirm the signed target and fresh registry heartbeat before advancing.',
    href: '/docs/api#rollouts',
  },
}

const noHeartbeatAgent = {
  id: 'agent-never',
  name: 'new-collector',
  hostname: '',
  agent_version: '',
  status: 'registered' as const,
  capabilities: [] as string[],
  heartbeat_state: 'never_seen' as const,
  heartbeat_reason: 'Agent has not completed an authenticated heartbeat.',
  version_state: 'unknown' as const,
  version_reason: 'Agent has not reported a version.',
  readiness_state: 'never_connected' as const,
  readiness_reason: 'Agent has not completed an authenticated heartbeat.',
  rollout_halted: false,
  last_failure: 'Agent has not completed an authenticated heartbeat.',
  next_safe_action: {
    kind: 'inspect_heartbeat' as const,
    label: 'Inspect enrollment and heartbeat',
    reason: 'Review mTLS enrollment and transport evidence.',
    href: '/docs/api#rollouts',
  },
}

function fleetFetch(rolloutsAvailable: boolean) {
  const base = defaultFetch()
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === '/v1/agents') {
      return jsonResponse({
        items: [staleAgent, noHeartbeatAgent],
        control_version: 'v1.4.0',
        rollouts_available: rolloutsAvailable,
      })
    }
    return base(input, init)
  })
}

describe('Admin fleet health action center', () => {
  test('shows registry evidence and opens a read-only, human-gated safe action', async () => {
    const user = userEvent.setup()
    const fetchMock = fleetFetch(true)
    vi.stubGlobal('fetch', fetchMock)

    renderApp('/admin')

    const table = await screen.findByRole('table', { name: 'Registered agents' })
    expect(within(table).getByText('Stale heartbeat')).toBeInTheDocument()
    expect(within(table).getByText('No heartbeat')).toBeInTheDocument()
    expect(within(table).getByText('None reported')).toBeInTheDocument()
    expect(within(table).getByText('canary · applying')).toBeInTheDocument()
    expect(within(table).getAllByText(/older than the 5m0s health gate/)).toHaveLength(2)
    const outcomes = await screen.findByRole('list', {
      name: /per-target device collection outcome receipts/i,
    })
    expect(within(outcomes).getAllByText('edge-r1.internal')).toHaveLength(2)
    expect(within(outcomes).getByText('Failed')).toBeInTheDocument()
    expect(within(outcomes).getByText('Healthy, empty')).toBeInTheDocument()
    expect(
      within(outcomes).getByText('Verify local access to the configured target.'),
    ).toBeInTheDocument()
    expect(within(outcomes).queryByRole('table')).not.toBeInTheDocument()

    await user.click(within(table).getByRole('button', { name: 'Review rollout health gate' }))
    const dialog = await screen.findByRole('dialog', { name: 'Safe action for edge-stale' })
    expect(within(dialog).getByText(/probectl never updates an agent/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/human-approved/i)).toBeInTheDocument()
    expect(
      within(dialog).getByRole('link', { name: /open rollout api and runbook/i }),
    ).toHaveAttribute('href', '/docs/api#rollouts')

    const mutation = fetchMock.mock.calls.find(([, init]) => (init?.method ?? 'GET') !== 'GET')
    expect(mutation, 'opening a safe action must not mutate fleet state').toBeUndefined()
  })

  test('reports rollout evidence unavailable without hiding fleet rows', async () => {
    vi.stubGlobal('fetch', fleetFetch(false))
    renderApp('/admin')

    expect(await screen.findByText(/staged-rollout evidence is unavailable/i)).toBeInTheDocument()
    expect(screen.getByText('edge-stale')).toBeInTheDocument()
    expect(screen.getAllByText('Rollout evidence unavailable').length).toBeGreaterThan(0)
  })
})
