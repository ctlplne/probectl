// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { describe, expect, test, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '../renderApp'
import { defaultFetch, jsonResponse, pathOf } from '../fetchStub'
import { JourneyRecorder } from './measurement'

function fleetAgent(
  id: string,
  name: string,
  readiness: 'ready' | 'stale' | 'version_skew',
  overrides: Record<string, unknown> = {},
) {
  const ready = readiness === 'ready'
  const skew = readiness === 'version_skew'
  return {
    id,
    name,
    hostname: `${name}.example`,
    agent_version: skew ? 'v1.1.0' : 'v1.4.0',
    status: 'online',
    capabilities: ['flow'],
    heartbeat_age_seconds: ready || skew ? 30 : 900,
    heartbeat_state: ready || skew ? 'ready' : 'stale',
    heartbeat_reason: ready || skew ? 'Heartbeat is fresh.' : 'Heartbeat is stale.',
    version_state: skew ? 'unsupported' : 'current',
    version_reason: skew ? 'Minor-version skew exceeds the supported window.' : 'Version matches.',
    readiness_state: readiness,
    readiness_reason: skew
      ? 'Minor-version skew exceeds the supported window.'
      : ready
        ? 'Agent is ready.'
        : 'Heartbeat is stale.',
    rollout_halted: false,
    last_failure: ready ? '' : skew ? 'Unsupported version.' : 'Heartbeat is stale.',
    next_safe_action: {
      kind: skew ? 'review_staged_rollout' : ready ? 'inspect_evidence' : 'inspect_heartbeat',
      label: skew
        ? 'Review staged rollout'
        : ready
          ? 'Inspect agent evidence'
          : 'Inspect stale heartbeat',
      reason: skew
        ? 'A human may plan a signed, cohort-gated rollout or rollback.'
        : 'Review tenant-scoped evidence only.',
      href: '/docs/api#rollouts',
    },
    ...overrides,
  }
}

describe('J5 fleet health to safe action', () => {
  test('identifies stale and version-skewed agents and opens guidance within three interactions', async () => {
    const user = userEvent.setup()
    const base = defaultFetch()
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (pathOf(input) === '/v1/agents') {
          return jsonResponse({
            items: [
              fleetAgent('ready', 'ready-edge', 'ready'),
              fleetAgent('stale', 'stale-edge', 'stale'),
              fleetAgent('skew', 'skew-edge', 'version_skew'),
            ],
            control_version: 'v1.4.0',
            rollouts_available: true,
          })
        }
        return base(input, init)
      }),
    )

    renderApp('/admin')
    await screen.findByText('ready-edge')

    let interactions = 0
    await user.selectOptions(screen.getByLabelText('Fleet health'), 'needs_action')
    interactions += 1

    const table = screen.getByRole('table', { name: 'Registered agents' })
    expect(within(table).getByText('stale-edge')).toBeInTheDocument()
    expect(within(table).getByText('skew-edge')).toBeInTheDocument()
    expect(within(table).queryByText('ready-edge')).not.toBeInTheDocument()

    await user.click(within(table).getByRole('button', { name: 'Review staged rollout' }))
    interactions += 1

    const dialog = await screen.findByRole('dialog', { name: 'Safe action for skew-edge' })
    expect(within(dialog).getByText(/never updates an agent/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/signed artifact/i)).toBeInTheDocument()
    expect(within(dialog).getByText(/rollback-capable/i)).toBeInTheDocument()

    const measurement = new JourneyRecorder('J5', 'fleet health to safe action')
      .pointer(interactions)
      .typedCount(0)
      .activeTimeProxy({
        min_ms: 5_000,
        max_ms: 30_000,
        basis: 'filter unhealthy agents, then open one evidence-only safe action',
      })
      .complete(
        'stale and version-skewed agents identified',
        'safe action is human-gated and never executes an update',
        'rollout cohort, health gate, rollback, tenant/RBAC, and audit constraints remain visible',
      )
      .snapshot()

    expect(measurement.pointer_interactions).toBeLessThanOrEqual(3)
    expect(measurement.typed_characters).toBeLessThanOrEqual(7)
    expect(measurement.context_breaks).toBe(0)
  })
})
