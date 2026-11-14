// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { expect, test, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import type { DeviceConfigVersion } from '../api/planes'
import { ConfigArchiveBinding } from '../components/ConfigArchiveBinding'
import { findPreviousConfig } from '../routes/configDiff'
import { renderApp } from './renderApp'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'

test('configuration predecessor stays in its exact canonical source stream across renaming', () => {
  const binding: NonNullable<DeviceConfigVersion['binding']> = {
    kind: 'operator_bound_archive',
    context_id: '00000000-0000-4000-8000-000000000001',
    device_entity_id: '00000000-0000-4000-8000-000000000002',
    agent_id: 'collector',
    source_ref: '192.0.2.1',
    source_assigned_at: '2026-11-14T00:00:00.000001Z',
    agent_assigned_at: '2026-11-14T00:00:00Z',
    bound_at: '2026-11-14T00:01:00Z',
  }
  const previous: DeviceConfigVersion = {
    id: 'previous',
    device: 'old-name',
    version: 1,
    content_hash: 'previous-hash',
    drifted: false,
    content: 'old',
    archived_at: binding.bound_at,
    binding,
  }
  const current: DeviceConfigVersion = {
    ...previous,
    id: 'current',
    device: 'renamed',
    version: 2,
    content_hash: 'current-hash',
    previous_hash: previous.content_hash,
    drifted: true,
    content: 'new',
  }
  expect(findPreviousConfig([previous], current)?.id).toBe('previous')
  for (const replacement of [
    null,
    { ...binding, context_id: 'foreign-context' },
    { ...binding, device_entity_id: 'foreign-device' },
    { ...binding, agent_id: 'different-collector' },
    { ...binding, source_ref: '192.0.2.2' },
    { ...binding, source_assigned_at: '2026-11-14T00:00:00.000002Z' },
    { ...binding, agent_assigned_at: '2026-11-14T00:00:00.000001Z' },
  ]) {
    expect(
      findPreviousConfig([{ ...previous, device: current.device, binding: replacement }], current),
    ).toBeUndefined()
  }
})

test('missing immediate archived predecessor cannot be replaced by an older hash match', () => {
  const older = {
    id: 'old',
    device: 'same',
    version: 1,
    content_hash: 'same-content',
    content: 'old',
    drifted: false,
  }
  const current = {
    ...older,
    id: 'current',
    version: 3,
    previous_hash: older.content_hash,
    content_hash: 'new',
    content: 'new',
    drifted: true,
  }
  expect(findPreviousConfig([older], current)).toBeUndefined()
})

test('configuration association displays exact scoped metadata and honest provenance for paired tenant views', async () => {
  for (const lane of [1, 2]) {
    const context = `00000000-0000-4000-8000-00000000010${lane}`
    const config: DeviceConfigVersion = {
      id: `config-${lane}`,
      device: 'same display',
      version: 1,
      content_hash: 'hash',
      drifted: false,
      archived_at: '2026-11-14T00:01:00Z',
      binding: {
        kind: 'operator_bound_archive',
        context_id: context,
        device_entity_id: `canonical-${lane}`,
        agent_id: `collector-${lane}`,
        source_ref: `192.0.2.${lane}`,
        source_assigned_at: '2026-11-14T00:00:00Z',
        agent_assigned_at: '2026-11-14T00:00:00Z',
        bound_at: '2026-11-14T00:01:00Z',
      },
    }
    const fallback = defaultFetch()
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) =>
      pathOf(input) === '/v1/device/configs'
        ? jsonResponse({ items: [config], archive_running: true })
        : fallback(input, init),
    )
    const result = renderApp('/planes/device', {
      me: {
        tenant_id: `00000000-0000-4000-8000-00000000030${lane}`,
        permissions: ['metrics.read', 'entities.read'],
      },
    })
    await screen.findAllByText('Operator-bound archive')
    expect(screen.getAllByText('Operator-bound archive')).toHaveLength(2)
    expect(
      screen.getAllByText('Declared device association; device collection was not attested.'),
    ).toHaveLength(2)
    expect(result.container).toHaveTextContent(context)
    expect(result.container).toHaveTextContent(`collector-${lane}`)
    expect(result.container).not.toHaveTextContent(`canonical-${3 - lane}`)
    cleanup()
  }
  render(
    <ConfigArchiveBinding
      config={{
        id: 'legacy',
        device: 'name-only',
        version: 1,
        content_hash: 'hash',
        drifted: false,
        archived_at: '2026-11-14T00:01:00Z',
      }}
    />,
  )
  expect(screen.getByText('Unbound archive')).toBeInTheDocument()
})
