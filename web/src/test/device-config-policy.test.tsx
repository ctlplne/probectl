// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const archivedAt = '2026-11-14T00:01:00Z'
const configID = '00000000-0000-4000-8000-000000000233'
const binding = {
  context_id: '00000000-0000-4000-8000-000000000123',
  device_entity_id: '00000000-0000-4000-8000-000000000456',
  agent_id: 'owned-collector',
  source_ref: '192.0.2.1',
}
const config = {
  id: configID,
  device: 'edge-router',
  version: 3,
  content_hash: 'a'.repeat(64),
  drifted: false,
  archived_at: archivedAt,
  binding: {
    ...binding,
    kind: 'operator_bound_archive',
    source_assigned_at: archivedAt,
    agent_assigned_at: archivedAt,
    bound_at: archivedAt,
  },
}

function fixture(saved: unknown[]) {
  const fallback = defaultFetch()
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    switch (pathOf(input)) {
      case '/v1/device/configs':
        return jsonResponse({ items: [config], archive_running: true })
      case '/v1/device/config-policy': {
        if (init?.method === 'PUT' && typeof init.body === 'string') {
          saved.push(JSON.parse(init.body) as unknown)
          return jsonResponse({
            version: '8',
            published_at: archivedAt,
            rules: [{ id: 'clock', revision: '8', mode: 'template', template: 'ios_ntp_server' }],
          })
        }
        return jsonResponse({ version: '7', published_at: archivedAt, rules: [] })
      }
      case `/v1/device/configs/${configID}/policy-evaluation`:
        return jsonResponse({
          archive_id: configID,
          evaluation: {
            policy_version: '6',
            evaluated_at: archivedAt,
            verdicts: [
              {
                rule_id: 'legacy-snmp',
                archive_id: configID,
                archive_sha256: config.content_hash,
                rule_revision: '6',
                state: 'violation',
                total_matches: 1,
                offending_lines: [
                  { line_number: 2, redacted_line: 'snmp-server community [redacted] RO' },
                ],
              },
            ],
          },
          observed_at: archivedAt,
        })
      default:
        return fallback(input, init)
    }
  })
}

test('opens the retained evaluation and saves new rules for the bound device', async () => {
  const saved: unknown[] = []
  fixture(saved)
  renderApp('/planes/device', {
    me: { permissions: ['metrics.read', 'metrics.write', 'entities.read'] },
  })
  const triggers = await screen.findAllByRole('button', { name: 'Configuration policy' })
  fireEvent.click(triggers[0])
  const dialog = within(
    await screen.findByRole('dialog', { name: 'Configuration policy · edge-router' }),
  )
  expect(await dialog.findByText('Rule revision 6')).toBeInTheDocument()
  expect(dialog.getByText('snmp-server community [redacted] RO')).toBeInTheDocument()
  expect(dialog.getByRole('button', { name: 'Download CSV' })).toBeInTheDocument()
  fireEvent.click(await dialog.findByRole('button', { name: 'Add rule' }))
  fireEvent.change(dialog.getByLabelText('Rule ID'), { target: { value: 'clock' } })
  fireEvent.click(dialog.getByRole('button', { name: 'Publish for new archives' }))
  await waitFor(() =>
    expect(saved).toEqual([
      {
        binding,
        expected_revision: '7',
        rules: [{ id: 'clock', mode: 'template', template: 'ios_ntp_server' }],
      },
    ]),
  )
  expect(dialog.getByText('Rule revision 6')).toBeInTheDocument()
})

test('a read-only user can inspect the redacted report without editing the policy', async () => {
  fixture([])
  renderApp('/planes/device', { me: { permissions: ['metrics.read', 'entities.read'] } })
  const triggers = await screen.findAllByRole('button', { name: 'Configuration policy' })
  fireEvent.click(triggers[0])
  const dialog = within(await screen.findByRole('dialog'))
  expect(await dialog.findByText('Violation')).toBeInTheDocument()
  expect(dialog.queryByRole('button', { name: 'Add rule' })).not.toBeInTheDocument()
})
