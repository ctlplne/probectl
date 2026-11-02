// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { cleanup, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const contextID = '00000000-0000-4000-8000-000000000301'
const planID = '00000000-0000-4000-8000-000000000302'
const sourceID = '00000000-0000-4000-8000-000000000305'
const snapshotHash = 'a'.repeat(64)
const reviewHash = 'b'.repeat(64)

test('Admin import requires explicit tenant-context review before an inert dry run', async () => {
  const fallback = defaultFetch()
  let reviewed = false
  let destinationWrites = 0
  const requests: Array<{ path: string; body: Record<string, unknown> }> = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input)
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {}
      if (path.startsWith('/v1/nms-imports/')) requests.push({ path, body })
      if (path === '/v1/entity-contexts')
        return jsonResponse({
          items: [
            {
              context_id: contextID,
              site_id: contextID,
              vrf_id: contextID,
              site_label: 'West DC',
              vrf_label: 'Private',
            },
          ],
        })
      if (path === '/v1/nms-imports/sources') return jsonResponse({ source_id: planID }, 201)
      if (path === '/v1/nms-imports/live-plans')
        return jsonResponse({ plan_id: planID, state: 'capturing' }, 201)
      if (path === `/v1/nms-imports/${planID}/advance`)
        return jsonResponse({
          completed_stage: 'complete',
          next_stage: 'sealed',
          pages: 1,
          rows: 1,
          snapshot_hash: snapshotHash,
        })
      if (path === `/v1/nms-imports/${planID}/rows`)
        return jsonResponse({
          context_id: contextID,
          plan_id: planID,
          source_id: sourceID,
          snapshot_hash: snapshotHash,
          row_count: 1,
          items: [
            {
              row_number: 0,
              object_kind: 'device',
              external_id: '17',
              label: 'Edge R1',
              address: '10.42.0.1',
              unmapped_codes: ['site_unmapped'],
              action: reviewed ? 'unmapped' : 'captured',
              reviewed,
              state: destinationWrites > 0 ? 'skipped' : 'pending',
            },
          ],
        })
      if (path === `/v1/nms-imports/${planID}/review-choices`) {
        reviewed = true
        return new Response(null, { status: 204 })
      }
      if (path === `/v1/nms-imports/${planID}/finalize-review`)
        return jsonResponse({
          state: 'preview',
          review_hash: reviewHash,
        })
      if (path === `/v1/nms-imports/${planID}/dry-run`)
        return jsonResponse({
          context_id: contextID,
          plan_id: planID,
          snapshot_hash: snapshotHash,
          review_hash: reviewHash,
          row_count: 1,
          items: [
            {
              row_number: 0,
              object_kind: 'device',
              external_id: '17',
              action: 'unmapped',
              changed_fields: [],
              unmapped_codes: ['site_unmapped'],
            },
          ],
        })
      if (path === `/v1/nms-imports/${planID}/verify-before-apply`)
        return jsonResponse({
          verified_stage: 'rules',
          next_stage: 'ready',
          pages: 1,
          rows: 1,
          ready: true,
        })
      if (path === `/v1/nms-imports/${planID}/apply`) {
        destinationWrites++
        return jsonResponse({
          state: 'applied',
          applied: 0,
          skipped: 1,
          remaining: 0,
          row_count: 1,
          review_hash: reviewHash,
        })
      }
      if (path.includes('/apply')) destinationWrites++
      return fallback(input, init)
    }),
  )

  renderApp('/admin', {
    me: {
      tenant_id: '00000000-0000-4000-8000-000000000300',
      permissions: ['agent.read', 'agent.write', 'nms.import.read', 'nms.import.write'],
    },
  })
  const card = (await screen.findByText('Incumbent NMS import')).closest('[data-nms-import]')
  expect(card).not.toBeNull()
  const region = within(card as HTMLElement)
  expect(await region.findByText('West DC / Private', { selector: 'strong' })).toBeInTheDocument()
  await userEvent.type(await region.findByLabelText('Source instance'), 'lab')
  await userEvent.type(region.getByLabelText('HTTPS origin'), 'https://nms.example.test')
  await userEvent.type(
    region.getByLabelText('Credential reference'),
    'vault:probectl/nms/tenant/token',
  )
  await userEvent.click(region.getByRole('button', { name: 'Configure source' }))
  expect(await region.findByText(/Source configured in this routing context/)).toBeInTheDocument()
  expect(region.getByLabelText('Credential reference')).toHaveValue('')
  await userEvent.click(region.getByRole('button', { name: 'Start inert plan' }))
  expect(await region.findByText(/Inert capture plan started/)).toBeInTheDocument()
  await userEvent.click(region.getByRole('button', { name: 'Advance one endpoint' }))
  const rows = await region.findByRole('table', { name: 'Import source rows' })
  expect(within(rows).getByText('site_unmapped')).toBeInTheDocument()
  expect(within(rows).getByText('10.42.0.1', { exact: false })).toBeInTheDocument()
  expect(within(rows).getByText('pending')).toBeInTheDocument()
  expect(region.getByText(sourceID)).toBeInTheDocument()
  expect(region.queryByText('source-only-secret')).toBeNull()
  await userEvent.selectOptions(region.getByLabelText('Choice for device 17'), 'unmapped')
  await userEvent.click(region.getByRole('button', { name: 'Save page choices' }))
  expect(await region.findByText(/1 explicit choice saved/)).toBeInTheDocument()
  await userEvent.click(region.getByRole('button', { name: 'Finalize dry run' }))
  expect(await region.findByText(new RegExp(reviewHash))).toBeInTheDocument()
  expect(
    await region.findByRole('table', { name: 'Import destination comparison' }),
  ).toBeInTheDocument()
  expect(destinationWrites).toBe(0)
  expect(
    requests.every(
      (request) =>
        request.body.context_id === contextID ||
        request.path.endsWith('/rows') ||
        request.path.endsWith('/dry-run'),
    ),
  ).toBe(true)
  expect(requests.some((request) => request.path.endsWith('/dry-run'))).toBe(true)
  expect(requests.find((request) => request.path.endsWith('/review-choices'))?.body).toMatchObject({
    snapshot_hash: snapshotHash,
    choices: [{ row_number: 0, action: 'unmapped' }],
  })
  expect(region.getByRole('button', { name: 'Apply one reviewed chunk' })).toBeDisabled()
  await userEvent.click(region.getByRole('button', { name: 'Recheck next source endpoint' }))
  expect(await region.findByText(/Source recheck complete/)).toBeInTheDocument()
  await userEvent.click(region.getByRole('button', { name: 'Apply one reviewed chunk' }))
  expect(await region.findByText(/Import complete/)).toBeInTheDocument()
  expect(within(rows).getByText('skipped')).toBeInTheDocument()
  expect(destinationWrites).toBe(1)
  expect(requests.find((request) => request.path.endsWith('/apply'))?.body).toMatchObject({
    context_id: contextID,
    snapshot_hash: snapshotHash,
    review_hash: reviewHash,
  })

  cleanup()
  const blueContextID = '00000000-0000-4000-8000-000000000303'
  const blueFallback = defaultFetch()
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === '/v1/entity-contexts')
      return Promise.resolve(
        jsonResponse({
          items: [
            {
              context_id: blueContextID,
              site_id: blueContextID,
              vrf_id: blueContextID,
              site_label: 'East DC',
              vrf_label: 'Private',
            },
          ],
        }),
      )
    return blueFallback(input, init)
  })
  renderApp('/admin', {
    me: {
      tenant_id: '00000000-0000-4000-8000-000000000304',
      permissions: ['nms.import.read', 'nms.import.write'],
    },
  })
  const blueCard = (await screen.findByText('Incumbent NMS import')).closest('[data-nms-import]')
  const blueRegion = within(blueCard as HTMLElement)
  expect(
    await blueRegion.findByText('East DC / Private', { selector: 'strong' }),
  ).toBeInTheDocument()
  expect(blueRegion.queryByText('Edge R1')).toBeNull()
  expect(blueRegion.getByLabelText('Source instance')).toHaveValue('')
  expect(blueRegion.getByLabelText('Import plan ID')).toHaveValue('')
})

test('Admin review can refresh an exact source group without an entity target', async () => {
  const fallback = defaultFetch()
  let saved: Record<string, unknown> | null = null
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            context_id: contextID,
            site_id: contextID,
            vrf_id: contextID,
            site_label: 'West DC',
            vrf_label: 'Private',
          },
        ],
      })
    if (path === `/v1/nms-imports/${planID}/rows`)
      return jsonResponse({
        context_id: contextID,
        plan_id: planID,
        source_id: sourceID,
        snapshot_hash: snapshotHash,
        row_count: 1,
        items: [
          {
            row_number: 0,
            object_kind: 'group',
            external_id: '7',
            label: 'WAN Transit',
            unmapped_codes: ['group_unmapped'],
            action: saved ? 'update' : 'captured',
            reviewed: saved !== null,
            state: 'pending',
          },
        ],
      })
    if (path === `/v1/nms-imports/${planID}/review-choices`) {
      saved = JSON.parse(String(init?.body)) as Record<string, unknown>
      return new Response(null, { status: 204 })
    }
    return fallback(input, init)
  })

  renderApp('/admin', {
    me: {
      tenant_id: '00000000-0000-4000-8000-000000000300',
      permissions: ['nms.import.read', 'nms.import.write'],
    },
  })
  const card = (await screen.findByText('Incumbent NMS import')).closest('[data-nms-import]')
  const region = within(card as HTMLElement)
  expect(await region.findByText('West DC / Private', { selector: 'strong' })).toBeInTheDocument()
  await userEvent.type(region.getByLabelText('Import plan ID'), planID)
  await userEvent.click(region.getByRole('button', { name: 'Load redacted rows' }))
  expect(await region.findByText(/WAN Transit/)).toBeInTheDocument()
  await userEvent.selectOptions(region.getByLabelText('Choice for group 7'), 'update')
  expect(region.queryByLabelText('Exact target entity ID for 7')).toBeNull()
  await userEvent.click(region.getByRole('button', { name: 'Save page choices' }))
  expect(await region.findByText(/1 explicit choice saved/)).toBeInTheDocument()
  expect(saved).toMatchObject({
    context_id: contextID,
    snapshot_hash: snapshotHash,
    choices: [{ row_number: 0, action: 'update', target_entity_id: '' }],
  })
})

test('Admin offers removal only for a generated member candidate', async () => {
  const fallback = defaultFetch()
  let saved: Record<string, unknown> | null = null
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            context_id: contextID,
            site_id: contextID,
            vrf_id: contextID,
            site_label: 'West DC',
            vrf_label: 'Private',
          },
        ],
      })
    if (path === `/v1/nms-imports/${planID}/rows`)
      return jsonResponse({
        context_id: contextID,
        plan_id: planID,
        source_id: sourceID,
        snapshot_hash: snapshotHash,
        row_count: 2,
        items: [
          {
            row_number: 0,
            object_kind: 'membership',
            external_id: '7:17',
            unmapped_codes: ['group_unmapped'],
            action: 'captured',
            reviewed: false,
            state: 'pending',
          },
          {
            row_number: 1,
            object_kind: 'membership',
            external_id: '7:18',
            unmapped_codes: ['member_removal_candidate'],
            action: 'captured',
            reviewed: false,
            state: 'pending',
          },
        ],
      })
    if (path === `/v1/nms-imports/${planID}/review-choices`) {
      saved = JSON.parse(String(init?.body)) as Record<string, unknown>
      return new Response(null, { status: 204 })
    }
    return fallback(input, init)
  })
  renderApp('/admin', {
    me: {
      tenant_id: '00000000-0000-4000-8000-000000000300',
      permissions: ['nms.import.read', 'nms.import.write'],
    },
  })
  const card = (await screen.findByText('Incumbent NMS import')).closest('[data-nms-import]')
  const region = within(card as HTMLElement)
  expect(await region.findByText('West DC / Private', { selector: 'strong' })).toBeInTheDocument()
  await userEvent.type(region.getByLabelText('Import plan ID'), planID)
  await userEvent.click(region.getByRole('button', { name: 'Load redacted rows' }))
  const ordinary = await region.findByLabelText('Choice for membership 7:17')
  const removal = region.getByLabelText('Choice for membership 7:18')
  expect(within(ordinary).queryByRole('option', { name: 'Remove exact member' })).toBeNull()
  await userEvent.selectOptions(removal, 'remove')
  await userEvent.click(region.getByRole('button', { name: 'Save page choices' }))
  expect(await region.findByText(/1 explicit choice saved/)).toBeInTheDocument()
  expect(saved).toMatchObject({
    context_id: contextID,
    snapshot_hash: snapshotHash,
    choices: [{ row_number: 1, action: 'remove' }],
  })
})

test('Admin alert review creates only the exact disabled target and clears it across tenants', async () => {
  const fallback = defaultFetch()
  const entityID = '00000000-0000-4000-8000-000000000306'
  const alertID = '00000000-0000-4000-8000-000000000307'
  let previewBody: Record<string, unknown> | null = null
  let applyBody: Record<string, unknown> | null = null
  const preview = {
    tenant_id: '00000000-0000-4000-8000-000000000300',
    context_id: contextID,
    source_id: sourceID,
    rule_external_id: '31',
    device_external_id: '17',
    entity_id: entityID,
    agent_id: 'agent-1',
    target_address: '192.0.2.44',
    plan_id: planID,
    snapshot_hash: snapshotHash,
    name: 'Port down',
    severity: 'critical',
    rule_kind: 'port_down',
    enabled: false,
  }
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = pathOf(input)
    if (path === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            context_id: contextID,
            site_id: contextID,
            vrf_id: contextID,
            site_label: 'West DC',
            vrf_label: 'Private',
          },
        ],
      })
    if (path === `/v1/nms-imports/${planID}/rows`)
      return jsonResponse({
        context_id: contextID,
        plan_id: planID,
        source_id: sourceID,
        snapshot_hash: snapshotHash,
        row_count: 1,
        items: [
          {
            row_number: 0,
            object_kind: 'alert_rule',
            external_id: '31',
            parent_external_id: '17',
            label: 'Port down',
            unmapped_codes: ['expression_unmapped'],
            action: 'unmapped',
            reviewed: true,
            state: 'skipped',
          },
        ],
      })
    if (path === '/v1/nms-imports/alert-target-preview') {
      previewBody = JSON.parse(String(init?.body)) as Record<string, unknown>
      return jsonResponse(preview)
    }
    if (path === '/v1/nms-imports/alert-target-apply') {
      applyBody = JSON.parse(String(init?.body)) as Record<string, unknown>
      return jsonResponse({ alert_rule_id: alertID, created: true }, 201)
    }
    return fallback(input, init)
  })
  renderApp('/admin', {
    me: {
      tenant_id: preview.tenant_id,
      permissions: ['nms.import.read', 'nms.import.write', 'entities.read', 'alert.write'],
    },
  })
  const card = (await screen.findByText('Incumbent NMS import')).closest('[data-nms-import]')
  const region = within(card as HTMLElement)
  expect(await region.findByText('West DC / Private', { selector: 'strong' })).toBeInTheDocument()
  await userEvent.type(region.getByLabelText('Import plan ID'), planID)
  await userEvent.click(region.getByRole('button', { name: 'Load redacted rows' }))
  expect(await region.findByText(/Port down/)).toBeInTheDocument()
  await userEvent.type(region.getByLabelText('Source rule ID'), '31')
  await userEvent.type(region.getByLabelText('Alert agent ID'), 'agent-1')
  await userEvent.type(region.getByLabelText('Alert target address'), '192.0.2.44')
  await userEvent.click(region.getByRole('button', { name: 'Verify alert target' }))
  expect(await region.findByText(/It will be disabled with no/)).toBeInTheDocument()
  expect(previewBody).toEqual({
    context_id: contextID,
    source_id: sourceID,
    rule_external_id: '31',
    agent_id: 'agent-1',
    target_address: '192.0.2.44',
  })
  expect(applyBody).toBeNull()
  await userEvent.click(region.getByRole('button', { name: 'Create disabled alert' }))
  expect(await region.findByText(/created disabled/)).toBeInTheDocument()
  expect(applyBody).toEqual({
    context_id: contextID,
    source_id: sourceID,
    rule_external_id: '31',
    agent_id: 'agent-1',
    target_address: '192.0.2.44',
    plan_id: planID,
    snapshot_hash: snapshotHash,
    entity_id: entityID,
  })

  cleanup()
  const otherContext = '00000000-0000-4000-8000-000000000308'
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    if (pathOf(input) === '/v1/entity-contexts')
      return jsonResponse({
        items: [
          {
            context_id: otherContext,
            site_id: otherContext,
            vrf_id: otherContext,
            site_label: 'East DC',
            vrf_label: 'Private',
          },
        ],
      })
    return fallback(input, init)
  })
  renderApp('/admin', {
    me: {
      tenant_id: '00000000-0000-4000-8000-000000000304',
      permissions: ['nms.import.read', 'nms.import.write', 'entities.read'],
    },
  })
  const otherCard = (await screen.findByText('Incumbent NMS import')).closest('[data-nms-import]')
  const otherRegion = within(otherCard as HTMLElement)
  expect(
    await otherRegion.findByText('East DC / Private', { selector: 'strong' }),
  ).toBeInTheDocument()
  expect(otherRegion.queryByText(alertID)).toBeNull()
  expect(otherRegion.getByLabelText('Import plan ID')).toHaveValue('')
  expect(otherRegion.queryByRole('button', { name: 'Create disabled alert' })).toBeNull()
})
