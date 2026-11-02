// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { defaultFetch, jsonResponse, pathOf } from './fetchStub'
import { renderApp } from './renderApp'

const contextID = '00000000-0000-4000-8000-000000000301'
const planID = '00000000-0000-4000-8000-000000000302'
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
      if (path === '/v1/me')
        return jsonResponse({
          tenant_id: '00000000-0000-4000-8000-000000000300',
          tenant_name: 'Import tenant',
          tenant_slug: 'import-tenant',
          user_id: 'u_import',
          email: 'operator@probectl.test',
          display_name: 'Import Operator',
          mfa_satisfied: true,
          permissions: ['agent.read', 'agent.write', 'nms.import.read', 'nms.import.write'],
        })
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
      if (path.includes('/apply')) destinationWrites++
      return fallback(input, init)
    }),
  )

  renderApp('/admin')
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
  expect(region.queryByText('source-only-secret')).toBeNull()
  await userEvent.selectOptions(region.getByLabelText('Choice for device 17'), 'unmapped')
  await userEvent.click(region.getByRole('button', { name: 'Save page choices' }))
  expect(await region.findByText(/1 explicit choice saved/)).toBeInTheDocument()
  await userEvent.click(region.getByRole('button', { name: 'Finalize dry run' }))
  expect(await region.findByText(new RegExp(reviewHash))).toBeInTheDocument()
  expect(destinationWrites).toBe(0)
  expect(
    requests.every(
      (request) => request.body.context_id === contextID || request.path.endsWith('/rows'),
    ),
  ).toBe(true)
  expect(requests.find((request) => request.path.endsWith('/review-choices'))?.body).toMatchObject({
    snapshot_hash: snapshotHash,
    choices: [{ row_number: 0, action: 'unmapped' }],
  })
})
