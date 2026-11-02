// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { apiFetch } from './client'

export interface ImportRow {
  row_number: number
  object_kind: string
  external_id: string
  label?: string
  address?: string
  location_label?: string
  unmapped_codes: string[]
  action: string
  target_entity_id?: string
  reviewed: boolean
}

export interface ImportRowsPage {
  context_id: string
  plan_id: string
  snapshot_hash: string
  row_count: number
  items: ImportRow[]
  next_cursor?: number
}

export interface ImportChoice {
  row_number: number
  action: 'create' | 'update' | 'skip' | 'unmapped'
  target_entity_id?: string
}

const jsonBody = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

const planPath = (planID: string) => `/nms-imports/${encodeURIComponent(planID)}`

export function configureImportSource(input: {
  context_id: string
  instance_ref: string
  https_origin: string
  credential_ref: string
}) {
  return apiFetch<{ source_id: string }>('/nms-imports/sources', jsonBody(input))
}

export function startImportPlan(contextID: string, instanceRef: string) {
  return apiFetch<{ plan_id: string; state: string }>(
    '/nms-imports/live-plans',
    jsonBody({ context_id: contextID, instance_ref: instanceRef }),
  )
}

export function advanceImportPlan(contextID: string, planID: string) {
  return apiFetch<{
    completed_stage: string
    next_stage: string
    pages: number
    rows: number
    snapshot_hash?: string
  }>(`${planPath(planID)}/advance`, jsonBody({ context_id: contextID }))
}

export function importRows(contextID: string, planID: string, cursor?: number) {
  const query = new URLSearchParams({ context_id: contextID, limit: '50' })
  if (cursor !== undefined) query.set('cursor', String(cursor))
  return apiFetch<ImportRowsPage>(`${planPath(planID)}/rows?${query.toString()}`)
}

export function setImportReviewChoices(
  contextID: string,
  planID: string,
  snapshotHash: string,
  choices: ImportChoice[],
) {
  return apiFetch<void>(
    `${planPath(planID)}/review-choices`,
    jsonBody({ context_id: contextID, snapshot_hash: snapshotHash, choices }),
  )
}

export function finalizeImportReview(contextID: string, planID: string, snapshotHash: string) {
  return apiFetch<{ state: 'preview'; review_hash: string }>(
    `${planPath(planID)}/finalize-review`,
    jsonBody({ context_id: contextID, snapshot_hash: snapshotHash }),
  )
}
