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

export interface ImportDiffItem {
  row_number: number
  object_kind: string
  external_id: string
  action: ImportChoice['action']
  target_entity_id?: string
  current_label?: string
  proposed_label?: string
  changed_fields: string[]
  unmapped_codes: string[]
}

export interface ImportDiffPage {
  context_id: string
  plan_id: string
  snapshot_hash: string
  review_hash: string
  row_count: number
  items: ImportDiffItem[]
  next_cursor?: number
}

export interface ImportChoice {
  row_number: number
  action: 'create' | 'update' | 'skip' | 'unmapped'
  target_entity_id?: string
}

export interface ImportConfigureResponse {
  source_id: string
}
export interface ImportStartResponse {
  plan_id: string
  state: string
}
export interface ImportAdvanceResponse {
  completed_stage: string
  next_stage: string
  pages: number
  rows: number
  snapshot_hash?: string
}
export interface ImportFinalizeResponse {
  state: 'preview'
  review_hash: string
}

const jsonInit = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export function configureImportSource(input: {
  context_id: string
  instance_ref: string
  https_origin: string
  credential_ref: string
}) {
  return apiFetch<ImportConfigureResponse>('/nms-imports/sources', jsonInit('POST', input))
}

export function startImportPlan(contextID: string, instanceRef: string) {
  return apiFetch<ImportStartResponse>(
    '/nms-imports/live-plans',
    jsonInit('POST', { context_id: contextID, instance_ref: instanceRef }),
  )
}

export function advanceImportPlan(contextID: string, planID: string) {
  return apiFetch<ImportAdvanceResponse>(
    `/nms-imports/${encodeURIComponent(planID)}/advance`,
    jsonInit('POST', { context_id: contextID }),
  )
}

export function importRows(contextID: string, planID: string, cursor?: number) {
  const query = new URLSearchParams({ context_id: contextID, limit: '50' })
  if (cursor !== undefined) query.set('cursor', String(cursor))
  return apiFetch<ImportRowsPage>(
    `/nms-imports/${encodeURIComponent(planID)}/rows?${query.toString()}`,
  )
}

export function importDiff(contextID: string, planID: string, reviewHash: string, cursor?: number) {
  const query = new URLSearchParams({ context_id: contextID, review_hash: reviewHash, limit: '50' })
  if (cursor !== undefined) query.set('cursor', String(cursor))
  return apiFetch<ImportDiffPage>(
    `/nms-imports/${encodeURIComponent(planID)}/dry-run?${query.toString()}`,
  )
}

export function setImportReviewChoices(
  contextID: string,
  planID: string,
  snapshotHash: string,
  choices: ImportChoice[],
) {
  return apiFetch<void>(
    `/nms-imports/${encodeURIComponent(planID)}/review-choices`,
    jsonInit('POST', { context_id: contextID, snapshot_hash: snapshotHash, choices }),
  )
}

export function finalizeImportReview(contextID: string, planID: string, snapshotHash: string) {
  return apiFetch<ImportFinalizeResponse>(
    `/nms-imports/${encodeURIComponent(planID)}/finalize-review`,
    jsonInit('POST', { context_id: contextID, snapshot_hash: snapshotHash }),
  )
}
