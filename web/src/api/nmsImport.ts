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
  parent_external_id?: string
  poll_seconds?: number
  label?: string
  address?: string
  location_label?: string
  unmapped_codes: string[]
  action: string
  target_entity_id?: string
  reviewed: boolean
  state: 'pending' | 'applied' | 'skipped'
  applied_at?: string
  bound_entity_id?: string
  binding_plan_id?: string
}

export interface ImportRowsPage {
  context_id: string
  plan_id: string
  source_id: string
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
  current_poll_seconds?: number
  proposed_label?: string
  proposed_poll_seconds?: number
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
  action: 'create' | 'update' | 'remove' | 'skip' | 'unmapped'
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
export interface ImportVerificationResponse {
  verified_stage: string
  next_stage: string
  pages: number
  rows: number
  ready: boolean
}
export interface ImportApplyResponse {
  state: 'applying' | 'applied'
  applied: number
  skipped: number
  remaining: number
  row_count: number
  review_hash: string
}

export interface ImportPollTargetSelection {
  context_id: string
  source_id: string
  item_external_id: string
  agent_id: string
  target_address: string
}

export interface ImportPollTargetPreview extends ImportPollTargetSelection {
  tenant_id: string
  host_external_id: string
  entity_id: string
  poll_seconds: number
  plan_id: string
  revision: number
}

export interface ImportPollProposal {
  item_external_id: string
  host_external_id: string
  poll_seconds: number
  plan_id: string
  revision: number
  applied_at: string
}

export interface ImportPollProposalsPage {
  context_id: string
  source_id: string
  items: ImportPollProposal[]
  next_cursor?: string
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

export function previewImportPollTarget(input: ImportPollTargetSelection) {
  return apiFetch<ImportPollTargetPreview>(
    '/nms-imports/poll-target-preview',
    jsonInit('POST', input),
  )
}

export function importPollProposals(contextID: string, sourceID: string, cursor?: string) {
  const query = new URLSearchParams({ context_id: contextID, source_id: sourceID, limit: '50' })
  if (cursor !== undefined) query.set('cursor', cursor)
  return apiFetch<ImportPollProposalsPage>(`/nms-imports/poll-proposals?${query.toString()}`)
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

export function verifyImportBeforeApply(
  contextID: string,
  planID: string,
  snapshotHash: string,
  reviewHash: string,
) {
  return apiFetch<ImportVerificationResponse>(
    `/nms-imports/${encodeURIComponent(planID)}/verify-before-apply`,
    jsonInit('POST', {
      context_id: contextID,
      snapshot_hash: snapshotHash,
      review_hash: reviewHash,
    }),
  )
}

export function applyImportReview(
  contextID: string,
  planID: string,
  snapshotHash: string,
  reviewHash: string,
) {
  return apiFetch<ImportApplyResponse>(
    `/nms-imports/${encodeURIComponent(planID)}/apply`,
    jsonInit('POST', {
      context_id: contextID,
      snapshot_hash: snapshotHash,
      review_hash: reviewHash,
    }),
  )
}
