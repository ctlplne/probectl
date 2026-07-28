// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export type CoverageStatus = 'uncovered' | 'stale' | 'non_redundant' | 'covered'
export type CoverageReadiness = 'ready' | 'degraded' | 'unavailable'
export type ExecutionCadenceState = 'on_cadence' | 'gaps_observed' | 'never_observed' | 'unknown'
export type ExecutionCadenceReason =
  | 'on_cadence'
  | 'missed_rounds'
  | 'no_exact_test_evidence'
  | 'evidence_unwired'
  | 'legacy_or_unattributed_evidence'
  | 'legacy_schedule_metadata'
  | 'interval_mismatch'
  | 'history_truncated'
  | 'insufficient_history'
  | 'future_evidence_timestamp'
  | 'definition_mismatch'
  | 'invalid_configured_interval'

export interface ExecutionCadenceReceipt {
  state: ExecutionCadenceState
  reason: ExecutionCadenceReason
  attribution: 'none' | 'exact_test_id'
  configured_interval_seconds: number
  window_seconds: number
  expected_rounds: number
  observed_rounds: number
  missed_rounds: number
  max_gap_seconds: number
  observed_agent_count: number
  history_complete: boolean
  current_assignment_verified: boolean
}

export interface CoverageNextAction {
  kind: 'enroll_vantage' | 'author_test'
  label: string
  href: string
}

export interface CoverageMatrixItem {
  test_id: string
  test_name: string
  region: string
  site: string
  agent_readiness: CoverageReadiness
  agent_count: number
  ready_agent_count: number
  probe_family: string
  target: string
  last_evidence_at?: string
  independent_vantage_count: number
  stale_after_seconds: number
  status: CoverageStatus
  execution_cadence: ExecutionCadenceReceipt
  next_action?: CoverageNextAction
}

export interface CoverageMatrixResponse {
  items: CoverageMatrixItem[]
  as_of: string
  evidence_running: boolean
  candidate_limit: number
  truncated: boolean
}

export type CoverageDebtPlane = 'synthetic' | 'path' | 'flow' | 'routing' | 'device'
export type CoverageDebtState = 'covered' | 'stale' | 'uncovered' | 'unknown'
export type CoverageDebtEntityKind =
  | 'site'
  | 'agent'
  | 'hop'
  | 'host'
  | 'service'
  | 'prefix'
  | 'as'
  | 'device'

export interface CoverageDebtAction {
  kind: 'navigate'
  label: string
  href: '/targets' | '/topology'
}

export interface CoverageDebtItem {
  entity_id: string
  entity_kind: CoverageDebtEntityKind
  label: string
  region?: string
  site?: string
  plane: CoverageDebtPlane
  state: CoverageDebtState
  observed_at?: string
  evidence_age_seconds?: number
  stale_after_seconds: number
  evidence_basis: string
  evidence_ref?: string
  next_action: CoverageDebtAction
}

export interface CoverageDebtProducer {
  plane: CoverageDebtPlane
  registered_count: number
  runtime_running: boolean
  evidence_count: number
  status: 'observed' | 'idle' | 'unregistered' | 'unwired'
}

export interface CoverageDebtResponse {
  items: CoverageDebtItem[]
  producers: CoverageDebtProducer[]
  as_of: string
  stale_after_seconds: number
  entity_limit: number
  candidate_limit: number
  candidates_truncated: boolean
  results_truncated: boolean
  entities_truncated: boolean
  topology_truncated: boolean
  partial_reasons: string[]
}

/** Read-only local coverage derivation. The server resolves tenant before it
 * joins agent labels and test definitions; the browser supplies no tenant id. */
export function useCoverageMatrix() {
  return useQuery({
    queryKey: ['coverage', 'vantages'],
    queryFn: () => apiFetch<CoverageMatrixResponse>('/coverage/vantages'),
    refetchInterval: 30_000,
  })
}

/** Cross-plane debt is likewise tenant-resolved by the server. Covered is
 * evidence-based; registrations and topology presence alone never turn green. */
export function useCoverageDebt() {
  return useQuery({
    queryKey: ['coverage', 'debt'],
    queryFn: () => apiFetch<CoverageDebtResponse>('/coverage/debt'),
    refetchInterval: 30_000,
  })
}
