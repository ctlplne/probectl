// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export type CoverageStatus = 'uncovered' | 'stale' | 'non_redundant' | 'covered'
export type CoverageReadiness = 'ready' | 'degraded' | 'unavailable'

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
  next_action?: CoverageNextAction
}

export interface CoverageMatrixResponse {
  items: CoverageMatrixItem[]
  as_of: string
  evidence_running: boolean
  candidate_limit: number
  truncated: boolean
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
