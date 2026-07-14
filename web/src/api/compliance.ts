// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The compliance / segmentation-validation API (surface: S46). Verdicts are
 * over OBSERVED traffic only: "violation" (forbidden traffic seen, with flow
 * evidence), "observed_clean" (zone traffic seen, none in the forbidden
 * scope), "not_observed" (nothing seen — explicitly NOT proof of isolation).
 * The coverage block is the never-overclaim contract; the evidence export is
 * hash-chained and audit-grade.
 */

export type Verdict = 'violation' | 'observed_clean' | 'not_observed'

export interface ViolationSample {
  src: string
  dst: string
  dst_port: number
  bytes: number
  source: string
  at: string
}

export interface RuleResult {
  policy: string
  rule_id: string
  description?: string
  from: string
  to: string
  ports: string
  frameworks?: Record<string, string>
  verdict: Verdict
  violations: number
  observed_pairs: number
  samples?: ViolationSample[]
  first_violated?: string
  last_violated?: string
}

export interface ComplianceCoverage {
  flow_observed: boolean
  ebpf_observed: boolean
  observations: number
  zones_seen: number
  zones_total: number
  notes: string[]
}

export interface ComplianceResponse {
  compliance_running: boolean
  items: RuleResult[]
  coverage?: ComplianceCoverage
}

export function useCompliance() {
  return useQuery({
    queryKey: ['compliance'],
    queryFn: () => apiFetch<ComplianceResponse>('/compliance'),
  })
}
