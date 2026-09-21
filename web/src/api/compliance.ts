// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

interface ComplianceWireResponse {
  compliance_running: boolean
  items?: RuleResult[] | null
  coverage?: (Omit<ComplianceCoverage, 'notes'> & { notes?: string[] | null }) | null
}

export function normalizeComplianceResponse(response: ComplianceWireResponse): ComplianceResponse {
  return {
    ...response,
    items: response.items ?? [],
    coverage: response.coverage
      ? {
          ...response.coverage,
          notes: response.coverage.notes ?? [],
        }
      : undefined,
  }
}

export function useCompliance() {
  return useQuery({
    queryKey: ['compliance'],
    queryFn: async () =>
      normalizeComplianceResponse(await apiFetch<ComplianceWireResponse>('/compliance')),
  })
}
