// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The editions/license API (S-T0). Admin → Editions is the ONE place tiers
 * appear when unlicensed (the hidden-unlicensed UX): commercial features are
 * otherwise invisible without an entitlement. Expiry semantics: 30-day
 * grace, then read-only — never broken telemetry.
 */

export type EditionTier = 'core' | 'enterprise' | 'msp'
export type PricingModel = 'flat' | 'consumption'
export type EditionState = 'community' | 'active' | 'grace' | 'read_only'
export type FeatureMode = 'enabled' | 'read_only' | 'off'

export interface FeatureInfo {
  name: string
  display_name?: string
  tier: EditionTier
  licensed: boolean
  mode: FeatureMode
}

export interface FIPSStatus {
  build_tag: boolean
  module_active: boolean
  enforced: boolean
  module_version?: string
  self_test_passed: boolean
}

export interface EditionsInfo {
  tier: EditionTier
  pricing_model?: PricingModel
  state: EditionState
  customer?: string
  license_id?: string
  expires_at?: string
  read_only_at?: string
  tenant_band?: number
  meters?: string[]
  /** How many license signing keys this build trusts; 0 = keyless build (DPR-001). */
  trust_anchors?: number
  features: FeatureInfo[]
  fips?: FIPSStatus
}

export function useEditions(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['editions'],
    queryFn: () => apiFetch<EditionsInfo>('/editions'),
    enabled: options?.enabled ?? true,
    // The shell banner reads this on every load: never retry (a 403/404 is an
    // authoritative "no banner"), and one fetch per 5 minutes is plenty.
    retry: false,
    staleTime: 5 * 60_000,
  })
}
