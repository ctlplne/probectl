import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The editions/license API (S-T0). Admin → Editions is the ONE place tiers
 * appear when unlicensed (the hidden-unlicensed UX): commercial features are
 * otherwise invisible without an entitlement. Expiry semantics: 30-day
 * grace, then read-only — never broken telemetry.
 */

export type EditionTier = 'community' | 'enterprise' | 'provider'
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
  state: EditionState
  customer?: string
  license_id?: string
  expires_at?: string
  read_only_at?: string
  tenant_band?: number
  features: FeatureInfo[]
  fips?: FIPSStatus
}

export function useEditions() {
  return useQuery({
    queryKey: ['editions'],
    queryFn: () => apiFetch<EditionsInfo>('/editions'),
  })
}
