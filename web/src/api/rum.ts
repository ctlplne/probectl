import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The RUM convergence API (surface: S47b — folds into the endpoint/DEM view,
 * no standalone screen). Verdicts are deliberate honesty wording: claims
 * cover what probectl OBSERVED — "no user impact observed" is not "no user
 * impact", and absence of RUM data is not proof of health. The privacy block
 * reports the server-ENFORCED posture (consent, redaction, no IP storage).
 */

export type RUMVerdict =
  | 'healthy'
  | 'user_impact_confirmed'
  | 'synthetic_only_no_user_impact'
  | 'user_only_synthetic_blind'

export interface RUMPageStats {
  page: string
  views: number
  error_rate: number
  p75_lcp_ms?: number
  p75_ttfb_ms?: number
}

export interface RUMAppStatus {
  app: string
  host: string
  window_views: number
  error_rate: number
  p75_lcp_ms?: number
  p75_ttfb_ms?: number
  rum_degraded: boolean
  synthetic_observed: boolean
  synthetic_degraded: boolean
  verdict: RUMVerdict
  pages: RUMPageStats[]
}

export interface RUMPrivacy {
  consent_required: boolean
  url_redaction: boolean
  ip_stored: boolean
  rejected_no_consent: number
  rejected_malformed: number
  rejected_invalid_field: number
  accepted_page_views: number
}

export interface RUMResponse {
  rum_running: boolean
  apps?: RUMAppStatus[]
  privacy?: RUMPrivacy
  coverage_notes?: string[]
}

export function useRUM() {
  return useQuery({
    queryKey: ['rum'],
    queryFn: () => apiFetch<RUMResponse>('/rum'),
  })
}
