import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The carbon/power estimate API (S48 — folds into the Cost page as the ESG
 * sibling of FinOps). Everything here is a coefficient-based ESTIMATE; the
 * methodology block is the honesty contract and the UI shows it.
 */

export interface CarbonAgg {
  bytes: number
  kwh: number
  gco2e: number
}

export interface CarbonTrendPoint {
  hour: string
  kwh: number
  gco2e: number
}

export interface CarbonMethodology {
  measured: boolean
  source: string
  grid_gco2e_per_kwh: number
  note: string
}

export interface CarbonSummary {
  total_bytes: number
  total_kwh: number
  total_gco2e: number
  by_class: Record<string, CarbonAgg>
  by_service: Record<string, CarbonAgg>
  by_team: Record<string, CarbonAgg>
  trend: CarbonTrendPoint[]
  methodology: CarbonMethodology
}

export interface CarbonResponse {
  carbon_running: boolean
  summary?: CarbonSummary
}

export function useCarbon() {
  return useQuery({
    queryKey: ['carbon'],
    queryFn: () => apiFetch<CarbonResponse>('/v1/carbon'),
  })
}
