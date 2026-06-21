import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import { formatCurrencyUSD, formatGibibytes } from '../i18n/number'

/**
 * The FinOps cost API (surface: S44). Egress volume × public pricing,
 * attributed per service and team (showback), with chatty cross-AZ pairs,
 * hourly trend, and budget status. Honesty flags matter here more than
 * anywhere: priced=false means volume-only (no invented dollars);
 * zones_mapped=false means locality classes are unknown. Heavy dashboarding
 * is federated to Grafana via the S40 datasource; this view is the summary.
 */

export interface CostAgg {
  bytes: number
  usd: number
}

export interface ChattyPair {
  service: string
  src_zone: string
  dst_zone: string
  class: string
  bytes: number
  usd: number
  chatty: boolean
}

export interface BudgetStatus {
  kind: string
  name: string
  monthly_usd: number
  spent_usd: number
  exceeded: boolean
}

export interface TrendPoint {
  hour: string
  bytes: number
  usd: number
}

export interface CostSummary {
  priced: boolean
  zones_mapped: boolean
  pricing_source?: string
  pricing_as_of?: string
  total_bytes: number
  total_usd: number
  by_class: Record<string, CostAgg>
  by_service: Record<string, CostAgg>
  by_team: Record<string, CostAgg>
  chatty_pairs: ChattyPair[]
  trend: TrendPoint[]
  budgets: BudgetStatus[]
}

export interface CostResponse {
  cost_running: boolean
  summary?: CostSummary
}

export function useCostSummary() {
  return useQuery({
    queryKey: ['cost-summary'],
    queryFn: () => apiFetch<CostResponse>('/cost/summary'),
  })
}

/** gib renders bytes as GiB with sensible precision. */
export function gib(bytes: number, locale?: string): string {
  return formatGibibytes(bytes, locale)
}

/** usd renders dollars. */
export function usd(v: number, locale?: string): string {
  return formatCurrencyUSD(v, locale)
}
