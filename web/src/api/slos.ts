// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import { formatRatioPercent } from '../i18n/number'

/**
 * The SLO API (surface: S45). OpenSLO-defined SLIs tracked per tenant:
 * attainment vs objective, error budget remaining, and the multi-window
 * burn rates (Google SRE method) with per-window firing state. cold_start
 * means the SLO lacks enough history to judge — honesty, not health.
 */

export interface BurnRate {
  window: string
  long: string
  short: string
  burn: number
  limit: number
  firing: boolean
}

export interface SLOStatus {
  name: string
  display_name?: string
  service: string
  team?: string
  objective: number
  window: string
  attainment: number
  error_budget_remaining: number
  total_events: number
  cold_start: boolean
  burn_rates: BurnRate[]
}

export interface SLOsResponse {
  slo_running: boolean
  items: SLOStatus[]
  /** When this tenant's in-memory evaluation window opened. */
  data_since?: string
}

export function useSLOs() {
  return useQuery({
    queryKey: ['slos'],
    queryFn: () => apiFetch<SLOsResponse>('/slos'),
  })
}

/** pct renders a ratio as a percentage with SLO-grade precision. */
export function pct(v: number, locale?: string): string {
  const digits = v >= 0.999 ? 3 : 2
  return formatRatioPercent(v, locale, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })
}
