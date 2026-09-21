// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useQuery } from '@tanstack/react-query'
import { apiFetch, isApiStatus } from './client'

/**
 * The latest-synthetic-result API (surface: S-FE5). One entry per (type,
 * target, agent) carrying the FULL per-type detail — DNS rcode/answers/DNSSEC,
 * the HTTP dns/connect/tls/ttfb waterfall, browser transaction step timings,
 * and ICMP/TCP/UDP latency families + loss — so every test type renders
 * first-class, never as raw JSON.
 */

export interface LatestResult {
  agent_id: string
  type: string
  target?: string
  success: boolean
  error?: string
  duration_ms?: number
  metrics?: Record<string, number>
  attributes?: Record<string, string>
  observed_at: string
}

interface LatestResultsResponse {
  items: LatestResult[]
  collector_running: boolean
}

/** useLatestResults polls the tenant's newest results (15s cadence). */
export function useLatestResults() {
  return useQuery({
    queryKey: ['results', 'latest'],
    queryFn: () => apiFetch<LatestResultsResponse>('/results/latest'),
    refetchInterval: 15_000,
  })
}

export interface ResultsHistoryResponse {
  items: LatestResult[]
  collector_running: boolean
  window: string
}

/** useResultsHistory returns the trailing-window result series (oldest
 * first) behind real-time-axis trends. A 404 means an older control plane
 * without the endpoint — callers fall back to the latest snapshot, so the
 * miss is authoritative and never retried. */
export function useResultsHistory(window = '1h') {
  return useQuery({
    queryKey: ['results', 'history', window],
    queryFn: () =>
      apiFetch<ResultsHistoryResponse>(`/results/history?window=${encodeURIComponent(window)}`),
    refetchInterval: 30_000,
    retry: (failureCount, error) => !isApiStatus(error, 404) && failureCount < 1,
  })
}

/** m reads an optional metric. */
export function m(r: LatestResult, key: string): number | undefined {
  const v = r.metrics?.[key]
  return typeof v === 'number' ? v : undefined
}

/** a reads an optional attribute. */
export function a(r: LatestResult, key: string): string | undefined {
  return r.attributes?.[key]
}

/** latencyFamily returns the latency metric prefix a type uses ("rtt" for
 *  icmp/udp, "connect" for tcp), or null when the type has no latency family. */
export function latencyFamily(type: string): 'rtt' | 'connect' | null {
  if (type === 'icmp' || type === 'udp') return 'rtt'
  if (type === 'tcp') return 'connect'
  return null
}
