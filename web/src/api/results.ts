import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

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
