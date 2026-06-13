import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The collective internet-outage API (surface: S47a). External events come
 * from opt-in public feeds (IODA / Cloudflare Radar) and are annotated with
 * THIS tenant's affected tests; vantage events are detected from the
 * tenant's own synthetic results. coverage_notes is the honesty contract:
 * your vantage points + open data — not a global probe fleet.
 */

export type OutageScopeKind = 'asn' | 'country' | 'region' | 'unknown'

export interface OutageScope {
  kind: OutageScopeKind
  code: string
  name?: string
}

export interface AffectedTest {
  canary_type: string
  target: string
  failures: number
  last_failure: string
}

export interface OutageEvent {
  id: string
  source: 'ioda' | 'cloudflare_radar' | 'vantage'
  scope: OutageScope
  severity: 'info' | 'warning' | 'critical'
  confidence: number
  title: string
  summary?: string
  start: string
  end?: string
  evidence_url?: string
  ongoing: boolean
  affected_tests?: AffectedTest[]
}

export interface FeedHealth {
  name: string
  status: 'ok' | 'failed' | 'pending'
  last_success?: string
  last_error?: string
  events: number
  license: string
  attribution?: string
  commercial_use: string
  url: string
}

export interface OutagesResponse {
  outage_running: boolean
  feeds_enabled?: boolean
  scope_resolution?: boolean
  events?: OutageEvent[]
  vantage_events?: OutageEvent[]
  feeds?: FeedHealth[]
  coverage_notes?: string[]
}

export function useOutages() {
  return useQuery({
    queryKey: ['outages'],
    queryFn: () => apiFetch<OutagesResponse>('/outages'),
  })
}
