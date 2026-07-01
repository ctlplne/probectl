import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Severity } from './incidents'

/**
 * The threat-detection triage API (surface: S-FE3, fed by S28 IOC matches and
 * later S42 NDR detections). A Detection is a confidence-scored SIGNAL with
 * verbatim source attribution — probectl never blocks, and feeds can list
 * benign infrastructure, so the surface renders provenance honestly.
 */

export interface Detection {
  id: string
  kind: string
  plane: string
  severity: Severity
  confidence?: number
  source?: string
  category?: string
  type?: string
  license?: string
  indicator?: string
  entity: string
  title: string
  summary?: string
  incident_id?: string
  observed_at: string
}

interface DetectionsResponse {
  items: Detection[]
  detections_running: boolean
}

export interface SourceAUP {
  license: string
  url: string
  attribution: string
  commercial_use: string
  redistribution: string
}

export interface OpenDataSourceStatus {
  name: string
  kind: string
  cadence_seconds: number
  aup: SourceAUP
  enabled: boolean
  status: string
  last_success: string
  last_error: string
}

export interface ThreatIntelFeedStatus extends OpenDataSourceStatus {
  ioc_count: number
}

export interface ThreatIntelStatusResponse {
  open_data_enabled: boolean
  threat_intel_enabled: boolean
  ioc_count: number
  open_data_sources: OpenDataSourceStatus[]
  threat_intel_feeds: ThreatIntelFeedStatus[]
}

/** useDetections polls the tenant's recent detections (15s cadence). */
export function useDetections() {
  return useQuery({
    queryKey: ['threat', 'detections'],
    queryFn: () => apiFetch<DetectionsResponse>('/threat/detections'),
    refetchInterval: 15_000,
  })
}

/** useThreatIntelStatus polls the shared feed AUP + last-good health matrix. */
export function useThreatIntelStatus() {
  return useQuery({
    queryKey: ['threat', 'intel-status'],
    queryFn: () => apiFetch<ThreatIntelStatusResponse>('/threat/intel/status'),
    refetchInterval: 60_000,
  })
}
