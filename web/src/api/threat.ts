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

/** useDetections polls the tenant's recent detections (15s cadence). */
export function useDetections() {
  return useQuery({
    queryKey: ['threat', 'detections'],
    queryFn: () => apiFetch<DetectionsResponse>('/threat/detections'),
    refetchInterval: 15_000,
  })
}
