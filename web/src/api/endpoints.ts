import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * The endpoint DEM API (surface: S-FE4, fed by S37). Each endpoint view is the
 * latest WiFi/gateway/last-mile/session state plus the slowdown attribution.
 * Privacy is upstream and absolute: fields the agent withheld (SSID, gateway
 * IP, public hops, ...) are ABSENT — the UI renders absence as "withheld",
 * never a fabricated value.
 */

export interface DEMResult {
  type: string
  target?: string
  success: boolean
  error?: string
  metrics?: Record<string, number>
  attributes?: Record<string, string>
  observed_at: string
}

export type AttributionCause = 'none' | 'wifi' | 'local' | 'isp' | 'network' | 'unknown'

export interface EndpointView {
  agent_id: string
  last_seen_at: string
  cause?: string
  summary?: string
  confidence?: number
  slow: boolean
  attribution?: DEMResult
  wifi?: DEMResult
  gateway?: DEMResult
  last_mile?: DEMResult
  sessions?: DEMResult[]
}

export interface EndpointsResponse {
  items: EndpointView[]
  collector_running: boolean
}

export interface EndpointFilters {
  q?: string
  cause?: string
}

export interface SavedInventoryView {
  id: string
  tenant_id: string
  surface: 'endpoints'
  name: string
  filters: Record<string, string>
  created_at: string
  updated_at: string
}

export interface EndpointSavedViewsResponse {
  items: SavedInventoryView[]
}

export interface SavedInventoryViewInput {
  surface: 'endpoints'
  name: string
  filters: Record<string, string>
}

/** useEndpoints polls the tenant's DEM fleet (30s cadence). */
export function useEndpoints(filters: EndpointFilters = {}) {
  return useQuery({
    queryKey: ['endpoints', filters],
    queryFn: () => {
      const params = new URLSearchParams()
      if (filters.q?.trim()) params.set('q', filters.q.trim())
      if (filters.cause && filters.cause !== 'all') params.set('cause', filters.cause)
      return apiFetch<EndpointsResponse>(`/endpoints?${params.toString()}`)
    },
    refetchInterval: 30_000,
  })
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

/** useEndpointSavedViews lists tenant-owned saved views for the endpoint fleet. */
export function useEndpointSavedViews() {
  return useQuery({
    queryKey: ['inventory', 'views', 'endpoints'],
    queryFn: () => apiFetch<EndpointSavedViewsResponse>('/inventory/views?surface=endpoints'),
  })
}

/** useCreateEndpointSavedView saves the current endpoint inventory filters. */
export function useCreateEndpointSavedView() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: SavedInventoryViewInput) =>
      apiFetch<SavedInventoryView>('/inventory/views', jsonInit('POST', input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['inventory', 'views', 'endpoints'] }),
  })
}

/** causeLabel renders an attribution cause as the operator-facing phrase. */
export function causeLabel(cause?: string): string {
  switch (cause) {
    case 'none':
      return 'healthy'
    case 'wifi':
      return 'WiFi'
    case 'local':
      return 'local network'
    case 'isp':
      return 'ISP / last mile'
    case 'network':
      return 'network / service'
    case 'unknown':
      return 'unknown'
    default:
      return cause ?? '—'
  }
}

/** causeTone maps a cause to a badge tone: the user-side layers read as
 *  warnings ("it's your WiFi"), the network side as danger ("it's on us"). */
export function causeTone(
  cause?: string,
  slow?: boolean,
): 'success' | 'warning' | 'danger' | 'neutral' {
  if (!slow || cause === 'none') return 'success'
  if (cause === 'wifi' || cause === 'local' || cause === 'isp') return 'warning'
  if (cause === 'network') return 'danger'
  return 'neutral'
}

/** metric reads a metric that may legitimately be absent (graceful degradation
 *  — the agent only reports what the OS exposed). */
export function metric(r: DEMResult | undefined, key: string): number | undefined {
  const v = r?.metrics?.[key]
  return typeof v === 'number' ? v : undefined
}

/** attr reads an attribute that may be privacy-withheld. */
export function attr(r: DEMResult | undefined, key: string): string | undefined {
  return r?.attributes?.[key]
}
