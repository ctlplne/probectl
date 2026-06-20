import { useQuery } from '@tanstack/react-query'
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

interface EndpointsResponse {
  items: EndpointView[]
  collector_running: boolean
}

/** useEndpoints polls the tenant's DEM fleet (30s cadence). */
export function useEndpoints() {
  return useQuery({
    queryKey: ['endpoints'],
    queryFn: () => apiFetch<EndpointsResponse>('/endpoints'),
    refetchInterval: 30_000,
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
