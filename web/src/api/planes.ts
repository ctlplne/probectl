import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export type FlowGroupBy = 'src' | 'dst' | 'pair' | 'src_asn' | 'dst_asn'

export interface FlowTopRow {
  key: string
  detail?: string
  bytes: number
  packets: number
  flows: number
  bytes_str?: string
  packets_str?: string
  flows_str?: string
}

export interface FlowTopResponse {
  items: FlowTopRow[]
  effective_limit?: number
  window?: string
}

export interface FlowCapacityPoint {
  ts: string
  exporter: string
  iface: number
  bps: number
  pps: number
}

export interface FlowCapacityResponse {
  items: FlowCapacityPoint[]
}

export interface FlowAnomaly {
  exporter: string
  iface: number
  ts: string
  current_bps: number
  baseline_bps: number
  stddev_bps: number
  sigma: number
}

export interface FlowAnomalyResponse {
  items: FlowAnomaly[]
}

export function useFlowTop(by: FlowGroupBy, window = '1h', limit = 10) {
  return useQuery({
    queryKey: ['flows', 'top', by, window, limit],
    queryFn: () =>
      apiFetch<FlowTopResponse>(
        `/flows/top?by=${encodeURIComponent(by)}&window=${encodeURIComponent(window)}&limit=${limit}`,
      ),
  })
}

export function useFlowCapacity(window = '1h', bucket = '5m') {
  return useQuery({
    queryKey: ['flows', 'capacity', window, bucket],
    queryFn: () =>
      apiFetch<FlowCapacityResponse>(
        `/flows/capacity?window=${encodeURIComponent(window)}&bucket=${encodeURIComponent(bucket)}`,
      ),
  })
}

export function useFlowAnomalies(window = '1h', bucket = '5m') {
  return useQuery({
    queryKey: ['flows', 'anomalies', window, bucket],
    queryFn: () =>
      apiFetch<FlowAnomalyResponse>(
        `/flows/anomalies?window=${encodeURIComponent(window)}&bucket=${encodeURIComponent(bucket)}`,
      ),
  })
}
