// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export type FlowGroupBy =
  | 'src'
  | 'dst'
  | 'pair'
  | 'src_asn'
  | 'dst_asn'
  | 'as_name'
  | 'src_country'
  | 'dst_country'
  | 'port'
  | 'protocol'
  | 'exporter'

export type FlowFilterField = Exclude<FlowGroupBy, 'pair'>

export interface FlowFilter {
  field: FlowFilterField
  value: string
}

export interface FlowTopRow {
  key: string
  detail?: string
  bytes: number
  packets: number
  flows: number
}

export interface FlowTopResponse {
  items: FlowTopRow[]
  series?: FlowSeriesPoint[]
  filters?: FlowFilter[]
  effective_limit?: number
  series_limit?: number
  window?: string
  bucket?: string
}

export interface FlowSeriesPoint {
  ts: string
  key: string
  detail?: string
  bytes: number
  packets: number
  flows: number
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

export interface AnomalyCitation {
  ref: string
  plane: string
  source: string
  metric: string
}

export interface AnomalyTrainingWindow {
  start: string
  end: string
  samples: number
}

export interface FlowAnomaly {
  exporter: string
  iface: number
  ts: string
  current_bps: number
  baseline_bps: number
  stddev_bps: number
  sigma: number
  model?: string
  training_window?: AnomalyTrainingWindow
  feature_citations?: AnomalyCitation[]
  features?: Record<string, number>
}

export interface FlowAnomalyResponse {
  items: FlowAnomaly[]
}

export interface DeviceSyslogEvent {
  id: string
  device: string
  severity_text: string
  message: string
  observed_at: string
}

export interface DeviceSyslogResponse {
  items: DeviceSyslogEvent[]
  syslog_running?: boolean
}

export interface DeviceConfigVersion {
  id: string
  device: string
  source?: string
  version: number
  content_hash: string
  previous_hash?: string
  drifted: boolean
  archived_at: string
}

export interface DeviceConfigResponse {
  items: DeviceConfigVersion[]
  archive_running?: boolean
  redaction_policy?: string
}

export interface DeviceNeighborEvidence {
  id: string
  agent_id: string
  local_device_address: string
  local_device_name?: string
  local_if_index?: number
  local_port_id: string
  remote_chassis_id?: string
  remote_device_name?: string
  remote_port_id: string
  remote_management_address?: string
  remote_platform?: string
  capabilities?: string[]
  protocol: 'lldp' | 'cdp'
  confidence: number
  observed_at: string
  fresh_until: string
  freshness: 'current' | 'stale' | 'future'
  age_seconds: number
}

export interface DeviceNeighborResponse {
  contract_version: 'probectl.device-neighbors/v1'
  items: DeviceNeighborEvidence[]
  collection_running: boolean
  effective_limit: number
  truncated: boolean
  as_of: string
  latest_at?: string
  retention: {
    max_per_device: number
    max_per_tenant: number
    stale_retention_hours: number
  }
}

export type DeviceCollectionOutcomeState =
  | 'ok_with_rows'
  | 'healthy_empty'
  | 'unsupported'
  | 'failed'
  | 'never_observed'

export interface DeviceCollectionOutcome {
  agent_id: string
  configured_target: string
  protocol: 'lldp' | 'cdp'
  last_attempt_at: string | null
  last_success_at: string | null
  state: DeviceCollectionOutcomeState
  reason:
    | 'rows_observed'
    | 'no_rows_observed'
    | 'mib_unsupported'
    | 'poll_failed'
    | 'credential_unavailable'
    | 'transport_unreachable'
    | 'base_poll_failed'
    | 'never_attempted'
  row_count: number
  next_action:
    | 'review_neighbor_evidence'
    | 'review_target_neighbor_configuration'
    | 'enable_protocol_on_configured_target'
    | 'verify_configured_target_access'
    | 'wait_for_first_collection'
}

export interface DeviceCollectionOutcomeResponse {
  contract_version: 'probectl.device-collection-outcomes/v1'
  items: DeviceCollectionOutcome[]
  collection_running: boolean
  effective_limit: number
  truncated: boolean
  as_of: string
  retention: {
    max_per_tenant: number
    retention_days: number
  }
}

export function useFlowTop(
  by: FlowGroupBy,
  window = '1h',
  limit = 10,
  filters: FlowFilter[] = [],
  bucket = '3m',
) {
  const encodedFilters = filters.map((filter) => `${filter.field}:${filter.value}`)
  return useQuery({
    queryKey: ['flows', 'top', by, window, bucket, limit, encodedFilters],
    queryFn: () => {
      const params = new URLSearchParams({ by, window, bucket, limit: String(limit) })
      encodedFilters.forEach((filter) => params.append('filter', filter))
      return apiFetch<FlowTopResponse>(`/flows/top?${params.toString()}`)
    },
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

export function useDeviceSyslog(limit = 5) {
  return useQuery({
    queryKey: ['device', 'syslog', limit],
    queryFn: () => apiFetch<DeviceSyslogResponse>(`/device/syslog?limit=${limit}`),
  })
}

export function useDeviceConfigs(limit = 5) {
  return useQuery({
    queryKey: ['device', 'configs', limit],
    queryFn: () => apiFetch<DeviceConfigResponse>(`/device/configs?limit=${limit}`),
  })
}

export function useDeviceNeighbors(limit = 100) {
  return useQuery({
    queryKey: ['device', 'neighbors', limit],
    queryFn: () => apiFetch<DeviceNeighborResponse>(`/device/neighbors?limit=${limit}`),
  })
}

export function useDeviceCollectionOutcomes(limit = 100) {
  return useQuery({
    queryKey: ['device', 'collection-outcomes', limit],
    queryFn: () =>
      apiFetch<DeviceCollectionOutcomeResponse>(`/device/collection-outcomes?limit=${limit}`),
  })
}
