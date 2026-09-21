// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

export type FlowFilterField = Exclude<FlowGroupBy, 'pair'> | 'group_as_name' | 'group_port'

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
  exporter_count?: number
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
  exporter_count?: number
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

export type FlowIngestQualityState = 'healthy' | 'degraded' | 'stale'

export interface FlowIngestQualityReceipt {
  agent_id: string
  exporter_address: string
  protocol: 'netflow' | 'netflow5' | 'netflow9' | 'ipfix' | 'sflow5'
  window_started_at: string
  window_ended_at: string
  last_packet_at: string
  last_valid_record_at: string | null
  packets_received: number
  records_decoded: number
  decode_error_packets: number
  template_misses: number
  queue_dropped_records: number
  emit_dropped_records: number
  template_state: 'not_applicable' | 'unknown' | 'learning' | 'ready' | 'missing'
  sampling_state: 'unknown' | 'unsampled' | 'sampled' | 'mixed'
  state: FlowIngestQualityState
  reason:
    | 'receiving_valid_records'
    | 'waiting_for_templates'
    | 'template_missing'
    | 'decode_errors'
    | 'queue_loss'
    | 'emit_loss'
    | 'no_valid_records'
    | 'no_recent_packets'
  next_action:
    | 'continue_monitoring'
    | 'verify_exporter_templates'
    | 'verify_exporter_protocol'
    | 'reduce_local_ingest_pressure'
    | 'verify_local_bus_delivery'
    | 'verify_exporter_delivery'
}

export interface FlowIngestQualityResponse {
  contract_version: 'probectl.flow-ingest-quality/v1'
  items: FlowIngestQualityReceipt[]
  ingest_running: boolean
  effective_limit: number
  truncated: boolean
  as_of: string
  stale_after_seconds: number
  retention: {
    max_per_tenant: number
    retention_days: number
  }
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
  /** Content was redacted by the control plane before archival. */
  content?: string
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

export function useFlowIngestQuality(limit = 100) {
  return useQuery({
    queryKey: ['flows', 'ingest-quality', limit],
    queryFn: () => apiFetch<FlowIngestQualityResponse>(`/flows/ingest-quality?limit=${limit}`),
  })
}

export function useDeviceSyslog(limit = 5) {
  return useQuery({
    queryKey: ['device', 'syslog', limit],
    queryFn: () => apiFetch<DeviceSyslogResponse>(`/device/syslog?limit=${limit}`),
  })
}

export function useDeviceConfigs(limit = 5, enabled = true) {
  return useQuery({
    queryKey: ['device', 'configs', limit],
    enabled,
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
