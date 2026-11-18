// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type {
  ClientReportDefinition,
  CarrierSLAReportDefinition,
  CarrierSLAReportManifestDefinition,
  CarrierSLAReportAgreementBinding,
  ComplianceFlowDefinition,
  ComplianceFlowManifestDefinition,
  ComplianceFlowManifestBindings,
} from './sdk.gen'
export type {
  ClientReportDefinition,
  ClientReportCapacityTarget,
  ComplianceFlowDefinition,
  ComplianceFlowManifestBindings,
  ComplianceFlowManifestDefinition,
  ComplianceFlowSource,
} from './sdk.gen'

export type DashboardPreset = 'operator' | 'executive'
export type ReportFormat = 'pdf' | 'csv'
export type ReportCadence = 'daily' | 'weekly' | 'monthly'

export const cmmcAuditControl = 'AU.L2-3.3.1'

export const flowComplianceControls = [
  { value: 'SC.L2-3.13.1', label: 'CMMC Level 2 SC.L2-3.13.1 · Boundary protection' },
  { value: 'SI.L2-3.14.6', label: 'CMMC Level 2 SI.L2-3.14.6 · Network monitoring' },
  { value: '11.4.5', label: 'PCI DSS 11.4.5 · Supporting segmentation evidence' },
  { value: '1.3.1', label: 'PCI DSS 1.3.1 · Inbound cardholder-data evidence' },
  { value: '1.3.2', label: 'PCI DSS 1.3.2 · Outbound cardholder-data evidence' },
] as const

export type FlowComplianceControl = (typeof flowComplianceControls)[number]['value']

export function needsCardholderZone(control: FlowComplianceControl) {
  return control === '1.3.1' || control === '1.3.2'
}

export interface DashboardDefinition {
  carrier_claim?: CarrierSLAReportDefinition | null
  compliance_control?: typeof cmmcAuditControl | FlowComplianceControl
  compliance_flow?: ComplianceFlowDefinition
  client_report?: ClientReportDefinition | null
  flow_sources?: Array<{ id: string; version: string }>
  absolute_from?: string
  absolute_to?: string
  provenance: string[]
  redaction_state: string
  coverage_limitations: string[]
  metrics?: Record<string, string>
}

export interface DashboardView {
  id: string
  tenant_id: string
  owner_id: string
  name: string
  preset: DashboardPreset
  shared: boolean
  definition: DashboardDefinition
  created_at: string
  updated_at: string
}

export interface DashboardCreateInput {
  name: string
  preset: DashboardPreset
  shared: boolean
  definition: DashboardDefinition
}

export interface DashboardManifest {
  api_version: 'probectl.io/dashboard/v1'
  kind: 'Dashboard'
  metadata: { name: string }
  spec: {
    preset: DashboardPreset
    shared: boolean
    definition: Omit<
      DashboardDefinition,
      'metrics' | 'flow_sources' | 'carrier_claim' | 'compliance_flow'
    > & {
      carrier_claim?: CarrierSLAReportManifestDefinition
      compliance_flow?: ComplianceFlowManifestDefinition
      metrics: Array<{ name: string; value: string }>
      flow_sources?: Array<{ slot: string }>
    }
  }
}

export interface DashboardManifestPreview {
  name: string
  preset: DashboardPreset
  shared: boolean
  absolute_from: string
  absolute_to: string
  metric_count: number
  source_count?: number
  provenance_count: number
  coverage_limitation_count: number
}

export interface DashboardManifestImportResponse {
  status: 'preview' | 'created'
  manifest: DashboardManifest
  preview: DashboardManifestPreview
  dashboard?: DashboardView
}

export interface ReportDestination {
  description?: string
  id: string
  name: string
  kind: string
  outbound: boolean
  ready: boolean
}

export interface ReportSchedule {
  provider_trigger_allowed?: boolean
  provider_request_id?: string
  provider_original_next_run_at?: string
  id: string
  tenant_id: string
  dashboard_id: string
  owner_id: string
  name: string
  format: ReportFormat
  cadence: ReportCadence
  destination_id: string
  enabled: boolean
  next_run_at: string
  last_run_at?: string
  created_at: string
  updated_at: string
}

export interface ReportArtifact {
  email_delivery?: {
    destination_id: string
    state: 'pending' | 'sent' | 'withdrawn'
    attempts: number
    next_attempt_at?: string
    delivered_at?: string
  }
  id: string
  dashboard_id: string
  schedule_id?: string
  format: ReportFormat
  media_type: string
  filename: string
  generated_by: string
  generated_at: string
  absolute_from: string
  absolute_to: string
  provenance: string[]
  redaction_state: string
  coverage_limitations: string[]
  download_url: string
  body_bytes?: number
  body_sha256?: string
}

interface DashboardList {
  items: DashboardView[]
}

interface ScheduleList {
  provider_trigger_available?: boolean
  items: ReportSchedule[]
  destinations: ReportDestination[]
  outbound_default: false
}

interface ArtifactList {
  items: ReportArtifact[]
  next_cursor?: string
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export function useDashboards(identity: string) {
  return useQuery({
    queryKey: ['dashboards', 'saved', identity],
    queryFn: () => apiFetch<DashboardList>('/dashboards'),
  })
}

export function useCreateDashboard() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: DashboardCreateInput) =>
      apiFetch<DashboardView>('/dashboards', jsonInit('POST', input)),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['dashboards', 'saved'] }),
  })
}

export function useImportDashboardManifest() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      manifest: DashboardManifest
      confirm: boolean
      source_bindings?: Record<string, { id: string; version: string }>
      agreement_bindings?: Record<string, CarrierSLAReportAgreementBinding>
      compliance_bindings?: ComplianceFlowManifestBindings
    }) =>
      apiFetch<DashboardManifestImportResponse>(
        '/dashboard-manifests/import',
        jsonInit('POST', input),
      ),
    onSuccess: (result) => {
      if (result.dashboard) {
        void queryClient.invalidateQueries({ queryKey: ['dashboards', 'saved'] })
      }
    },
  })
}

export function useReportSchedules() {
  return useQuery({
    queryKey: ['dashboards', 'report-schedules'],
    queryFn: () => apiFetch<ScheduleList>('/dashboard-report-schedules'),
    refetchInterval: 60_000,
  })
}

export function useCreateReportSchedule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      dashboard_id: string
      name: string
      format: ReportFormat
      cadence: ReportCadence
      destination_id: string
      first_run_at: string
      provider_trigger_allowed?: boolean
    }) => apiFetch<ReportSchedule>('/dashboard-report-schedules', jsonInit('POST', input)),
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ['dashboards', 'report-schedules'] }),
  })
}

export function useUpdateReportSchedule() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      ...controls
    }: {
      id: string
      enabled?: boolean
      provider_trigger_allowed?: boolean
      destination_id?: string
    }) =>
      apiFetch<ReportSchedule>(
        `/dashboard-report-schedules/${encodeURIComponent(id)}`,
        jsonInit('PATCH', controls),
      ),
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ['dashboards', 'report-schedules'] }),
  })
}

export function useReportArtifacts(identity: string, cursor: string) {
  const qs = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  return useQuery({
    queryKey: ['dashboards', 'report-artifacts', identity, cursor],
    queryFn: () => apiFetch<ArtifactList>(`/dashboard-report-artifacts${qs}`),
    refetchInterval: 60_000,
  })
}

export function useGenerateDashboardReport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { dashboard_id: string; format: ReportFormat }) =>
      apiFetch<ReportArtifact>('/dashboard-reports', jsonInit('POST', input)),
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ['dashboards', 'report-artifacts'] }),
  })
}
