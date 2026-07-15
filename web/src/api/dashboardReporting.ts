// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export type DashboardPreset = 'operator' | 'executive'
export type ReportFormat = 'pdf' | 'csv'
export type ReportCadence = 'daily' | 'weekly' | 'monthly'

export interface DashboardDefinition {
  absolute_from: string
  absolute_to: string
  provenance: string[]
  redaction_state: string
  coverage_limitations: string[]
  metrics: Record<string, string>
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

export interface ReportDestination {
  id: string
  name: string
  kind: string
  outbound: boolean
  ready: boolean
}

export interface ReportSchedule {
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
}

interface DashboardList {
  items: DashboardView[]
}

interface ScheduleList {
  items: ReportSchedule[]
  destinations: ReportDestination[]
  outbound_default: false
}

interface ArtifactList {
  items: ReportArtifact[]
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

export function useDashboards() {
  return useQuery({
    queryKey: ['dashboards', 'saved'],
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
    }) => apiFetch<ReportSchedule>('/dashboard-report-schedules', jsonInit('POST', input)),
    onSuccess: () =>
      void queryClient.invalidateQueries({ queryKey: ['dashboards', 'report-schedules'] }),
  })
}

export function useReportArtifacts() {
  return useQuery({
    queryKey: ['dashboards', 'report-artifacts'],
    queryFn: () => apiFetch<ArtifactList>('/dashboard-report-artifacts'),
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
