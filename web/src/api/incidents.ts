// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, isApiStatus } from './client'
import type { Answer } from './ai'

export type Severity = 'info' | 'warning' | 'critical'
export type IncidentStatus = 'open' | 'resolved'

/** A Signal is one plane's observation on an incident timeline. plane/kind are
 *  free-form and attributes is arbitrary, so future planes need no UI changes. */
export interface Signal {
  plane: string
  kind: string
  severity: Severity
  title: string
  summary?: string
  target?: string
  prefix?: string
  attributes?: Record<string, string>
  occurred_at: string
}

export interface Incident {
  id: string
  tenant_id: string
  status: IncidentStatus
  severity: Severity
  title: string
  target?: string
  prefix?: string
  started_at: string
  last_seen_at: string
  resolved_at?: string
  signal_count: number
  signals?: Signal[]
  signals_truncated?: boolean
  signals_limit?: number
}

export interface ChangeEvent {
  id: string
  source: string
  kind: string
  title: string
  summary?: string
  target?: string
  prefix?: string
  actor?: string
  ref?: string
  url?: string
  occurred_at: string
}

export interface ChangeCandidate {
  event: ChangeEvent
  score: number
  reason: string
}

export interface IncidentShareSelection {
  kind: 'evidence' | 'entity'
  id: string
}

export interface IncidentShareContext {
  from: string
  to: string
  filters: Record<string, string>
  selection?: IncidentShareSelection
}

export interface IncidentShareArtifact {
  id: string
  incident: Incident
  context: IncidentShareContext
  answer: Answer
  created_at: string
  expires_at: string
}

export interface CreateIncidentShareRequest {
  context: IncidentShareContext
}

export type IncidentJournalKind = 'note' | 'checkpoint'
export type IncidentJournalCitationState = 'available' | 'unavailable'

export interface IncidentJournalCitationRequest {
  share_id: string
  evidence_id: string
}

export interface IncidentJournalCitation extends IncidentJournalCitationRequest {
  state: IncidentJournalCitationState
  domain?: string
  plane?: string
  title?: string
  summary?: string
  occurred_at?: string
  ref?: string
}

export interface IncidentJournalEntry {
  id: string
  incident_id: string
  kind: IncidentJournalKind
  format: 'plain_text'
  body: string
  citation?: IncidentJournalCitation
  created_by: string
  created_at: string
  expires_at: string
}

export interface IncidentJournalList {
  items: IncidentJournalEntry[]
  truncated: boolean
  limit: number
}

export interface AppendIncidentJournalRequest {
  kind: IncidentJournalKind
  body: string
  citation?: IncidentJournalCitationRequest
}

/** useIncidents lists the tenant's incidents, most-recently-active first. */
export function useIncidents(enabled = true) {
  return useQuery({
    queryKey: ['incidents'],
    enabled,
    queryFn: () => apiFetch<{ items: Incident[] }>('/incidents').then((r) => r.items),
  })
}

/** Tenant-scoped change timeline used by path/incident evidence overlays. */
export function useChanges(enabled = true) {
  return useQuery({
    queryKey: ['changes'],
    enabled,
    queryFn: () => apiFetch<{ items: ChangeEvent[] }>('/changes').then((r) => r.items),
  })
}

/** useIncident fetches one incident with its bounded signal timeline. The
 * server sets signals_truncated when signal_count exceeds the returned rows. */
export function useIncident(id: string | undefined) {
  return useQuery({
    queryKey: ['incident', id],
    enabled: !!id,
    queryFn: () => apiFetch<Incident>(`/incidents/${id}`),
    // A tenant-scoped miss is authoritative. Retrying an unavailable ID only
    // delays fail-closed URL-context invalidation.
    retry: (failureCount, error) => !isApiStatus(error, 404) && failureCount < 1,
  })
}

/** Candidate changes are already tenant-scoped and ranked by the server. */
export function useIncidentChanges(id: string | undefined) {
  return useQuery({
    queryKey: ['incident-changes', id],
    enabled: !!id,
    queryFn: () =>
      apiFetch<{ items: ChangeCandidate[] }>(`/incidents/${id}/changes`).then((r) => r.items),
    retry: (failureCount, error) =>
      !isApiStatus(error, 404) && !isApiStatus(error, 503) && failureCount < 1,
  })
}

/** Creates a redacted, expiring incident snapshot. The server derives the
 * tenant from the session and performs a fresh, cited RCA before persisting. */
export function useCreateIncidentShare(id: string | undefined) {
  return useMutation({
    mutationFn: (request: CreateIncidentShareRequest) =>
      apiFetch<IncidentShareArtifact>(`/incidents/${id}/shares`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }),
  })
}

/** Reads an authenticated same-tenant share. Missing, expired, revoked, and
 * foreign-tenant IDs intentionally have the same 404 behavior. */
export function useIncidentShare(id: string | undefined) {
  return useQuery({
    queryKey: ['incident-share', id],
    enabled: !!id,
    queryFn: () => apiFetch<IncidentShareArtifact>(`/incident-shares/${id}`),
    retry: (failureCount, error) => !isApiStatus(error, 404) && failureCount < 1,
  })
}

/** Lists one live incident journal. Cited evidence is returned only after the
 * server re-authorizes its source share in this tenant on this exact read. */
export function useIncidentJournal(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ['incident-journal', id],
    enabled: enabled && !!id,
    queryFn: () => apiFetch<IncidentJournalList>(`/incidents/${id}/journal`),
    retry: (failureCount, error) => !isApiStatus(error, 404) && failureCount < 1,
  })
}

/** Appends inert plain text; checkpoint citations are independently
 * re-authorized by the server before the row is written. */
export function useAppendIncidentJournal(id: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (request: AppendIncidentJournalRequest) =>
      apiFetch<IncidentJournalEntry>(`/incidents/${id}/journal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['incident-journal', id] })
    },
  })
}

/** useResolveIncident marks an incident resolved. */
export function useResolveIncident(id: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      apiFetch<Incident>(`/incidents/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'resolved' }),
      }),
    onSuccess: (inc) => {
      qc.setQueryData(['incident', id], inc)
      void qc.invalidateQueries({ queryKey: ['incidents'] })
    },
  })
}

/** severityTone maps a severity to a design-system Badge tone. */
export function severityTone(s: Severity): 'danger' | 'warning' | 'info' {
  if (s === 'critical') return 'danger'
  if (s === 'warning') return 'warning'
  return 'info'
}
