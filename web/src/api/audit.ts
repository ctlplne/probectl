import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch, apiURL } from './client'

export interface AuditEvent {
  seq: number
  actor: string
  action: string
  target?: string
  data?: Record<string, unknown>
  prev_hash?: string
  hash: string
  created_at?: string
}

export interface AuditList {
  items: AuditEvent[]
  next: number
}

export interface AuditVerify {
  ok: boolean
  detail?: string
}

export interface AuditFilters {
  actor?: string
  action?: string
  target?: string
  after?: number
  limit?: number
}

function paramsFor(filters: AuditFilters): URLSearchParams {
  const q = new URLSearchParams()
  if (filters.after !== undefined && filters.after > 0) q.set('after', String(filters.after))
  q.set('limit', String(filters.limit ?? 100))
  for (const key of ['actor', 'action', 'target'] as const) {
    const v = filters[key]?.trim()
    if (v) q.set(key, v)
  }
  return q
}

export function auditExportHref(filters: AuditFilters): string {
  const q = paramsFor(filters)
  const suffix = q.toString()
  return suffix ? `${apiURL('/audit')}?${suffix}` : apiURL('/audit')
}

export function useAuditEvents(filters: AuditFilters) {
  const q = paramsFor(filters)
  return useQuery({
    queryKey: ['audit', 'events', q.toString()],
    queryFn: () => apiFetch<AuditList>(`/audit?${q.toString()}`),
  })
}

export function useVerifyAudit() {
  return useMutation({
    mutationFn: () => apiFetch<AuditVerify>('/audit/verify'),
  })
}
