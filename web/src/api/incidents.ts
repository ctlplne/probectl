import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

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
}

/** useIncidents lists the tenant's incidents, most-recently-active first. */
export function useIncidents() {
  return useQuery({
    queryKey: ['incidents'],
    queryFn: () => apiFetch<{ items: Incident[] }>('/incidents').then((r) => r.items),
  })
}

/** useIncident fetches one incident with its full signal timeline. */
export function useIncident(id: string | undefined) {
  return useQuery({
    queryKey: ['incident', id],
    enabled: !!id,
    queryFn: () => apiFetch<Incident>(`/incidents/${id}`),
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
