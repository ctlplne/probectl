import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Severity } from './incidents'

/**
 * The S16 alerting API (surface: S-FE1). Two halves:
 *  - Alert RULES (durable config, /v1/alerts CRUD).
 *  - ACTIVE alerts (engine truth, /v1/alerts/active + silence/ack actions).
 * The UI never derives alert state client-side: every action returns the
 * engine's updated view and the list re-polls the engine.
 */

export interface ChannelSpec {
  type: 'webhook' | 'email'
  url?: string
  secret?: string
  recipients?: string[]
}

export interface AlertRule {
  id: string
  tenant_id: string
  name: string
  enabled: boolean
  metric: string
  match?: Record<string, string>
  type: 'threshold' | 'baseline'
  comparison?: 'gt' | 'lt' | 'gte' | 'lte'
  threshold?: number
  window?: number
  sensitivity?: number
  for_n?: number
  renotify_seconds?: number
  severity: Severity
  channels?: ChannelSpec[]
  created_at: string
  updated_at: string
}

/** The create/update body (server validates; id/timestamps are server-owned). */
export type AlertRuleInput = Omit<AlertRule, 'id' | 'tenant_id' | 'created_at' | 'updated_at'>

export interface ActiveAlert {
  fingerprint: string
  rule_id: string
  rule_name: string
  severity: Severity
  metric: string
  labels?: Record<string, string>
  value: number
  reason: string
  since: string
  last_seen_at: string
  silenced_until?: string
  acked_by?: string
  acked_at?: string
}

interface ActiveAlertsResponse {
  items: ActiveAlert[]
  evaluator_running: boolean
}

/** useActiveAlerts polls the engine's firing set (engine truth, 15s cadence). */
export function useActiveAlerts() {
  return useQuery({
    queryKey: ['alerts', 'active'],
    queryFn: () => apiFetch<ActiveAlertsResponse>('/alerts/active'),
    refetchInterval: 15_000,
  })
}

/** useAlertRules lists the tenant's alert rules. */
export function useAlertRules() {
  return useQuery({
    queryKey: ['alerts', 'rules'],
    queryFn: () => apiFetch<{ items: AlertRule[] }>('/alerts').then((r) => r.items),
  })
}

function jsonInit(method: string, body: unknown): RequestInit {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
}

/** useSaveAlertRule creates (no id) or updates (id) a rule. */
export function useSaveAlertRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }: { id?: string; input: AlertRuleInput }) =>
      id
        ? apiFetch<AlertRule>(`/alerts/${id}`, jsonInit('PUT', input))
        : apiFetch<AlertRule>('/alerts', jsonInit('POST', input)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['alerts', 'rules'] }),
  })
}

/** useDeleteAlertRule deletes a rule. */
export function useDeleteAlertRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiFetch<undefined>(`/alerts/${id}`, { method: 'DELETE' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['alerts', 'rules'] }),
  })
}

/** useSilenceAlert silences a firing series for N minutes (0 clears). */
export function useSilenceAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ fingerprint, minutes }: { fingerprint: string; minutes: number }) =>
      apiFetch<ActiveAlert>('/alerts/active/silence', jsonInit('POST', { fingerprint, duration_minutes: minutes })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['alerts', 'active'] }),
  })
}

/** useAckAlert acknowledges a firing series as the caller. */
export function useAckAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ fingerprint }: { fingerprint: string }) =>
      apiFetch<ActiveAlert>('/alerts/active/ack', jsonInit('POST', { fingerprint })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['alerts', 'active'] }),
  })
}

/** alertStateOf derives the display state of an active alert (for filtering). */
export function alertStateOf(a: ActiveAlert): 'firing' | 'silenced' | 'acked' {
  if (a.silenced_until) return 'silenced'
  if (a.acked_by) return 'acked'
  return 'firing'
}
