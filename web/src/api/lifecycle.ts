import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

/** The tenant lifecycle view (S-T5, core): retention control + residency/
 *  isolation visibility. Export streams from /v1/lifecycle/export. */

export interface LifecycleStatus {
  tenant_id?: string
  flow_retention_days: number | null
  isolation_model: string
  residency?: string
}

export interface LifecycleRetentionInput {
  flow_retention_days: number | null
}

export interface LifecycleStoreResult {
  store: string
  deleted: number
  verified_zero: boolean
  notes?: string
}

export interface LifecycleEraseAttestation {
  format_version: number
  tenant_id: string
  tenant_slug?: string
  actor: string
  started_at: string
  finished_at: string
  stores: LifecycleStoreResult[]
  backup_policy: string
  backup_retention_days?: number
  backup_erasure_deadline?: string
  complete: boolean
  report_sha256: string
}

export interface LifecycleEraseInput {
  confirm: string
}

export function useLifecycle() {
  return useQuery({
    queryKey: ['lifecycle'],
    queryFn: () => apiFetch<LifecycleStatus>('/lifecycle/retention'),
  })
}

export function useSaveLifecycleRetention() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: LifecycleRetentionInput) =>
      apiFetch<LifecycleStatus>('/lifecycle/retention', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['lifecycle'] }),
  })
}

export function useEraseTenantLifecycle() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: LifecycleEraseInput) =>
      apiFetch<LifecycleEraseAttestation>('/lifecycle/erase', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['lifecycle'] }),
  })
}
